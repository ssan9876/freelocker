// Package identity manages the agent's cryptographic identity: its key,
// certificate, and the metadata returned at enrollment.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/ca"
	"freelocker/internal/server/tokens"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var ErrNotEnrolled = errors.New("agent is not enrolled")

type Enrollment struct {
	DeviceID      string `json:"device_id"`
	CommandPub    []byte `json:"command_pub"`
	UpdatePub     []byte `json:"update_pub"`
	UninstallHash []byte `json:"uninstall_hash"`
}

type Store struct {
	Paths     agentpaths.Paths
	Protector secret.Protector
}

func (s *Store) Enrolled() bool {
	_, err := os.Stat(s.Paths.Enrollment())
	return err == nil
}

func (s *Store) Enroll(ctx context.Context, serverURL, installToken string, hw *flv1.HardwareInfo) (*Enrollment, error) {
	secretPart, pin, err := tokens.Parse(installToken)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: hw.GetHostname()}}, key)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(serverURL, grpc.WithTransportCredentials(credentials.NewTLS(pinnedTLS(pin))))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := flv1.NewEnrollmentClient(conn).Enroll(ctx, &flv1.EnrollRequest{
		TokenSecret: secretPart, CsrDer: csr, Hardware: hw,
	})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	if err := s.writeIdentity(key, resp.GetCertDer(), resp.GetCaCertDer()); err != nil {
		return nil, err
	}
	enr := &Enrollment{
		DeviceID: resp.GetDeviceId(), CommandPub: resp.GetCommandSigningPublicKey(),
		UpdatePub: resp.GetUpdateSigningPublicKey(), UninstallHash: resp.GetUninstallCodeSha256(),
	}
	return enr, s.writeEnrollment(enr)
}

type Loaded struct {
	Enrollment
	certDER      []byte
	keyDER       []byte
	caDER        []byte
	CertNotAfter time.Time
}

func (s *Store) Load() (*Loaded, error) {
	if !s.Enrolled() {
		return nil, ErrNotEnrolled
	}
	var enr Enrollment
	b, err := os.ReadFile(s.Paths.Enrollment())
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &enr); err != nil {
		return nil, err
	}
	certDER, err := readPEM(s.Paths.Cert(), "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	caDER, err := readPEM(s.Paths.CA(), "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	sealed, err := readPEM(s.Paths.Key(), "FREELOCKER SEALED KEY")
	if err != nil {
		return nil, err
	}
	keyDER, err := s.Protector.Unprotect(sealed)
	if err != nil {
		return nil, fmt.Errorf("unprotect key: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return &Loaded{Enrollment: enr, certDER: certDER, keyDER: keyDER, caDER: caDER, CertNotAfter: cert.NotAfter}, nil
}

func (l *Loaded) TLSConfig() (*tls.Config, error) {
	key, err := x509.ParsePKCS8PrivateKey(l.keyDER)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(l.caDER)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots,
		ServerName:   ca.PinFromCert(l.caDER), // SNI selects our tenant's server cert
		Certificates: []tls.Certificate{{Certificate: [][]byte{l.certDER}, PrivateKey: key}},
	}, nil
}

func (s *Store) Renew(ctx context.Context, serverURL string, l *Loaded) error {
	tlsCfg, err := l.TLSConfig()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(serverURL, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return err
	}
	defer conn.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: l.DeviceID}}, key)
	if err != nil {
		return err
	}
	resp, err := flv1.NewAgentClient(conn).RenewCertificate(ctx, &flv1.RenewRequest{CsrDer: csr})
	if err != nil {
		return err
	}
	return s.writeIdentity(key, resp.GetCertDer(), l.caDER)
}

func (s *Store) writeIdentity(key *ecdsa.PrivateKey, certDER, caDER []byte) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	sealed, err := s.Protector.Protect(keyDER)
	if err != nil {
		return err
	}
	if err := writePEM(s.Paths.Key(), "FREELOCKER SEALED KEY", sealed, 0o600); err != nil {
		return err
	}
	if err := writePEM(s.Paths.Cert(), "CERTIFICATE", certDER, 0o644); err != nil {
		return err
	}
	return writePEM(s.Paths.CA(), "CERTIFICATE", caDER, 0o644)
}

func (s *Store) writeEnrollment(e *Enrollment) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Paths.Enrollment(), b, 0o600)
}

func pinnedTLS(pin string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: pin, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) < 2 {
				return errors.New("server did not present a CA chain")
			}
			caDER := raw[len(raw)-1]
			if ca.PinFromCert(caDER) != pin {
				return errors.New("server CA does not match install token pin")
			}
			caCert, err := x509.ParseCertificate(caDER)
			if err != nil {
				return err
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			roots := x509.NewCertPool()
			roots.AddCert(caCert)
			_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		},
	}
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	return os.WriteFile(path, b, mode)
}

func readPEM(path, typ string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != typ {
		return nil, fmt.Errorf("%s: expected PEM %q", path, typ)
	}
	return block.Bytes, nil
}
