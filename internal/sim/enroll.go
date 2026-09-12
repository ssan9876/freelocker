// Package sim is a protocol-accurate fake agent used by integration tests
// and the agent-sim load tool.
package sim

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/ca"
	"freelocker/internal/server/tokens"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Identity struct {
	DeviceID      string
	CertDER       []byte
	KeyDER        []byte
	CADER         []byte
	CommandPub    ed25519.PublicKey
	UpdatePub     ed25519.PublicKey
	UninstallHash []byte
}

// pinnedTLS trusts the server only if its chain ends in the CA whose pin
// is embedded in the install token.
func pinnedTLS(pin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         pin, // SNI: tell a multi-tenant server which tenant's cert to present
		InsecureSkipVerify: true, // replaced by VerifyPeerCertificate below
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

func Enroll(ctx context.Context, addr, installToken string, hw *flv1.HardwareInfo) (*Identity, error) {
	secret, pin, err := tokens.Parse(installToken)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hw.GetHostname()}}, key)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(pinnedTLS(pin))))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	resp, err := flv1.NewEnrollmentClient(conn).Enroll(ctx, &flv1.EnrollRequest{TokenSecret: secret, CsrDer: csr, Hardware: hw})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Identity{
		DeviceID: resp.GetDeviceId(), CertDER: resp.GetCertDer(), KeyDER: keyDER, CADER: resp.GetCaCertDer(),
		CommandPub: resp.GetCommandSigningPublicKey(), UpdatePub: resp.GetUpdateSigningPublicKey(),
		UninstallHash: resp.GetUninstallCodeSha256(),
	}, nil
}

func (id *Identity) TLSConfig() (*tls.Config, error) {
	key, err := x509.ParsePKCS8PrivateKey(id.KeyDER)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(id.CADER)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   ca.PinFromCert(id.CADER), // SNI selects our tenant's server cert
		RootCAs:      roots,
		Certificates: []tls.Certificate{{Certificate: [][]byte{id.CertDER}, PrivateKey: key}},
	}, nil
}
