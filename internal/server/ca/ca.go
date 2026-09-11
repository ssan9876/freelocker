// Package ca is the server's internal certificate authority. It issues
// device client certificates and the agent-facing server certificate.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/google/uuid"
)

const (
	DeviceCertValidity = 90 * 24 * time.Hour
	RenewAfter         = 60 * 24 * time.Hour
	caValidity         = 10 * 365 * 24 * time.Hour
	serverCertValidity = 365 * 24 * time.Hour
	backdate           = 5 * time.Minute // clock-skew tolerance
)

type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func New(commonName string, now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"FreeLocker"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, key: key}, nil
}

func Load(certDER, keyDER []byte) (*CA, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("CA key is not ECDSA")
	}
	return &CA{Cert: cert, key: ek}, nil
}

func (c *CA) MarshalKey() ([]byte, error) { return x509.MarshalPKCS8PrivateKey(c.key) }

func (c *CA) Pin() string { return PinFromCert(c.Cert.Raw) }

// PinFromCert is the value embedded in install tokens so agents can
// authenticate the server before they hold any certificate.
func PinFromCert(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:16])
}

func (c *CA) SignDevice(csrDER []byte, deviceID uuid.UUID, now time.Time) ([]byte, string, time.Time, error) {
	req, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, "", time.Time{}, fmt.Errorf("CSR signature: %w", err)
	}
	pub, ok := req.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, "", time.Time{}, errors.New("CSR key must be ECDSA P-256")
	}
	serial := randSerial()
	notAfter := now.Add(DeviceCertValidity).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: deviceID.String()},
		NotBefore:    now.Add(-backdate),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.key)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return der, serial.Text(16), notAfter, nil
}

func (c *CA) IssueServerCert(hostnames []string, now time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: "freelocker-server"},
		NotBefore:    now.Add(-backdate),
		NotAfter:     now.Add(serverCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, c.Cert.Raw}, PrivateKey: key}, nil
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}
