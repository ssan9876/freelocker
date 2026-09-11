package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/google/uuid"
)

func csr(t *testing.T, key any, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSignDeviceProducesClientCertChainedToCA(t *testing.T) {
	now := time.Now()
	c, err := New("FreeLocker Test CA", now)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := uuid.New()

	der, serial, notAfter, err := c.SignDevice(csr(t, key, "ignored"), id, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != id.String() {
		t.Errorf("CN = %q, want device id (CSR CN must be ignored)", cert.Subject.CommonName)
	}
	if serial == "" || !notAfter.Equal(cert.NotAfter) {
		t.Errorf("serial=%q notAfter=%v cert.NotAfter=%v", serial, notAfter, cert.NotAfter)
	}
	if d := cert.NotAfter.Sub(now); d < DeviceCertValidity-time.Minute || d > DeviceCertValidity+time.Minute {
		t.Errorf("validity = %v", d)
	}
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignDeviceRejectsNonP256(t *testing.T) {
	c, _ := New("CA", time.Now())
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, _, _, err := c.SignDevice(csr(t, rsaKey, "x"), uuid.New(), time.Now()); err == nil {
		t.Fatal("expected RSA CSR to be rejected")
	}
	if _, _, _, err := c.SignDevice([]byte("garbage"), uuid.New(), time.Now()); err == nil {
		t.Fatal("expected garbage CSR to be rejected")
	}
}

func TestServerCertAndReload(t *testing.T) {
	now := time.Now()
	c, _ := New("CA", now)
	tc, err := c.IssueServerCert([]string{"fl.example.com", "127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(tc.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	for _, host := range []string{"fl.example.com", "127.0.0.1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
			t.Errorf("verify %s: %v", host, err)
		}
	}

	keyDER, err := c.MarshalKey()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Load(c.Cert.Raw, keyDER)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Pin() != c.Pin() || len(c.Pin()) != 32 {
		t.Errorf("pin mismatch or wrong length: %q vs %q", c2.Pin(), c.Pin())
	}
	if PinFromCert(c.Cert.Raw) != c.Pin() {
		t.Error("PinFromCert disagrees with Pin")
	}
}
