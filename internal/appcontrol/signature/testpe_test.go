package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// chain generates leaf + intermediate + root certificates. Each cert is
// signed by the next; alg controls the leaf's signature algorithm.
func chain(t *testing.T, alg x509.SignatureAlgorithm) (leafCert, mid, root *x509.Certificate) {
	t.Helper()
	mk := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, sigAlg x509.SignatureAlgorithm) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  isCA,
			BasicConstraintsValid: true,
			SignatureAlgorithm:    sigAlg,
		}
		p, pk := parent, parentKey
		if p == nil {
			p, pk = tmpl, key // self-signed
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, p, &key.PublicKey, pk)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c, key
	}
	rootC, rootKey := mk("Test Root", nil, nil, true, x509.ECDSAWithSHA256)
	midC, midKey := mk("Test Intermediate", rootC, rootKey, true, x509.ECDSAWithSHA256)
	leafC, _ := mk("Contoso Ltd", midC, midKey, false, alg)
	return leafC, midC, rootC
}

// signedPE writes a minimal PE whose certificate table holds a PKCS#7
// SignedData carrying certs. It is not a loadable binary — only the headers
// the parser reads are real. With no certs the table is left empty, which
// must read back as "unsigned".
func signedPE(t *testing.T, certs []*x509.Certificate) string {
	t.Helper()
	var cert []byte
	if len(certs) > 0 {
		p7 := pkcs7With(t, certs)
		// WIN_CERTIFICATE: dwLength, wRevision (0x0200), wCertificateType (0x0002).
		cert = make([]byte, 8)
		binary.LittleEndian.PutUint32(cert[0:], uint32(8+len(p7)))
		binary.LittleEndian.PutUint16(cert[4:], 0x0200)
		binary.LittleEndian.PutUint16(cert[6:], 0x0002)
		cert = append(cert, p7...)
	}

	// PE layout: DOS stub (0x40) -> "PE\0\0" at 0x40 -> COFF header (20) ->
	// optional header (PE32+, 0xF0 incl. 16 data directories).
	const peOff = 0x40
	const optSize = 0xF0
	buf := make([]byte, peOff+4+20+optSize)
	copy(buf[0:], []byte("MZ"))
	binary.LittleEndian.PutUint32(buf[0x3C:], peOff)
	copy(buf[peOff:], []byte("PE\x00\x00"))
	coff := buf[peOff+4:]
	binary.LittleEndian.PutUint16(coff[0:], 0x8664)   // Machine: amd64
	binary.LittleEndian.PutUint16(coff[2:], 0)        // NumberOfSections
	binary.LittleEndian.PutUint16(coff[16:], optSize) // SizeOfOptionalHeader
	opt := coff[20:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20B) // PE32+ magic
	binary.LittleEndian.PutUint32(opt[108:], 16)  // NumberOfRvaAndSizes
	// Data directory 4 (certificate table) sits at optional-header offset
	// 112 + 4*8 = 144; its VirtualAddress is a FILE OFFSET.
	if len(cert) > 0 {
		binary.LittleEndian.PutUint32(opt[144:], uint32(len(buf)))
		binary.LittleEndian.PutUint32(opt[148:], uint32(len(cert)))
	}
	buf = append(buf, cert...)

	path := filepath.Join(t.TempDir(), "signed.exe")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// pkcs7With builds a ContentInfo/SignedData whose certificates field holds
// certs (no signer infos — the parser only reads certificates).
func pkcs7With(t *testing.T, certs []*x509.Certificate) []byte {
	t.Helper()
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	sd := struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		SignerInfos      asn1.RawValue
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: 17, IsCompound: true},
		ContentInfo: asn1.RawValue{Class: asn1.ClassUniversal, Tag: 16, IsCompound: true,
			Bytes: mustMarshal(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4})},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw},
		SignerInfos:  asn1.RawValue{Class: asn1.ClassUniversal, Tag: 17, IsCompound: true},
	}
	sdDER := mustMarshal(t, sd)
	// Real PKCS#7 wraps SignedData in an explicit [0]; emit that wrapper
	// ourselves so the parser sees the production shape.
	ci := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, // signedData
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER},
	}
	return mustMarshal(t, ci)
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
