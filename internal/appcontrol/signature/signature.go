// Package signature reads the Authenticode signature embedded in a Windows
// PE file and reports the publisher identity WDAC matches on: the TBS hash
// of the leaf signing certificate.
//
// Parsing says which certificate a file presents; it does not prove the
// signature is valid. Verified is set only by the Windows build, which asks
// WinVerifyTrust. Callers must refuse to build allow rules from an
// unverified publisher.
package signature

import (
	"crypto"
	_ "crypto/sha1" // registered for hashFor
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type Info struct {
	TBSHash     string // upper-case hex; "" when unsigned
	SubjectName string // leaf CN — the friendly publisher name
	Issuer      string // issuer CN
	Verified    bool   // Windows says the signature is valid and trusted
}

// FromFile reads path's embedded signature. An unsigned (or catalog-signed)
// file yields a zero Info and a nil error; an unreadable or malformed file
// yields an error.
func FromFile(path string) (Info, error) {
	certs, err := embeddedCerts(path)
	if err != nil {
		return Info{}, err
	}
	if len(certs) == 0 {
		return Info{}, nil
	}
	c := leaf(certs)
	if c == nil {
		return Info{}, errors.New("signature: no leaf certificate in chain")
	}
	tbs, err := TBSHash(c)
	if err != nil {
		return Info{}, err
	}
	return Info{
		TBSHash: tbs, SubjectName: c.Subject.CommonName, Issuer: c.Issuer.CommonName,
		Verified: verify(path),
	}, nil
}

// TBSHash is the certificate's DER TBSCertificate hashed with the
// certificate's own signature hash algorithm, upper-case hex — the value
// WDAC uses in <CertRoot Type="TBS">.
func TBSHash(c *x509.Certificate) (string, error) {
	h, err := hashFor(c.SignatureAlgorithm)
	if err != nil {
		return "", err
	}
	d := h.New()
	d.Write(c.RawTBSCertificate)
	return strings.ToUpper(hex.EncodeToString(d.Sum(nil))), nil
}

func hashFor(alg x509.SignatureAlgorithm) (crypto.Hash, error) {
	switch alg {
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return crypto.SHA256, nil
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return crypto.SHA384, nil
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return crypto.SHA512, nil
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return crypto.SHA1, nil
	default:
		return 0, fmt.Errorf("signature: unsupported certificate signature algorithm %v", alg)
	}
}

// leaf returns the certificate that signs the file. Candidates are the
// certificates that issue no other certificate in the set; a signed file also
// embeds its timestamping chain, so a code-signing certificate always wins
// over one that only does timestamping.
func leaf(certs []*x509.Certificate) *x509.Certificate {
	var fallback *x509.Certificate
	for _, c := range certs {
		isIssuer := false
		for _, other := range certs {
			if other != c && string(other.RawIssuer) == string(c.RawSubject) {
				isIssuer = true
				break
			}
		}
		if isIssuer {
			continue
		}
		if codeSigner(c) {
			return c
		}
		if fallback == nil && !timestamper(c) {
			fallback = c
		}
	}
	return fallback
}

func codeSigner(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}

func timestamper(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageTimeStamping {
			return true
		}
	}
	return false
}

// embeddedCerts extracts the certificates from the PE's certificate table
// (optional-header data directory 4), whose VirtualAddress is a file offset.
func embeddedCerts(path string) ([]*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pf, err := pe.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	defer pf.Close()

	var off, size uint32
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 4 {
			off, size = oh.DataDirectory[4].VirtualAddress, oh.DataDirectory[4].Size
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 4 {
			off, size = oh.DataDirectory[4].VirtualAddress, oh.DataDirectory[4].Size
		}
	default:
		return nil, errors.New("signature: unrecognized PE optional header")
	}
	if off == 0 || size < 8 {
		return nil, nil // unsigned
	}
	blob := make([]byte, size)
	if _, err := f.ReadAt(blob, int64(off)); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("signature: read certificate table: %w", err)
	}
	// WIN_CERTIFICATE: dwLength(4) wRevision(2) wCertificateType(2) then data.
	length := binary.LittleEndian.Uint32(blob[0:4])
	if length < 8 || uint32(len(blob)) < length {
		length = uint32(len(blob))
	}
	p7 := blob[8:length]
	if len(p7) == 0 {
		return nil, nil
	}
	return certsFromPKCS7(p7)
}

func certsFromPKCS7(der []byte) ([]*x509.Certificate, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("signature: parse ContentInfo: %w", err)
	}
	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		Rest             asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("signature: parse SignedData: %w", err)
	}
	if len(sd.Certificates.Bytes) == 0 {
		return nil, nil
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signature: parse certificates: %w", err)
	}
	return certs, nil
}
