# Publisher (Signer) Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin allow everything signed by a verified publisher, so an allow rule survives application updates instead of breaking on every new file hash.

**Architecture:** A new portable `internal/appcontrol/signature` package reads a PE file's embedded Authenticode certificate and computes the WDAC **TBS hash**; Windows-only code adds `WinVerifyTrust` validation. The agent reports `signer_tbs` + `signer_verified` with observations and block events (additive proto fields); the server stores them and can promote an observation or approve a request as a `publisher` rule — a kind the rule model, store and WDAC compiler already support. Publisher rules are only ever created from a signature Windows verified, and the TBS value is always read server-side from the stored observation, never accepted from the client.

**Tech Stack:** Go (`debug/pe`, `crypto/x509`, `encoding/asn1`, `golang.org/x/sys/windows`), protobuf via `buf`, Postgres/pgx, React + TypeScript console.

**Spec:** `docs/superpowers/specs/2026-09-12-publisher-signer-rules-design.md`

## Global Constraints

- TBS hash = DER `TBSCertificate` bytes hashed with **that certificate's own signature hash algorithm**, upper-case hex. `rules.Normalize` requires 64 hex chars, so only SHA-256-class certificates can become rules (SHA-1 → 40 chars → rejected, by design).
- Publisher identity comes from the **leaf** signing certificate (the one in the PKCS#7 set that is not the issuer of any other certificate in that set).
- A publisher rule may only be created from a record with `signer_verified = true` and a non-empty `signer_tbs`; otherwise HTTP 400. The client never supplies the TBS value.
- Windows-specific code uses `//go:build windows` with a `!windows` sibling so `go build`/`go vet`/tests pass on any OS; check with `GOOS=linux go build ./...`.
- All new proto fields are additive; an older agent that sends none must behave exactly as today.
- Reading signatures is read-only. No enforcement behaviour changes: a policy's compiled XML stays byte-identical until someone adds a publisher rule.
- Tests need dev Postgres: `docker compose -f deploy/docker-compose.dev.yml up -d` (port 55432). `buf generate` needs `$(go env GOPATH)/bin` on PATH.
- Windows-only tests that care about file identity must use the 64-bit `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (the Claude Code PowerShell tool is 32-bit and redirects System32 to SysWOW64).
- Commits: conventional messages ending with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`. Branch `feat/signer-rules`.

## File Structure

| File | Responsibility |
|---|---|
| `internal/appcontrol/signature/signature.go` | portable: PE → PKCS#7 → leaf certificate → `Info` (TBS hash, names) |
| `internal/appcontrol/signature/signature_windows.go` | `verify(path)` via `wintrust.dll` |
| `internal/appcontrol/signature/signature_other.go` | `verify(path)` stub → false |
| `internal/appcontrol/signature/testpe_test.go` | builds a synthetic signed PE for portable tests |
| `internal/agent/scan/scan.go`, `scan_windows.go` | observed apps carry publisher fields |
| `internal/agent/blocks/blocks.go`, `internal/agent/runner/runner.go` | block events enriched from the file on disk |
| `proto/freelocker/v1/agent.proto` | `signer_tbs`, `signer_verified` on `ObservedApp` + `BlockEvent` |
| `internal/server/store/migrations/0016_signer_identity.sql`, `observations.go`, `approvals.go` | persist publisher identity |
| `internal/server/httpapi/policies.go`, `approvals.go` | promote/approve as publisher; expose fields |
| `web/src/api.ts`, `web/src/pages/DeviceDetail.tsx`, `web/src/pages/Approvals.tsx` | publisher column + actions |

---

### Task 1: signature package — portable parsing and TBS hash

**Files:**
- Create: `internal/appcontrol/signature/signature.go`
- Create: `internal/appcontrol/signature/signature_other.go`
- Create: `internal/appcontrol/signature/signature_windows.go` (stub returning false in this task; real verification in Task 2)
- Test: `internal/appcontrol/signature/signature_test.go`
- Test: `internal/appcontrol/signature/testpe_test.go`

**Interfaces:**
- Consumes: stdlib only (`debug/pe`, `crypto/x509`, `encoding/asn1`, `crypto/sha256`).
- Produces:
  - `type Info struct { TBSHash, SubjectName, Issuer string; Verified bool }`
  - `func FromFile(path string) (Info, error)` — zero `Info`, nil error for an unsigned file.
  - `func TBSHash(c *x509.Certificate) (string, error)` — used by the server-side tests and by `FromFile`.
  - `func leaf(certs []*x509.Certificate) *x509.Certificate`

- [ ] **Step 1: Write the synthetic-PE test helper**

`internal/appcontrol/signature/testpe_test.go`:

```go
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
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:       big.NewInt(time.Now().UnixNano()),
			Subject:            pkix.Name{CommonName: cn},
			NotBefore:          time.Now().Add(-time.Hour),
			NotAfter:           time.Now().Add(time.Hour),
			IsCA:               isCA,
			BasicConstraintsValid: true,
			SignatureAlgorithm: sigAlg,
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
// the parser reads are real.
func signedPE(t *testing.T, certs []*x509.Certificate) string {
	t.Helper()
	p7 := pkcs7With(t, certs)

	// WIN_CERTIFICATE: dwLength, wRevision (0x0200), wCertificateType (0x0002).
	cert := make([]byte, 8)
	binary.LittleEndian.PutUint32(cert[0:], uint32(8+len(p7)))
	binary.LittleEndian.PutUint16(cert[4:], 0x0200)
	binary.LittleEndian.PutUint16(cert[6:], 0x0002)
	cert = append(cert, p7...)

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
	// Data directory 4 (certificate table) is at optional-header offset
	// 112 + 4*8 = 144: VirtualAddress is a FILE OFFSET for this directory.
	binary.LittleEndian.PutUint32(opt[144:], uint32(len(buf)))
	binary.LittleEndian.PutUint32(opt[148:], uint32(len(cert)))
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
		DigestAlgorithms: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: nil}, // SET OF {}
		ContentInfo: asn1.RawValue{Class: 0, Tag: 16, IsCompound: true,
			Bytes: mustMarshal(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4})},
		Certificates: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: raw},
		SignerInfos:  asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: nil},
	}
	sdDER := mustMarshal(t, sd)
	ci := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, // signedData
		Content:     asn1.RawValue{FullBytes: sdDER},
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
```

- [ ] **Step 2: Write the failing tests**

`internal/appcontrol/signature/signature_test.go`:

```go
package signature

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTBSHashMatchesManualSHA256(t *testing.T) {
	leafC, _, _ := chain(t, x509.ECDSAWithSHA256)
	got, err := TBSHash(leafC)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leafC.RawTBSCertificate)
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	if got != want {
		t.Fatalf("TBSHash = %s, want %s", got, want)
	}
	if len(got) != 64 {
		t.Errorf("SHA-256 TBS hash must be 64 hex chars, got %d", len(got))
	}
}

func TestTBSHashFollowsCertificateAlgorithm(t *testing.T) {
	leafC, _, _ := chain(t, x509.ECDSAWithSHA384)
	got, err := TBSHash(leafC)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 96 {
		t.Fatalf("SHA-384-signed cert should hash to 96 hex chars, got %d (%s)", len(got), got)
	}
}

func TestLeafPicksNonIssuer(t *testing.T) {
	leafC, mid, root := chain(t, x509.ECDSAWithSHA256)
	for _, order := range [][]*x509.Certificate{
		{leafC, mid, root}, {root, mid, leafC}, {mid, root, leafC},
	} {
		if got := leaf(order); got == nil || got.Subject.CommonName != "Contoso Ltd" {
			t.Fatalf("leaf = %v, want Contoso Ltd", got)
		}
	}
}

func TestFromFileReadsEmbeddedCertificate(t *testing.T) {
	leafC, mid, root := chain(t, x509.ECDSAWithSHA256)
	path := signedPE(t, []*x509.Certificate{leafC, mid, root})

	info, err := FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := TBSHash(leafC)
	if info.TBSHash != want {
		t.Errorf("TBSHash = %q, want %q", info.TBSHash, want)
	}
	if info.SubjectName != "Contoso Ltd" || info.Issuer != "Test Intermediate" {
		t.Errorf("names = %q / %q", info.SubjectName, info.Issuer)
	}
	if info.Verified {
		t.Error("portable parsing must not claim the signature is verified")
	}
}

func TestFromFileUnsignedAndBroken(t *testing.T) {
	// A PE with no certificate table: unsigned, no error.
	path := signedPE(t, nil)
	info, err := FromFile(path)
	if err != nil || info.TBSHash != "" {
		t.Errorf("empty cert table = %+v, %v; want zero Info and nil error", info, err)
	}
	// Not a PE at all: an error, not a panic.
	junk := filepath.Join(t.TempDir(), "junk.exe")
	os.WriteFile(junk, []byte("not a PE file at all"), 0o600)
	if _, err := FromFile(junk); err == nil {
		t.Error("non-PE file should error")
	}
	if _, err := FromFile(filepath.Join(t.TempDir(), "missing.exe")); err == nil {
		t.Error("missing file should error")
	}
}
```

Note: `signedPE(t, nil)` writes a certificate table whose size covers only an
empty PKCS#7, which the parser must treat as unsigned rather than failing.

- [ ] **Step 3: Run to verify they fail**

Run: `go test ./internal/appcontrol/signature/`
Expected: build FAIL — `undefined: TBSHash`, `undefined: FromFile`, `undefined: leaf`.

- [ ] **Step 4: Implement the portable parser**

`internal/appcontrol/signature/signature.go`:

```go
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
	info := Info{TBSHash: tbs, SubjectName: c.Subject.CommonName, Issuer: c.Issuer.CommonName}
	info.Verified = verify(path)
	return info, nil
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

// leaf returns the certificate that signs the file: the one that is not the
// issuer of any other certificate in the set.
func leaf(certs []*x509.Certificate) *x509.Certificate {
	for _, c := range certs {
		isIssuer := false
		for _, other := range certs {
			if other != c && string(other.RawIssuer) == string(c.RawSubject) {
				isIssuer = true
				break
			}
		}
		if !isIssuer {
			return c
		}
	}
	return nil
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
```

`internal/appcontrol/signature/signature_other.go`:

```go
//go:build !windows

package signature

// verify is Windows-only; elsewhere a signature is never treated as verified.
func verify(string) bool { return false }
```

`internal/appcontrol/signature/signature_windows.go` (placeholder this task; Task 2 implements it):

```go
//go:build windows

package signature

// verify is implemented in Task 2 via WinVerifyTrust.
func verify(string) bool { return false }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/appcontrol/signature/ -v`
Expected: all five tests PASS. If `asn1.Unmarshal` rejects the synthetic
SignedData, fix the **test helper** (the real-world shape is authoritative),
never loosen the parser to accept malformed DER.

- [ ] **Step 6: Commit**

```bash
git add internal/appcontrol/signature
git commit -m "feat(signature): read Authenticode certificates and compute WDAC TBS hashes

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: signature package — Windows verification

**Files:**
- Modify: `internal/appcontrol/signature/signature_windows.go` (replace the placeholder)
- Test: `internal/appcontrol/signature/signature_windows_test.go` (new, `//go:build windows`)

**Interfaces:**
- Consumes (Task 1): `FromFile`, `Info`.
- Produces: `verify(path string) bool` — true only when `WinVerifyTrust` reports a valid, trusted signature.

- [ ] **Step 1: Write the failing Windows-only test**

`internal/appcontrol/signature/signature_windows_test.go`:

```go
//go:build windows

package signature

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFromFileVerifiesSystemBinary reads a Microsoft-signed system binary.
// Read-only and safe on a dev box. Skips when the file has no embedded
// signature (some builds ship catalog-signed binaries only).
func TestFromFileVerifiesSystemBinary(t *testing.T) {
	const path = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	info, err := FromFile(path)
	if err != nil {
		t.Fatalf("FromFile(%s): %v", path, err)
	}
	if info.TBSHash == "" {
		t.Skip("no embedded signature (catalog-signed); nothing to verify here")
	}
	if !info.Verified {
		t.Errorf("%s should verify as trusted; got Verified=false (TBS %s, subject %q)", path, info.TBSHash, info.SubjectName)
	}
	if info.SubjectName == "" {
		t.Error("signed binary should report a subject name")
	}
}

func TestVerifyRejectsUnsignedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "plain.exe")
	if err := os.WriteFile(p, []byte("MZ not really a binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if verify(p) {
		t.Error("unsigned file must not verify")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/appcontrol/signature/ -run 'VerifiesSystemBinary|RejectsUnsigned' -v`
Expected: `TestFromFileVerifiesSystemBinary` FAILS with "should verify as trusted; got Verified=false" (the placeholder always returns false). `TestVerifyRejectsUnsignedFile` passes already — that is fine, it guards the next step.

- [ ] **Step 3: Implement WinVerifyTrust**

Replace `internal/appcontrol/signature/signature_windows.go`:

```go
//go:build windows

package signature

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrust          = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")
)

// WINTRUST_ACTION_GENERIC_VERIFY_V2
var actionGenericVerifyV2 = windows.GUID{
	Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

const (
	wtdUINone          = 2
	wtdRevokeNone      = 0
	wtdChoiceFile      = 1
	wtdStateActionVerify = 1
	wtdStateActionClose  = 2
	wtdSafer           = 0x100
	invalidHandle      = ^uintptr(0)
)

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject uintptr
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *wintrustFileInfo
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

// verify asks Windows whether path carries a valid, trusted Authenticode
// signature. Revocation checking is off so an offline machine still gets a
// usable answer; the publisher identity itself comes from the certificate.
func verify(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	fi := wintrustFileInfo{hFile: windows.Handle(invalidHandle), pcwszFilePath: p}
	fi.cbStruct = uint32(unsafe.Sizeof(fi))
	d := wintrustData{
		dwUIChoice: wtdUINone, fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice: wtdChoiceFile, pFile: &fi,
		dwStateAction: wtdStateActionVerify, dwProvFlags: wtdSafer,
	}
	d.cbStruct = uint32(unsafe.Sizeof(d))

	rc, _, _ := procWinVerifyTrust.Call(invalidHandle,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&d)))

	// Always release the state data, whatever the verdict.
	d.dwStateAction = wtdStateActionClose
	procWinVerifyTrust.Call(invalidHandle,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&d)))

	return rc == 0 // ERROR_SUCCESS: signed and trusted
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/appcontrol/signature/ -v`
Expected: every test PASSES (or the system-binary test SKIPS on a
catalog-only build). Then `GOOS=linux go build ./... && go vet ./...` clean.

- [ ] **Step 5: Commit**

```bash
git add internal/appcontrol/signature
git commit -m "feat(signature): verify Authenticode trust with WinVerifyTrust

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Protocol and agent — report publisher identity

**Files:**
- Modify: `proto/freelocker/v1/agent.proto` (2 messages), then `buf generate`
- Modify: `internal/agent/scan/scan.go` (2 fields), `internal/agent/scan/scan_windows.go` (fill them)
- Modify: `internal/agent/blocks/blocks.go` (2 fields)
- Modify: `internal/agent/runner/runner.go` (enrich block events; send new fields for observations and blocks)
- Modify: `internal/server/agentapi/policy.go` (read new fields into store types)
- Test: `internal/agent/runner/signer_test.go` (new)

**Interfaces:**
- Consumes (Tasks 1–2): `signature.FromFile`, `signature.Info`.
- Produces:
  - `scan.Observed{SHA256, Path, Signer string; SignerTBS string; SignerVerified bool}`
  - `blocks.BlockEvent{…; SignerTBS string; SignerVerified bool}`
  - proto fields `ObservedApp.signer_tbs/4`, `ObservedApp.signer_verified/5`, `BlockEvent.signer_tbs/6`, `BlockEvent.signer_verified/7`
  - `store.Observation` / `store.BlockEvent` gain the same two fields (Task 4 persists them; this task only needs them to compile — do Task 4 first if you prefer, the tests here cover the agent side only).

- [ ] **Step 1: Write the failing runner test**

`internal/agent/runner/signer_test.go` — the runner must enrich a block
event that has a name but no certificate, using the file on disk:

```go
package runner_test

import (
	"os"
	"path/filepath"
	"testing"

	"freelocker/internal/agent/blocks"
	"freelocker/internal/agent/runner"
)

func TestEnrichBlockEventsFillsPublisher(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone.exe")
	unsigned := filepath.Join(t.TempDir(), "plain.exe")
	if err := os.WriteFile(unsigned, []byte("not a PE"), 0o600); err != nil {
		t.Fatal(err)
	}

	in := []blocks.BlockEvent{
		{SHA256: "AA", Path: missing, Signer: "Contoso"},
		{SHA256: "BB", Path: unsigned},
		{SHA256: "CC", Path: "", Signer: ""},
	}
	got := runner.EnrichBlockEvents(in)
	if len(got) != 3 {
		t.Fatalf("enrich dropped events: %d", len(got))
	}
	for i, e := range got {
		if e.SignerTBS != "" || e.SignerVerified {
			t.Errorf("event %d: unreadable/unsigned file must leave publisher empty, got %+v", i, e)
		}
	}
	if got[0].Signer != "Contoso" {
		t.Errorf("existing signer name must survive enrichment: %q", got[0].Signer)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/agent/runner/ -run EnrichBlockEvents`
Expected: build FAIL — `undefined: runner.EnrichBlockEvents`, and
`e.SignerTBS` undefined on `blocks.BlockEvent`.

- [ ] **Step 3: Extend the proto and regenerate**

In `proto/freelocker/v1/agent.proto`:

```proto
message ObservedApp {
  string sha256 = 1;
  string path = 2;
  string signer = 3;
  string signer_tbs = 4;      // signing certificate TBS hash, "" when unsigned
  bool signer_verified = 5;   // Windows verified the signature
}

message BlockEvent {
  string sha256 = 1;
  string path = 2;
  string signer = 3;
  bool blocked = 4; // true = enforced block, false = audit-only would-block
  int64 at_unix = 5;
  string signer_tbs = 6;
  bool signer_verified = 7;
}
```

Run: `PATH="$PATH:$(go env GOPATH)/bin" buf generate`
Expected: `gen/freelocker/v1/*.pb.go` updated with `GetSignerTbs()` / `GetSignerVerified()`.

- [ ] **Step 4: Add the fields and the enrichment**

`internal/agent/scan/scan.go`:

```go
type Observed struct {
	SHA256         string
	Path           string
	Signer         string // friendly publisher name
	SignerTBS      string // signing certificate TBS hash
	SignerVerified bool   // Windows verified the signature
}
```

`internal/agent/scan/scan_windows.go` — replace the deferred-signer comment
and fill the fields (best effort; never drop an observation):

```go
// runningImpl enumerates running processes, resolves each full image path,
// and records the Authenticode hash plus the publisher identity of each
// distinct executable.
```

and inside the loop, where the observation is appended:

```go
			if sum, err := AuthenticodeHash(path); err == nil {
				o := Observed{SHA256: sum, Path: path}
				if info, err := signature.FromFile(path); err == nil {
					o.Signer, o.SignerTBS, o.SignerVerified = info.SubjectName, info.TBSHash, info.Verified
				}
				out = append(out, o)
			}
```

with `"freelocker/internal/appcontrol/signature"` added to its imports.

`internal/agent/blocks/blocks.go` — add to `BlockEvent`:

```go
	SignerTBS      string // signing certificate TBS hash (filled from the file, not the log)
	SignerVerified bool
```

`internal/agent/runner/runner.go` — add the exported helper (exported so the
test above can drive it directly) and call it where block events are read:

```go
// EnrichBlockEvents fills in publisher identity from each event's file on
// disk: the CodeIntegrity log carries only a name, and WDAC rules need the
// certificate's TBS hash. Missing or unsigned files are left as they are.
func EnrichBlockEvents(evs []blocks.BlockEvent) []blocks.BlockEvent {
	for i := range evs {
		if evs[i].Path == "" || evs[i].SignerTBS != "" {
			continue
		}
		info, err := signature.FromFile(evs[i].Path)
		if err != nil {
			continue
		}
		evs[i].SignerTBS, evs[i].SignerVerified = info.TBSHash, info.Verified
		if evs[i].Signer == "" {
			evs[i].Signer = info.SubjectName
		}
	}
	return evs
}
```

with `"freelocker/internal/appcontrol/signature"` imported. Then, in the
app-control tick where block events are collected and sent (the code building
`flv1.BlockEvent` around line 339), wrap the slice with
`EnrichBlockEvents(...)` before the send loop, and add the new fields to both
payloads:

```go
		apps = append(apps, &flv1.ObservedApp{Sha256: o.SHA256, Path: o.Path, Signer: o.Signer,
			SignerTbs: o.SignerTBS, SignerVerified: o.SignerVerified})
```

```go
			Sha256: e.SHA256, Path: e.Path, Signer: e.Signer, Blocked: e.Blocked, AtUnix: e.At.Unix(),
			SignerTbs: e.SignerTBS, SignerVerified: e.SignerVerified,
```

`internal/server/agentapi/policy.go` — carry the fields into the store types
(both conversion sites):

```go
			SHA256: a.GetSha256(), Path: a.GetPath(), Signer: a.GetSigner(),
			SignerTBS: a.GetSignerTbs(), SignerVerified: a.GetSignerVerified(),
```

```go
			SHA256: e.GetSha256(), Path: e.GetPath(), Signer: e.GetSigner(), Blocked: e.GetBlocked(), At: at,
			SignerTBS: e.GetSignerTbs(), SignerVerified: e.GetSignerVerified(),
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/agent/... ./internal/server/agentapi/ && GOOS=linux go build ./...`
Expected: `ok` throughout. (`store.Observation`/`store.BlockEvent` must already
carry the two fields — add them here if Task 4 has not run yet; they are
listed in Task 4 Step 3.)

- [ ] **Step 6: Commit**

```bash
git add proto gen internal/agent internal/server/agentapi internal/server/store
git commit -m "feat(agent): report publisher identity with observations and blocks

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Server — persist publisher identity

**Files:**
- Create: `internal/server/store/migrations/0016_signer_identity.sql`
- Modify: `internal/server/store/observations.go` (types, upsert, list, block insert/list)
- Modify: `internal/server/store/approvals.go` (type, upsert, list/get)
- Test: `internal/server/store/signer_test.go` (new)

**Interfaces:**
- Produces:
  - `store.Observation` / `store.BlockEvent` / `store.ApprovalRequest` each gain `SignerTBS string` and `SignerVerified bool`.
  - `func (s *Store) ObservationPublisher(ctx context.Context, tenantID uuid.UUID, sha256 string) (tbs, name string, verified bool, err error)` — most recently seen observation for that hash in the tenant; `ErrNotFound` when none.

- [ ] **Step 1: Write the failing store test**

`internal/server/store/signer_test.go`:

```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestObservationPublisherRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, tenant, _, dev := overrideEnv(t) // from overrides_test.go: tenant + grouped device
	now := time.Now()

	for _, o := range []store.Observation{
		{SHA256: "AA11", Path: `C:\app.exe`, Signer: "Contoso Ltd", SignerTBS: "BEEF", SignerVerified: true},
		{SHA256: "BB22", Path: `C:\other.exe`, Signer: "Nobody"},
	} {
		if err := s.RecordObservation(ctx, tenant, dev, o, now); err != nil {
			t.Fatal(err)
		}
	}

	obs, err := s.ListObservations(ctx, tenant, dev, 10)
	if err != nil || len(obs) != 2 {
		t.Fatalf("observations = %d, %v", len(obs), err)
	}
	byHash := map[string]store.Observation{}
	for _, o := range obs {
		byHash[o.SHA256] = o
	}
	if o := byHash["AA11"]; o.SignerTBS != "BEEF" || !o.SignerVerified {
		t.Errorf("verified observation = %+v", o)
	}
	if o := byHash["BB22"]; o.SignerTBS != "" || o.SignerVerified {
		t.Errorf("unsigned observation = %+v", o)
	}

	tbs, name, verified, err := s.ObservationPublisher(ctx, tenant, "AA11")
	if err != nil || tbs != "BEEF" || name != "Contoso Ltd" || !verified {
		t.Fatalf("ObservationPublisher = %q %q %v, %v", tbs, name, verified, err)
	}
	if _, _, _, err := s.ObservationPublisher(ctx, tenant, "NOPE"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown hash err = %v", err)
	}
	other, _ := s.CreateTenant(ctx, "Other")
	if _, _, _, err := s.ObservationPublisher(ctx, other, "AA11"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant err = %v", err)
	}
}

func TestBlockEventsAndApprovalsCarryPublisher(t *testing.T) {
	ctx := context.Background()
	s, tenant, gid, dev := overrideEnv(t)
	pid, err := s.CreatePolicy(ctx, tenant, "P", "audit")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AssignPolicy(ctx, tenant, gid, pid); err != nil {
		t.Fatal(err)
	}
	evs := []store.BlockEvent{{
		SHA256: "CC33", Path: `C:\blocked.exe`, Signer: "Contoso Ltd",
		SignerTBS: "FEED", SignerVerified: true, Blocked: false, At: time.Now(),
	}}
	if err := s.RecordBlockEvents(ctx, tenant, dev, evs); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListBlockEvents(ctx, tenant, 10)
	if err != nil || len(list) != 1 || list[0].SignerTBS != "FEED" || !list[0].SignerVerified {
		t.Fatalf("block events = %+v, %v", list, err)
	}
	if err := s.UpsertApprovalRequests(ctx, tenant, pid, dev, evs); err != nil {
		t.Fatal(err)
	}
	reqs, err := s.ListApprovalRequests(ctx, tenant, "pending", 10)
	if err != nil || len(reqs) != 1 {
		t.Fatalf("approval requests = %+v, %v", reqs, err)
	}
	if reqs[0].SignerTBS != "FEED" || !reqs[0].SignerVerified {
		t.Errorf("approval request publisher = %+v", reqs[0])
	}
	got, err := s.GetApprovalRequest(ctx, tenant, reqs[0].ID)
	if err != nil || got.SignerTBS != "FEED" || !got.SignerVerified {
		t.Errorf("GetApprovalRequest publisher = %+v, %v", got, err)
	}
	_ = uuid.UUID{}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/server/store/ -run 'ObservationPublisher|CarryPublisher'`
Expected: build FAIL — unknown field `SignerTBS` in `store.Observation`, `s.ObservationPublisher` undefined.

- [ ] **Step 3: Add the migration, fields and queries**

`internal/server/store/migrations/0016_signer_identity.sql`:

```sql
-- +goose Up
-- Publisher identity: the signing certificate's TBS hash (what WDAC matches)
-- and whether Windows verified the signature. Existing rows keep empty/false
-- and so offer no publisher rule.
ALTER TABLE observations
    ADD COLUMN signer_tbs text NOT NULL DEFAULT '',
    ADD COLUMN signer_verified boolean NOT NULL DEFAULT false;
ALTER TABLE block_events
    ADD COLUMN signer_tbs text NOT NULL DEFAULT '',
    ADD COLUMN signer_verified boolean NOT NULL DEFAULT false;
ALTER TABLE approval_requests
    ADD COLUMN signer_tbs text NOT NULL DEFAULT '',
    ADD COLUMN signer_verified boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE approval_requests DROP COLUMN signer_verified, DROP COLUMN signer_tbs;
ALTER TABLE block_events DROP COLUMN signer_verified, DROP COLUMN signer_tbs;
ALTER TABLE observations DROP COLUMN signer_verified, DROP COLUMN signer_tbs;
```

In `internal/server/store/observations.go`:
- add `SignerTBS string` and `SignerVerified bool` to `Observation` and `BlockEvent`;
- extend the observation upsert to insert both columns, keeping the existing
  "first non-empty wins" style for the identity so a later unsigned read does
  not erase a good one:

```go
			signer=CASE WHEN observations.signer='' THEN EXCLUDED.signer ELSE observations.signer END,
			signer_tbs=CASE WHEN observations.signer_tbs='' THEN EXCLUDED.signer_tbs ELSE observations.signer_tbs END,
			signer_verified=(observations.signer_verified OR EXCLUDED.signer_verified)
```

- add both columns to the `INSERT` column list and `VALUES` (with
  `o.SignerTBS, o.SignerVerified`), to the observation `SELECT` and its
  `Scan`, to the `block_events` insert and its `SELECT`/`Scan`;
- add `ObservationPublisher`:

```go
// ObservationPublisher returns the publisher identity most recently seen for
// a hash in the tenant. ErrNotFound when no observation matches.
func (s *Store) ObservationPublisher(ctx context.Context, tenantID uuid.UUID, sha256 string) (string, string, bool, error) {
	var tbs, name string
	var verified bool
	err := s.pool.QueryRow(ctx, `
		SELECT signer_tbs, signer, signer_verified FROM observations
		WHERE tenant_id = $1 AND sha256 = $2
		ORDER BY signer_verified DESC, last_seen DESC LIMIT 1`, tenantID, sha256).
		Scan(&tbs, &name, &verified)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return tbs, name, verified, err
}
```

In `internal/server/store/approvals.go`:
- add `SignerTBS string` / `SignerVerified bool` to `ApprovalRequest`;
- in `UpsertApprovalRequests`, extend the per-hash `agg` with
  `signerTBS string` / `signerVerified bool`, filling them the same way as
  `signer` (first non-empty wins; `verified` ORs), and add the two columns to
  the insert plus the conflict update (same CASE/OR shape as observations);
- add the two columns to every `ApprovalRequest` SELECT/Scan (list and get).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/server/store/`
Expected: `ok`, including the existing observation and approval tests.

- [ ] **Step 5: Commit**

```bash
git add internal/server/store
git commit -m "feat(store): persist publisher identity for observations, blocks, approvals

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Console API — promote and approve as publisher

**Files:**
- Modify: `internal/server/httpapi/policies.go` (`promoteObservation`, rename `addHashRule` → `addRule` carrying `PublisherName`, expose fields in `listObservations`/`listBlocks`)
- Modify: `internal/server/httpapi/approvals.go` (`decideApproval` publisher branch, `approvalJSON` fields)
- Test: `internal/server/httpapi/signer_test.go` (new)

**Interfaces:**
- Consumes (Task 4): `store.ObservationPublisher`, the new struct fields.
- Produces:
  - `POST /api/observations/promote` body gains `kind` (`""`/`hash` default, `publisher`).
  - `POST /api/approvals/{id}/approve` body `kind` gains `publisher`.
  - `GET /api/devices/{id}/observations`, `GET /api/blocks`, `GET /api/approvals` include `signer_tbs` and `signer_verified`.

- [ ] **Step 1: Write the failing test**

`internal/server/httpapi/signer_test.go`:

```go
package httpapi_test

import (
	"context"
	"testing"
	"time"

	"freelocker/internal/server/store"
)

// seedObservation records one observation for the env's fake device.
func seedObservation(t *testing.T, e *env, dev string, o store.Observation) {
	t.Helper()
	ctx := context.Background()
	tenant, _ := e.store.FirstTenant(ctx)
	id := mustParseUUID(t, dev)
	if err := e.store.RecordObservation(ctx, tenant, id, o, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestPromoteObservationAsPublisher(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	dev := e.fakeDevice(t).String()
	var pol idResp
	c.do("POST", "/api/policies", map[string]string{"name": "Workstations", "mode": "audit"}, &pol)

	const tbs = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	seedObservation(t, e, dev, store.Observation{
		SHA256: "AA11", Path: `C:\app.exe`, Signer: "Contoso Ltd", SignerTBS: tbs, SignerVerified: true,
	})
	seedObservation(t, e, dev, store.Observation{
		SHA256: "BB22", Path: `C:\unsigned.exe`,
	})

	// A verified observation becomes a publisher rule whose value is the TBS hash.
	body := map[string]string{"policy_id": pol.ID, "sha256": "AA11", "kind": "publisher", "description": "Contoso apps"}
	if code := c.do("POST", "/api/observations/promote", body, nil); code != 201 {
		t.Fatalf("promote publisher = %d", code)
	}
	var detail struct {
		Rules []struct {
			Kind          string `json:"kind"`
			Value         string `json:"value"`
			PublisherName string `json:"publisher_name"`
		} `json:"rules"`
	}
	c.do("GET", "/api/policies/"+pol.ID, nil, &detail)
	found := false
	for _, r := range detail.Rules {
		if r.Kind == "publisher" {
			found = true
			if r.Value != tbs || r.PublisherName != "Contoso Ltd" {
				t.Errorf("publisher rule = %+v", r)
			}
		}
	}
	if !found {
		t.Fatalf("no publisher rule on policy: %+v", detail.Rules)
	}

	// Unsigned/unverified observations are refused.
	bad := map[string]string{"policy_id": pol.ID, "sha256": "BB22", "kind": "publisher"}
	if code := c.do("POST", "/api/observations/promote", bad, nil); code != 400 {
		t.Errorf("unverified promote = %d, want 400", code)
	}
	missing := map[string]string{"policy_id": pol.ID, "sha256": "NOPE", "kind": "publisher"}
	if code := c.do("POST", "/api/observations/promote", missing, nil); code != 404 {
		t.Errorf("unknown observation promote = %d, want 404", code)
	}
	// The client cannot smuggle its own TBS value.
	spoof := map[string]string{"policy_id": pol.ID, "sha256": "BB22", "kind": "publisher", "signer_tbs": tbs}
	if code := c.do("POST", "/api/observations/promote", spoof, nil); code != 400 {
		t.Errorf("client-supplied TBS = %d, want 400", code)
	}
}

func TestObservationsListExposesPublisher(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	dev := e.fakeDevice(t).String()
	const tbs = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	seedObservation(t, e, dev, store.Observation{SHA256: "AA11", Path: `C:\app.exe`, Signer: "Contoso Ltd", SignerTBS: tbs, SignerVerified: true})

	var obs []struct {
		SHA256         string `json:"sha256"`
		Signer         string `json:"signer"`
		SignerTBS      string `json:"signer_tbs"`
		SignerVerified bool   `json:"signer_verified"`
	}
	if code := c.do("GET", "/api/devices/"+dev+"/observations", nil, &obs); code != 200 || len(obs) != 1 {
		t.Fatalf("observations = %d, %+v", code, obs)
	}
	if obs[0].SignerTBS != tbs || !obs[0].SignerVerified || obs[0].Signer != "Contoso Ltd" {
		t.Errorf("observation JSON = %+v", obs[0])
	}
}
```

Add this helper to the same file (the test env has no UUID parser yet):

```go
func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
```

with `"github.com/google/uuid"` imported.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/server/httpapi/ -run 'PromoteObservationAsPublisher|ObservationsListExposesPublisher'`
Expected: FAIL — promote returns 201 with a *hash* rule (`kind` ignored, no publisher rule found) and `signer_tbs` is absent from the observations JSON.

- [ ] **Step 3: Implement the API changes**

In `internal/server/httpapi/policies.go`:

- rename `addHashRule` to `addRule` (update both call sites, here and in
  `approvals.go`) and carry the publisher name:

```go
// addRule adds a normalized allow rule to a policy and recompiles it,
// returning the new version. An identical rule already on the policy is not
// an error, so retrying is safe.
func (a *API) addRule(ctx context.Context, p principal, policyID uuid.UUID, rule rules.Rule) (string, error) {
	_, err := a.Store.AddRule(ctx, p.TenantID, policyID, store.PolicyRule{
		Kind: string(rule.Kind), Value: rule.Value, PublisherName: rule.PublisherName, Description: rule.Description,
	}, &p.Admin.ID)
	if err != nil && !errors.Is(err, store.ErrConflict) {
		return "", err
	}
	return a.Runtime().Policy.Recompile(ctx, p.TenantID, policyID)
}
```

- replace `promoteObservation`'s rule construction so `kind` is honoured and
  the publisher identity is read from the store, never the request:

```go
	var req struct {
		PolicyID    string `json:"policy_id"`
		SHA256      string `json:"sha256"`
		Kind        string `json:"kind"` // "" or "hash" (default), or "publisher"
		Description string `json:"description"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	pid, err := uuid.Parse(req.PolicyID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid policy_id")
		return
	}
	p := principalFrom(r)
	rule := rules.Rule{Kind: rules.Hash, Value: req.SHA256, Description: req.Description}
	if req.Kind == "publisher" {
		// The TBS hash comes from the stored observation, so a client cannot
		// claim a publisher was verified.
		tbs, name, verified, err := a.Store.ObservationPublisher(r.Context(), p.TenantID, req.SHA256)
		if err != nil {
			a.storeErr(w, err)
			return
		}
		if tbs == "" || !verified {
			writeErr(w, http.StatusBadRequest, "this program has no verified publisher; allow it by hash instead")
			return
		}
		rule = rules.Rule{Kind: rules.Publisher, Value: tbs, PublisherName: name, Description: req.Description}
	} else if req.Kind != "" && req.Kind != "hash" {
		writeErr(w, http.StatusBadRequest, "kind must be hash or publisher")
		return
	}
	norm, err := rules.Normalize(rule)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	version, err := a.addRule(r.Context(), p, pid, norm)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "policy.add_rule", "policy", pid.String(),
		map[string]any{"kind": string(norm.Kind), "value": norm.Value, "via": "learning"}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"version": version})
```

- add the new fields to `listObservations` and `listBlocks` output:

```go
			"sha256": o.SHA256, "path": o.Path, "signer": o.Signer,
			"signer_tbs": o.SignerTBS, "signer_verified": o.SignerVerified,
```

```go
			"signer": e.Signer, "signer_tbs": e.SignerTBS, "signer_verified": e.SignerVerified,
			"blocked": e.Blocked, "at": e.At,
```

In `internal/server/httpapi/approvals.go`:

- add `SignerTBS string \`json:"signer_tbs"\`` and `SignerVerified bool \`json:"signer_verified"\`` to `approvalJSON`, and populate them in `listApprovals`.
- replace the hash/path branch in `decideApproval` (dropping the stale comment
  about publisher approval not being offered):

```go
		kind := rules.Hash
		value, publisher := req.SHA256, ""
		if r.Body != nil {
			var body struct {
				Kind string `json:"kind"`
			}
			_ = readJSONOptional(r, &body)
			switch body.Kind {
			case "path":
				if req.Path == "" {
					writeErr(w, http.StatusBadRequest, "cannot approve by path: this request has no path")
					return
				}
				kind, value = rules.Path, req.Path
			case "publisher":
				if req.SignerTBS == "" || !req.SignerVerified {
					writeErr(w, http.StatusBadRequest, "cannot approve by publisher: no verified signature for this program")
					return
				}
				kind, value, publisher = rules.Publisher, req.SignerTBS, req.Signer
			case "", "hash":
			default:
				writeErr(w, http.StatusBadRequest, "kind must be hash, path, or publisher")
				return
			}
		}
		norm, err := rules.Normalize(rules.Rule{
			Kind: kind, Value: value, PublisherName: publisher,
			Description: fmt.Sprintf("approved from request %s (%s)", req.ID, req.Path),
		})
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := a.addRule(r.Context(), p, req.PolicyID, norm); err != nil {
			a.storeErr(w, err)
			return
		}
```

- include the kind in the approve audit detail:

```go
	a.audit(r, p, action, "approval", id.String(), map[string]any{
		"policy_id": req.PolicyID.String(), "sha256": req.SHA256,
	}, "success")
```
becomes, for the approved branch, the same map plus `"kind": string(kind)` —
declare `kind` before the `if status == "approved"` block (default
`rules.Hash`) so it is in scope for the audit call.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go vet ./internal/server/... && go test ./internal/server/httpapi/`
Expected: `ok`, existing approvals tests included.

- [ ] **Step 5: Add the approve-as-publisher test**

Append to `internal/server/httpapi/signer_test.go`:

```go
func TestApproveAsPublisher(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.initialized(t)
	dev := e.fakeDevice(t)
	tenant, _ := e.store.FirstTenant(ctx)
	var grp, pol idResp
	c.do("POST", "/api/groups", map[string]string{"name": "WS"}, &grp)
	c.do("POST", "/api/policies", map[string]string{"name": "P", "mode": "audit"}, &pol)
	c.do("POST", "/api/policies/"+pol.ID+"/assign", map[string]string{"group_id": grp.ID}, nil)
	c.do("POST", "/api/devices/"+dev.String()+"/group", map[string]any{"group_id": grp.ID}, nil)

	const tbs = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	pid := mustParseUUID(t, pol.ID)
	if err := e.store.UpsertApprovalRequests(ctx, tenant, pid, dev, []store.BlockEvent{{
		SHA256: "CC33", Path: `C:\blocked.exe`, Signer: "Contoso Ltd", SignerTBS: tbs, SignerVerified: true, At: time.Now(),
	}}); err != nil {
		t.Fatal(err)
	}
	var reqs []struct {
		ID             string `json:"id"`
		SignerTBS      string `json:"signer_tbs"`
		SignerVerified bool   `json:"signer_verified"`
	}
	c.do("GET", "/api/approvals?status=pending", nil, &reqs)
	if len(reqs) != 1 || reqs[0].SignerTBS != tbs || !reqs[0].SignerVerified {
		t.Fatalf("approvals = %+v", reqs)
	}
	if code := c.do("POST", "/api/approvals/"+reqs[0].ID+"/approve", map[string]string{"kind": "publisher"}, nil); code != 204 {
		t.Fatalf("approve publisher = %d", code)
	}
	var detail struct {
		Rules []struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"rules"`
	}
	c.do("GET", "/api/policies/"+pol.ID, nil, &detail)
	for _, r := range detail.Rules {
		if r.Kind == "publisher" && r.Value == tbs {
			return
		}
	}
	t.Errorf("no publisher rule after approval: %+v", detail.Rules)
}
```

Run: `go test ./internal/server/httpapi/ -run ApproveAsPublisher`
Expected: PASS (the Step 3 implementation already covers it; if it fails, fix the handler, not the test).

- [ ] **Step 6: Commit**

```bash
git add internal/server/httpapi
git commit -m "feat(appcontrol): promote and approve as publisher rules

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Console — publisher column and actions

**Files:**
- Modify: `web/src/api.ts` (`Observation`, `BlockEvent`, `ApprovalRequest` types)
- Modify: `web/src/pages/DeviceDetail.tsx` (publisher column + "Add as publisher")
- Modify: `web/src/pages/Approvals.tsx` (publisher column + "Approve publisher")

**Interfaces:**
- Consumes (Task 5): the new JSON fields and `kind` parameters.
- Produces: UI only. Verification is `tsc` via the console build.

- [ ] **Step 1: Extend the API types**

In `web/src/api.ts`, add to `Observation`, `BlockEvent` and `ApprovalRequest`:

```ts
  signer_tbs: string;
  signer_verified: boolean;
```

- [ ] **Step 2: Device detail — publisher column and action**

In `web/src/pages/DeviceDetail.tsx`, change `promote` to take a kind and add
a publisher column to the observed-applications table:

```tsx
  const promote = async (sha256: string, description: string, kind: "hash" | "publisher" = "hash") => {
    if (!promoteTo) {
      notify("Choose a policy first", "error");
      return;
    }
    try {
      await api.post("/api/observations/promote", { policy_id: promoteTo, sha256, description, kind });
      notify(kind === "publisher" ? "Publisher allowed" : "Added to policy");
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not add rule", "error");
    }
  };
```

In the observations table header, add `<th>Publisher</th>` before the actions
column, and in each row:

```tsx
                      <td>
                        {o.signer_verified ? (
                          o.signer || "Signed"
                        ) : o.signer || o.signer_tbs ? (
                          <span title="Windows could not verify this signature">Unverified signature</span>
                        ) : (
                          "—"
                        )}
                      </td>
```

and next to the existing "Add as rule" button:

```tsx
                        <button
                          className="ghost"
                          disabled={!o.signer_verified || !o.signer_tbs}
                          title={
                            o.signer_verified && o.signer_tbs
                              ? `Allow everything signed by ${o.signer || "this publisher"}`
                              : "Needs a signature Windows can verify"
                          }
                          onClick={() => promote(o.sha256, o.signer || o.path, "publisher")}
                        >
                          Add as publisher
                        </button>
```

- [ ] **Step 3: Approvals — publisher state and action**

`web/src/pages/Approvals.tsx` already has a `Signer` column and a `decide`
helper (which sends `{kind}` and reloads). Widen the helper's kind:

```tsx
  const decide = async (r: ApprovalRequest, action: "approve" | "deny", kind?: "hash" | "path" | "publisher") => {
```

Replace the signer cell so verification state is visible:

```tsx
                  <td>
                    {r.signer_verified ? (
                      r.signer || "Signed"
                    ) : r.signer || r.signer_tbs ? (
                      <span title="Windows could not verify this signature">{r.signer || "Unknown"} (unverified)</span>
                    ) : (
                      "—"
                    )}
                  </td>
```

Add the publisher button after the existing "Approve by path" button:

```tsx
                        <button
                          className="ghost"
                          disabled={busy === r.id || !r.signer_verified || !r.signer_tbs}
                          title={
                            r.signer_verified && r.signer_tbs
                              ? `Allow everything signed by ${r.signer || "this publisher"}`
                              : "Needs a signature Windows can verify"
                          }
                          onClick={() => decide(r, "approve", "publisher")}
                        >
                          Approve publisher
                        </button>
```

And correct the page's intro line, which currently claims approving always
adds a hash:

```tsx
        Programs a policy blocked or would have blocked. Approving adds the file's hash — or its path or
        publisher — to that policy's allowlist.
```

- [ ] **Step 4: Typecheck and build**

Run: `npm --prefix web run build`
Expected: `tsc -b` clean, `✓ built`, and `git status --short internal/server/webui` empty.

- [ ] **Step 5: Commit**

```bash
git add web/src
git commit -m "feat(console): show publishers and allow them as rules

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Full verification and merge

- [ ] **Step 1:** `go vet ./... && go test ./...` — every package `ok` (includes the WDAC `ConvertFrom-CIPolicy` Windows test, which must still accept a policy carrying a publisher rule).
- [ ] **Step 2:** `GOOS=linux go build ./... && GOOS=windows go build -o /dev/null ./cmd/agent ./cmd/server` — both succeed.
- [ ] **Step 3:** `npm --prefix web run build` — clean.
- [ ] **Step 4:** Append a "Publisher rules" section to `docs/appcontrol-manual-test.md`: on the VM, run a signed app, confirm the console shows its publisher as verified, allow the publisher, recompile, and confirm a *different* build signed by the same publisher is allowed while an unsigned copy still blocks in enforce mode. Commit the doc.
- [ ] **Step 5:** `git checkout master && git merge --ff-only feat/signer-rules`.
