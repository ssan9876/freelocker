package scan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakePE builds a minimal PE32+ image: DOS header, PE signature, COFF
// header, optional header with 16 data directories, some body bytes, and
// (if certLen > 0) a trailing certificate table the directory points at.
// It returns the file and the offsets of the checksum field and the
// certificate directory entry.
func fakePE(t *testing.T, certLen int) (data []byte, checksumOff, certDirOff int) {
	t.Helper()
	const peOff = 0x80
	const optOff = peOff + 4 + 20 // after "PE\0\0" + COFF header
	const optSize = 112 + 16*8    // PE32+ fixed part + 16 directories
	body := make([]byte, optOff+optSize+64)
	for i := range body {
		body[i] = byte(i * 7) // non-zero filler so excluded ranges matter
	}
	copy(body[0:], "MZ")
	binary.LittleEndian.PutUint32(body[0x3C:], peOff)
	copy(body[peOff:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(body[peOff+4+16:], optSize) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(body[optOff:], 0x20b)       // PE32+ magic
	binary.LittleEndian.PutUint32(body[optOff+108:], 16)      // NumberOfRvaAndSizes
	checksumOff = optOff + 64
	certDirOff = optOff + 112 + 4*8
	binary.LittleEndian.PutUint32(body[certDirOff:], 0)
	binary.LittleEndian.PutUint32(body[certDirOff+4:], 0)
	if certLen > 0 {
		binary.LittleEndian.PutUint32(body[certDirOff:], uint32(len(body)))
		binary.LittleEndian.PutUint32(body[certDirOff+4:], uint32(certLen))
		cert := make([]byte, certLen)
		for i := range cert {
			cert[i] = 0xCC
		}
		body = append(body, cert...)
	}
	return body, checksumOff, certDirOff
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.exe")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func upperHex(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func TestAuthenticodeHashExcludesChecksumCertEntryAndCertTable(t *testing.T) {
	data, ck, cd := fakePE(t, 24)
	certStart := int(binary.LittleEndian.Uint32(data[cd:]))

	h := sha256.New()
	h.Write(data[:ck])
	h.Write(data[ck+4 : cd])
	h.Write(data[cd+8 : certStart])
	want := upperHex(h.Sum(nil))

	got, err := AuthenticodeHash(writeTemp(t, data))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("AuthenticodeHash = %s, want %s", got, want)
	}

	// Changing only the excluded bytes must not change the hash.
	mutated := append([]byte(nil), data...)
	mutated[ck] ^= 0xFF
	mutated[len(mutated)-1] ^= 0xFF // inside the certificate table
	if again, _ := AuthenticodeHash(writeTemp(t, mutated)); again != want {
		t.Errorf("hash changed when only excluded bytes changed: %s", again)
	}
}

func TestAuthenticodeHashUnsignedPE(t *testing.T) {
	data, ck, cd := fakePE(t, 0)
	h := sha256.New()
	h.Write(data[:ck])
	h.Write(data[ck+4 : cd])
	h.Write(data[cd+8:])
	got, err := AuthenticodeHash(writeTemp(t, data))
	if err != nil || got != upperHex(h.Sum(nil)) {
		t.Fatalf("unsigned = %s, %v", got, err)
	}
}

func TestAuthenticodeHashNonPEFallsBackToSHA256(t *testing.T) {
	content := []byte("echo hello\r\n")
	sum := sha256.Sum256(content)
	got, err := AuthenticodeHash(writeTemp(t, content))
	if err != nil || got != upperHex(sum[:]) {
		t.Fatalf("non-PE = %s, %v; want plain SHA-256", got, err)
	}
}

func TestAuthenticodeHashMissingFile(t *testing.T) {
	if _, err := AuthenticodeHash(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
