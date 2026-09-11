package scan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// AuthenticodeHash returns the upper-case hex Authenticode SHA-256 of a PE
// file — the hash WDAC `<Allow Hash=…>` rules and CodeIntegrity events use.
// It covers the whole file except the optional-header checksum, the
// certificate-table directory entry, and the certificate table itself, so it
// is the same whether or not (and however) the file is signed.
//
// Files that are not well-formed PE images fall back to a plain SHA-256.
func AuthenticodeHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := st.Size()

	h := sha256.New()
	ranges, ok := peHashRanges(f, size)
	if !ok {
		ranges = [][2]int64{{0, size}}
	}
	for _, r := range ranges {
		if _, err := io.Copy(h, io.NewSectionReader(f, r[0], r[1]-r[0])); err != nil {
			return "", err
		}
	}
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), nil
}

// peHashRanges returns the [start, end) byte ranges Authenticode hashes, or
// ok=false if the file is not a PE image whose headers lie within the file.
func peHashRanges(r io.ReaderAt, size int64) (ranges [][2]int64, ok bool) {
	u16 := func(off int64) (uint16, bool) {
		var b [2]byte
		if off < 0 || off+2 > size {
			return 0, false
		}
		if _, err := r.ReadAt(b[:], off); err != nil {
			return 0, false
		}
		return binary.LittleEndian.Uint16(b[:]), true
	}
	u32 := func(off int64) (uint32, bool) {
		var b [4]byte
		if off < 0 || off+4 > size {
			return 0, false
		}
		if _, err := r.ReadAt(b[:], off); err != nil {
			return 0, false
		}
		return binary.LittleEndian.Uint32(b[:]), true
	}

	if mz, ok := u16(0); !ok || mz != 0x5A4D { // "MZ"
		return nil, false
	}
	peOff32, ok := u32(0x3C)
	if !ok {
		return nil, false
	}
	peOff := int64(peOff32)
	if sig, ok := u32(peOff); !ok || sig != 0x00004550 { // "PE\0\0"
		return nil, false
	}
	optSize, ok := u16(peOff + 4 + 16)
	if !ok {
		return nil, false
	}
	optOff := peOff + 4 + 20
	magic, ok := u16(optOff)
	if !ok {
		return nil, false
	}
	var numDirsOff, dirsOff int64
	switch magic {
	case 0x10b: // PE32
		numDirsOff, dirsOff = optOff+92, optOff+96
	case 0x20b: // PE32+
		numDirsOff, dirsOff = optOff+108, optOff+112
	default:
		return nil, false
	}
	optEnd := optOff + int64(optSize)
	checksumOff := optOff + 64
	if optEnd > size || checksumOff+4 > optEnd {
		return nil, false
	}
	numDirs, ok := u32(numDirsOff)
	if !ok {
		return nil, false
	}

	const certDirIndex = 4 // IMAGE_DIRECTORY_ENTRY_SECURITY
	certDirOff := dirsOff + certDirIndex*8
	if numDirs <= certDirIndex || certDirOff+8 > optEnd {
		// No certificate directory: only the checksum is excluded.
		return [][2]int64{{0, checksumOff}, {checksumOff + 4, size}}, true
	}
	certOff32, _ := u32(certDirOff)
	certLen32, _ := u32(certDirOff + 4)
	certOff, certLen := int64(certOff32), int64(certLen32)

	ranges = [][2]int64{{0, checksumOff}, {checksumOff + 4, certDirOff}}
	if certLen == 0 || certOff < certDirOff+8 || certOff+certLen > size {
		// Unsigned (or a directory entry we can't trust): hash the rest.
		return append(ranges, [2]int64{certDirOff + 8, size}), true
	}
	ranges = append(ranges, [2]int64{certDirOff + 8, certOff})
	if end := certOff + certLen; end < size {
		ranges = append(ranges, [2]int64{end, size})
	}
	return ranges, true
}
