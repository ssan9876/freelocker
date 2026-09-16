//go:build windows

package motw

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

// maxStreamBytes caps how much of the stream is read. A real Zone.Identifier
// is a few hundred bytes; anything larger is malformed or hostile, and this
// runs over every binary a machine executes.
const maxStreamBytes = 8 << 10

// Read returns the Mark-of-the-Web for a file.
//
// A missing stream is the normal case — every file Windows installed has
// none — so it returns a zero Info and a nil error rather than an error the
// caller has to classify. Only a genuine failure (permission, I/O) returns
// one, and even then the caller should carry on: provenance is an attribute
// of an observation, never a reason to drop it.
func Read(path string) (Info, error) {
	f, err := os.Open(path + streamName)
	if err != nil {
		// NTFS reports a missing stream as not-exist; FAT/exFAT and network
		// shares have no stream support at all and report various errors.
		// All mean the same thing to us: no mark.
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrInvalid) {
			return Info{}, nil
		}
		return Info{}, err
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxStreamBytes))
	if err != nil {
		return Info{}, err
	}
	return Parse(raw), nil
}
