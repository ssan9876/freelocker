package secret

import (
	"bytes"
	"testing"
)

func TestDefaultRoundtrip(t *testing.T) {
	p := Default()
	sealed, err := p.Protect([]byte("device-private-key"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Unprotect(sealed)
	if err != nil || !bytes.Equal(got, []byte("device-private-key")) {
		t.Fatalf("Unprotect = %q, %v", got, err)
	}
}
