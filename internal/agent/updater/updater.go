// Package updater downloads, verifies, and stages agent updates. The
// actual binary swap is performed by the separate cmd/agent-updater
// process so the running image is not being replaced under itself.
package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func Download(ctx context.Context, url string, wantSHA256 []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if !bytes.Equal(sum[:], wantSHA256) {
		return nil, errors.New("downloaded binary hash mismatch")
	}
	return b, nil
}

func Verify(pub ed25519.PublicKey, sha256sum, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("bad update public key")
	}
	if !ed25519.Verify(pub, sha256sum, signature) {
		return errors.New("update signature invalid")
	}
	return nil
}

func Stage(dir string, bin []byte) (string, error) {
	path := filepath.Join(dir, "freelocker-agent.new.exe")
	if err := os.WriteFile(path, bin, 0o755); err != nil {
		return "", err
	}
	return path, nil
}

type Plan struct {
	CurrentExe  string
	NewExe      string
	UpdaterExe  string
	ServiceName string
}

func (p Plan) SwapArgs() []string {
	return []string{"swap", "-service", p.ServiceName, "-current", p.CurrentExe, "-new", p.NewExe}
}
