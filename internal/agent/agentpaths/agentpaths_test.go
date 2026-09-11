package agentpaths

import (
	"path/filepath"
	"testing"
)

func TestPathsAreUnderDataDir(t *testing.T) {
	p := Default()
	if p.DataDir == "" || p.InstallDir == "" {
		t.Fatal("empty paths")
	}
	for _, got := range []string{p.Config(), p.Key(), p.Cert(), p.CA(), p.Enrollment()} {
		if filepath.Dir(got) != p.DataDir {
			t.Errorf("%s not under DataDir %s", got, p.DataDir)
		}
	}
}
