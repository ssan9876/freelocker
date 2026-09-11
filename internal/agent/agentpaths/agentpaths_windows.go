//go:build windows

package agentpaths

import (
	"os"
	"path/filepath"
)

func init() {
	defaultDirs = func() (install, data string) {
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pf, "FreeLocker"), filepath.Join(pd, "FreeLocker")
	}
}
