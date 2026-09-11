// Package agentpaths centralizes the agent's on-disk locations.
package agentpaths

import (
	"os"
	"path/filepath"
)

type Paths struct {
	InstallDir string
	DataDir    string
}

func (p Paths) Config() string     { return filepath.Join(p.DataDir, "config.yaml") }
func (p Paths) Key() string        { return filepath.Join(p.DataDir, "device.key") }
func (p Paths) Cert() string       { return filepath.Join(p.DataDir, "device.crt") }
func (p Paths) CA() string         { return filepath.Join(p.DataDir, "ca.crt") }
func (p Paths) Enrollment() string { return filepath.Join(p.DataDir, "enrollment.json") }
func (p Paths) Log() string        { return filepath.Join(p.DataDir, "agent.log") }

// defaultDirs is overridden on Windows.
var defaultDirs = func() (install, data string) {
	base := filepath.Join(os.TempDir(), "freelocker")
	return filepath.Join(base, "bin"), filepath.Join(base, "data")
}

func Default() Paths {
	install, data := defaultDirs()
	return Paths{InstallDir: install, DataDir: data}
}
