//go:build windows

package hardening

import (
	"fmt"
	"os/exec"
)

// SecureDataDir restricts the data directory to SYSTEM and Administrators.
func SecureDataDir(dir string) error {
	steps := [][]string{
		{dir, "/inheritance:r"},
		{dir, "/grant:r", "SYSTEM:(OI)(CI)F"},
		{dir, "/grant:r", "Administrators:(OI)(CI)F"},
	}
	for _, args := range steps {
		if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("icacls %v: %v (%s)", args, err, out)
		}
	}
	return nil
}

func ConfigureRecovery(service string) error {
	out, err := exec.Command("sc.exe", "failure", service,
		"reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc failure: %v (%s)", err, out)
	}
	return nil
}
