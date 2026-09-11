//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/hardening"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/secret"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "FreeLockerAgent"

func newFlagSet(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ExitOnError) }

func manage(verb string, args []string, log *slog.Logger) error {
	switch verb {
	case "install-service":
		return installService()
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
		code := fs.String("code", "", "uninstall code from the console")
		force := fs.Bool("force-fromserver", false, "skip code check (server-driven uninstall)")
		fs.Parse(args)
		return uninstall(*code, *force)
	default:
		return fmt.Errorf("unknown verb %q", verb)
	}
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already installed", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "FreeLocker Agent", StartType: mgr.StartAutomatic, Description: "FreeLocker endpoint agent.",
	}, "run")
	if err != nil {
		return err
	}
	defer s.Close()

	paths := agentpaths.Default()
	if err := hardening.SecureDataDir(paths.DataDir); err != nil {
		return err
	}
	if err := hardening.ConfigureRecovery(serviceName); err != nil {
		return err
	}
	return s.Start()
}

func uninstall(code string, force bool) error {
	paths := agentpaths.Default()
	if !force {
		st := &identity.Store{Paths: paths, Protector: secret.Default()}
		enr, err := st.Load()
		if err != nil {
			return fmt.Errorf("cannot verify uninstall code: %w", err)
		}
		sum := sha256.Sum256([]byte(code))
		if subtle.ConstantTimeCompare(sum[:], enr.UninstallHash) != 1 {
			return fmt.Errorf("incorrect uninstall code")
		}
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		s.Control(svc.Stop)
		waitStopped(s, 30*time.Second)
		s.Delete()
	}
	return os.RemoveAll(paths.DataDir)
}

func waitStopped(s *mgr.Service, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if st, err := s.Query(); err == nil && st.State == svc.Stopped {
			return
		}
		time.Sleep(time.Second)
	}
}

// uninstaller returns a func the running service uses to remove itself on
// a server Uninstall command (bypasses the code check).
func uninstaller(paths agentpaths.Paths) func(context.Context) error {
	return func(context.Context) error {
		exe := filepath.Join(paths.InstallDir, "freelocker-agent.exe")
		return exec.Command(exe, "uninstall", "-force-fromserver").Start()
	}
}
