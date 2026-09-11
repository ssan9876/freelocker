// Package actions implements executor.Actions for the real agent.
package actions

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/updater"
	"freelocker/internal/server/commands"
)

type Actions struct {
	Identity  *identity.Store
	Paths     agentpaths.Paths
	ServerURL string
	UpdatePub func() ed25519.PublicKey
	Log       *slog.Logger

	// Renew is injected by the service so RotateCertificate reuses the
	// runner's server URL and loaded identity.
	Renew func(ctx context.Context) error
	// Uninstaller performs stop+delete+cleanup (Windows implementation
	// injected by the service; nil elsewhere).
	Uninstaller func(ctx context.Context) error

	// StageOnly stops UpdateAgent before launching the swap helper (tests).
	StageOnly bool
}

func (a *Actions) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

func (a *Actions) RefreshInventory(ctx context.Context) error { return nil }

func (a *Actions) RotateCertificate(ctx context.Context) error {
	if a.Renew == nil {
		return errors.New("renew not wired")
	}
	return a.Renew(ctx)
}

func (a *Actions) Uninstall(ctx context.Context) error {
	if a.Uninstaller == nil {
		return errors.New("uninstall not supported in this build")
	}
	return a.Uninstaller(ctx)
}

func (a *Actions) UpdateAgent(ctx context.Context, cmd *flv1.Command) error {
	p, err := commands.ParseUpdate(cmd.GetPayload())
	if err != nil {
		return err
	}
	bin, err := updater.Download(ctx, p.URL, p.SHA256)
	if err != nil {
		return err
	}
	if err := updater.Verify(a.UpdatePub(), p.SHA256, p.Signature); err != nil {
		return err
	}
	staged, err := updater.Stage(a.Paths.InstallDir, bin)
	if err != nil {
		return err
	}
	if a.StageOnly {
		return nil
	}
	current, err := os.Executable()
	if err != nil {
		return err
	}
	plan := updater.Plan{
		CurrentExe: current, NewExe: staged, ServiceName: "FreeLockerAgent",
		UpdaterExe: filepath.Join(a.Paths.InstallDir, "agent-updater.exe"),
	}
	if err := exec.Command(plan.UpdaterExe, plan.SwapArgs()...).Start(); err != nil {
		return err
	}
	a.log().Info("update staged; swap helper launched", "version", p.Version)
	return nil // the swap helper will stop this service
}
