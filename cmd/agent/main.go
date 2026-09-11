// Command freelocker-agent is the endpoint agent: a Windows service that
// enrolls with the server and enforces policy. It also runs in the
// foreground for development on any OS.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"freelocker/internal/agent/actions"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/config"
	"freelocker/internal/agent/enforcer"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
	"freelocker/internal/agent/runner"
	"freelocker/internal/agent/secret"
	"freelocker/internal/agent/service"
	"freelocker/internal/agent/version"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	verb := "run"
	if len(os.Args) > 1 {
		verb = os.Args[1]
	}
	switch verb {
	case "version":
		fmt.Println(version.Version)
	case "run":
		if err := runAgent(log); err != nil {
			log.Error("agent exited", "err", err)
			os.Exit(1)
		}
	case "write-config":
		if err := writeConfig(os.Args[2:]); err != nil {
			log.Error("write-config failed", "err", err)
			os.Exit(1)
		}
	case "install-service", "uninstall":
		if err := manage(verb, os.Args[2:], log); err != nil {
			log.Error(verb+" failed", "err", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: freelocker-agent [run|install-service|uninstall|write-config|version]")
		os.Exit(2)
	}
}

func writeConfig(args []string) error {
	fs := newFlagSet("write-config")
	server := fs.String("server", "", "server URL host:port")
	token := fs.String("token", "", "install token")
	fs.Parse(args)
	if *server == "" {
		return fmt.Errorf("-server is required")
	}
	paths := agentpaths.Default()
	if err := os.MkdirAll(paths.DataDir, 0o755); err != nil {
		return err
	}
	return config.Write(paths.Config(), config.Config{ServerURL: *server, Token: *token})
}

func runAgent(log *slog.Logger) error {
	paths := agentpaths.Default()
	cfg, err := config.Load(paths.Config())
	if err != nil {
		return err
	}
	st := &identity.Store{Paths: paths, Protector: secret.Default()}
	inv := inventory.New()
	r := &runner.Runner{
		ServerURL: cfg.ServerURL, Identity: st, Inventory: inv,
		HeartbeatInterval: 30 * time.Second, Log: log,
	}
	act := &actions.Actions{
		Identity: st, Paths: paths, ServerURL: cfg.ServerURL, Log: log,
		UpdatePub: func() ed25519.PublicKey {
			l, err := st.Load()
			if err != nil {
				return nil
			}
			return ed25519.PublicKey(l.UpdatePub)
		},
		Renew: func(ctx context.Context) error {
			l, err := st.Load()
			if err != nil {
				return err
			}
			return st.Renew(ctx, cfg.ServerURL, l)
		},
		Uninstaller: uninstaller(paths),
	}
	r.Executor = &executor.Executor{Actions: act, Log: log}
	r.Enforcer = enforcer.Default(paths.DataDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if !st.Enrolled() {
		if cfg.Token == "" {
			return fmt.Errorf("not enrolled and no token in %s", paths.Config())
		}
		if err := r.EnsureEnrolled(ctx, cfg.Token, runner.HardwareInfo(inv)); err != nil {
			return err
		}
		log.Info("enrolled")
	}
	// The update-signing key (learned at enrollment) also verifies policy.
	if l, err := st.Load(); err == nil {
		r.UpdatePub = ed25519.PublicKey(l.UpdatePub)
	}
	return service.Run(ctx, r)
}
