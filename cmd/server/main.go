// Command freelocker-server runs the FreeLocker management server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(os.Args[1:], log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(args []string, log *slog.Logger) error {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", "", "path to server YAML config")
	org := fs.String("org", "", "organization name (init)")
	email := fs.String("email", "", "admin email (init, create-admin)")
	password := fs.String("password", "", "admin password (init, create-admin); prefer env FREELOCKER_ADMIN_PASSWORD")
	role := fs.String("role", "admin", "role for create-admin: owner, admin, readonly")
	fs.Parse(args)
	if *password == "" {
		*password = os.Getenv("FREELOCKER_ADMIN_PASSWORD")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()

	switch cmd {
	case "serve":
		return a.Run(ctx)
	case "init":
		k, err := a.Initialize(ctx, *org, *email, *password)
		if err != nil {
			return err
		}
		fmt.Printf("Initialized %q. CA pin: %s\n", *org, k.CA.Pin())
		return nil
	case "create-admin":
		return a.CreateAdmin(ctx, *email, *password, *role)
	default:
		return fmt.Errorf("unknown command %q (want serve, init, or create-admin)", cmd)
	}
}
