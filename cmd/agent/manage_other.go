//go:build !windows

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"

	"freelocker/internal/agent/agentpaths"
)

func newFlagSet(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ExitOnError) }

func manage(string, []string, *slog.Logger) error {
	return errors.New("service management is only available on Windows")
}

func uninstaller(agentpaths.Paths) func(context.Context) error { return nil }
