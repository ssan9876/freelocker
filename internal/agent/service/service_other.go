//go:build !windows

package service

import (
	"context"

	"freelocker/internal/agent/runner"
)

// Run executes the agent in the foreground on non-Windows platforms.
func Run(ctx context.Context, r *runner.Runner) error { return r.Run(ctx) }
