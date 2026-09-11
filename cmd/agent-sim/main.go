// Command agent-sim runs many fake agents against a FreeLocker server for
// integration and load testing.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/sim"
)

type stateEntry struct {
	Hostname string        `json:"hostname"`
	Identity *sim.Identity `json:"identity"`
}

func main() {
	server := flag.String("server", "localhost:8443", "agent API address (host must be in the server's public_hostnames)")
	token := flag.String("token", "", "install token (needed only for agents not yet in the state file)")
	count := flag.Int("count", 1, "number of simulated agents")
	interval := flag.Duration("interval", 30*time.Second, "heartbeat interval")
	statePath := flag.String("state", "sim-state.json", "file that persists enrolled identities between runs")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	agents, err := loadOrEnroll(ctx, *statePath, *server, *token, *count)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("running %d simulated agents against %s (Ctrl+C to stop)\n", len(agents), *server)

	var wg sync.WaitGroup
	for _, a := range agents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			(&sim.Runner{Addr: *server, Identity: a.Identity, Hostname: a.Hostname, Interval: *interval, Log: log}).Run(ctx)
		}()
		time.Sleep(5 * time.Millisecond) // spread connection storms
	}
	wg.Wait()
}

func loadOrEnroll(ctx context.Context, path, server, token string, count int) ([]stateEntry, error) {
	var agents []stateEntry
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &agents); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(agents) >= count {
		return agents[:count], nil
	}
	if token == "" {
		return nil, fmt.Errorf("need -token to enroll %d more agents", count-len(agents))
	}

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 50)
		errs []error
	)
	for i := len(agents); i < count; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			host := fmt.Sprintf("sim-%05d", i)
			id, err := sim.Enroll(ctx, server, token, &flv1.HardwareInfo{Hostname: host, OsBuild: "sim", MachineGuid: host})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", host, err))
				return
			}
			agents = append(agents, stateEntry{Hostname: host, Identity: id})
		}()
	}
	wg.Wait()
	b, _ := json.MarshalIndent(agents, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%d enrollments failed, first: %w", len(errs), errs[0])
	}
	return agents, nil
}
