// Command agent-updater replaces the FreeLocker agent binary out of band
// and rolls back if the new build does not become healthy.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "swap" {
		fmt.Fprintln(os.Stderr, "usage: agent-updater swap -service <name> -current <path> -new <path>")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("swap", flag.ExitOnError)
	service := fs.String("service", "FreeLockerAgent", "service name")
	current := fs.String("current", "", "path to the installed agent exe")
	newExe := fs.String("new", "", "path to the downloaded new exe")
	fs.Parse(os.Args[2:])
	if *current == "" || *newExe == "" {
		fmt.Fprintln(os.Stderr, "current and new are required")
		os.Exit(2)
	}
	if err := swap(*service, *current, *newExe); err != nil {
		fmt.Fprintln(os.Stderr, "swap failed:", err)
		os.Exit(1)
	}
}

func swap(service, current, newExe string) error {
	backup := current + ".bak"
	sc := func(args ...string) error { return exec.Command("sc.exe", args...).Run() }

	sc("stop", service)
	waitStopped(service, 30*time.Second)

	os.Remove(backup)
	if err := os.Rename(current, backup); err != nil {
		return fmt.Errorf("backup current: %w", err)
	}
	if err := os.Rename(newExe, current); err != nil {
		os.Rename(backup, current) // restore
		sc("start", service)
		return fmt.Errorf("install new: %w", err)
	}
	if err := sc("start", service); err != nil {
		return rollback(service, current, backup, fmt.Errorf("start new: %w", err))
	}
	if healthy(service, 2*time.Minute) {
		os.Remove(backup)
		return nil
	}
	return rollback(service, current, backup, fmt.Errorf("new agent did not become healthy"))
}

func rollback(service, current, backup string, cause error) error {
	exec.Command("sc.exe", "stop", service).Run()
	waitStopped(service, 30*time.Second)
	os.Remove(current)
	if err := os.Rename(backup, current); err != nil {
		return fmt.Errorf("%v; ALSO rollback failed: %w", cause, err)
	}
	exec.Command("sc.exe", "start", service).Run()
	return cause
}

func healthy(service string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if serviceRunning(service) {
			return true
		}
		time.Sleep(3 * time.Second)
	}
	return false
}

func serviceRunning(service string) bool {
	out, err := exec.Command("sc.exe", "query", service).Output()
	return err == nil && strings.Contains(string(out), "RUNNING")
}

func waitStopped(service string, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !serviceRunning(service) {
			return
		}
		time.Sleep(1 * time.Second)
	}
}
