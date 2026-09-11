//go:build !windows

package scan

func runningImpl() ([]Observed, error) { return nil, nil }
