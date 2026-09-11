//go:build !windows

package metrics

func collect() (Sample, error) { return Sample{}, nil }
