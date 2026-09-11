// Package metrics collects endpoint resource utilization for telemetry.
// Values are percentages in [0,100]. Collection is platform-specific:
// real on Windows, a zeroed stub elsewhere so the logic builds and tests
// off-Windows.
package metrics

type Sample struct {
	CPUPct  float64
	MemPct  float64
	DiskPct float64
}

// Collect returns a single resource sample.
func Collect() (Sample, error) { return collect() }

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
