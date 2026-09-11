package metrics

import "testing"

func TestCollectReturnsPercentages(t *testing.T) {
	s, err := Collect()
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]float64{"cpu": s.CPUPct, "mem": s.MemPct, "disk": s.DiskPct} {
		if v < 0 || v > 100 {
			t.Errorf("%s = %v, out of [0,100]", name, v)
		}
	}
}

func TestClampPct(t *testing.T) {
	if clampPct(-5) != 0 || clampPct(150) != 100 || clampPct(42) != 42 {
		t.Fatal("clampPct wrong")
	}
}
