package inventory

import (
	"testing"
)

func TestCollectFillsBasics(t *testing.T) {
	c := New()
	inv := c.Collect()
	if inv.GetHostname() == "" {
		t.Error("hostname empty")
	}
	if inv.GetAgentVersion() == "" {
		t.Error("agent version empty")
	}
	if inv.GetUptimeSeconds() < 0 {
		t.Error("negative uptime")
	}
}

func TestLocalIPsExcludeLoopback(t *testing.T) {
	for _, ip := range LocalIPs() {
		if ip == "127.0.0.1" || ip == "::1" {
			t.Errorf("loopback leaked: %s", ip)
		}
	}
}
