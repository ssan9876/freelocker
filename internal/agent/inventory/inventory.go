// Package inventory gathers the facts sent in each heartbeat.
package inventory

import (
	"net"
	"os"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/version"
)

type Collector interface {
	Collect() *flv1.Inventory
}

type Base struct {
	StartedAt time.Time
}

func (b Base) base() *flv1.Inventory {
	host, _ := os.Hostname()
	return &flv1.Inventory{
		Hostname: host, AgentVersion: version.Version,
		IpAddresses: LocalIPs(), UptimeSeconds: int64(time.Since(b.StartedAt).Seconds()),
	}
}

func LocalIPs() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}
