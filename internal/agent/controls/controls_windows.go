//go:build windows

package controls

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/windows/registry"
)

const (
	usbstorKey = `SYSTEM\CurrentControlSet\Services\USBSTOR`
	// usbstorStart: 3 = manual (allowed), 4 = disabled (blocked).
	usbAllow = 3
	usbBlock = 4

	// System policy key holding UAC elevation behavior.
	systemPolicyKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	// ConsentPromptBehaviorUser: 3 = prompt standard users for credentials
	// (default), 0 = automatically deny elevation requests from standard
	// users. Admin elevation (ConsentPromptBehaviorAdmin) is untouched, so
	// this never locks administrators out.
	elevationAllow = 3
	elevationBlock = 0

	fwRulePrefix = "FreeLocker-Net"
)

type WinEnforcer struct {
	// ServerHost is host or host:port of the FreeLocker server; network
	// blocking always keeps an allow-exception for it so the agent's own
	// connection survives.
	ServerHost string

	mu   sync.Mutex
	last Controls
	set  bool
}

func Default(serverHost string) Enforcer { return &WinEnforcer{ServerHost: serverHost} }

func (e *WinEnforcer) Apply(_ context.Context, c Controls) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.set && e.last == c {
		return nil // idempotent
	}
	if err := e.applyUSB(c.USBStorageBlocked); err != nil {
		return err
	}
	if err := e.applyElevation(c.ElevationBlocked); err != nil {
		return err
	}
	if err := e.applyNetwork(c.NetworkBlocked); err != nil {
		return err
	}
	e.last, e.set = c, true
	return nil
}

func (e *WinEnforcer) applyUSB(blocked bool) error {
	want := uint32(usbAllow)
	if blocked {
		want = usbBlock
	}
	return setDWord(usbstorKey, "Start", want)
}

func (e *WinEnforcer) applyElevation(blocked bool) error {
	want := uint32(elevationAllow)
	if blocked {
		want = elevationBlock
	}
	return setDWord(systemPolicyKey, "ConsentPromptBehaviorUser", want)
}

// applyNetwork sets the default outbound firewall action to block and adds
// allow rules for the server, DNS, and DHCP so the agent stays reachable;
// unblocking restores the default outbound-allow and removes the rules.
func (e *WinEnforcer) applyNetwork(blocked bool) error {
	if !blocked {
		netsh("advfirewall", "firewall", "delete", "rule", "name="+fwRulePrefix+"-Server")
		netsh("advfirewall", "firewall", "delete", "rule", "name="+fwRulePrefix+"-DNS")
		netsh("advfirewall", "firewall", "delete", "rule", "name="+fwRulePrefix+"-DHCP")
		return netshErr("advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
	}
	// Allow rules first, then flip the default so nothing else gets out.
	ips := e.serverIPs()
	if len(ips) == 0 {
		return fmt.Errorf("cannot block network: server host %q did not resolve; refusing to risk cutting management", e.ServerHost)
	}
	if err := netshErr("advfirewall", "firewall", "add", "rule", "name="+fwRulePrefix+"-Server",
		"dir=out", "action=allow", "enable=yes", "remoteip="+strings.Join(ips, ",")); err != nil {
		return err
	}
	netsh("advfirewall", "firewall", "add", "rule", "name="+fwRulePrefix+"-DNS",
		"dir=out", "action=allow", "enable=yes", "protocol=UDP", "remoteport=53")
	netsh("advfirewall", "firewall", "add", "rule", "name="+fwRulePrefix+"-DHCP",
		"dir=out", "action=allow", "enable=yes", "protocol=UDP", "remoteport=67,68")
	return netshErr("advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")
}

func (e *WinEnforcer) serverIPs() []string {
	host := e.ServerHost
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	return addrs
}

func (e *WinEnforcer) Last() Controls {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.last
}

func setDWord(key, name string, val uint32) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, val)
}

func netsh(args ...string) { _ = exec.Command("netsh", args...).Run() }

func netshErr(args ...string) error {
	if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("netsh %v: %v (%s)", args, err, out)
	}
	return nil
}
