//go:build windows

package ringfence

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/windows/registry"
)

const asrKey = `SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`

// WinEnforcer applies ringfences with netsh firewall rules and ASR machine
// policy. Both are reversible: rules are removed and values deleted.
type WinEnforcer struct {
	// agentImages are paths that must never be ringfenced, so a ringfence
	// can never sever the agent's own management link.
	agentImages []string

	mu      sync.Mutex
	applied string
	last    Ringfence
}

func Default(agentImages []string) Enforcer {
	lower := make([]string, 0, len(agentImages))
	for _, p := range agentImages {
		lower = append(lower, strings.ToLower(p))
	}
	return &WinEnforcer{agentImages: lower}
}

func (e *WinEnforcer) Apply(_ context.Context, r Ringfence) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.applied == r.Version && r.Version != "" {
		return nil // idempotent
	}
	for _, p := range r.Programs {
		for _, self := range e.agentImages {
			if strings.EqualFold(p.Path, self) {
				return fmt.Errorf("refusing to ringfence the agent's own image %q: that would sever management", p.Path)
			}
		}
	}
	if err := e.applyNetwork(r); err != nil {
		return err
	}
	if err := e.applyASR(r); err != nil {
		return err
	}
	e.applied = r.Version
	e.last = r
	return nil
}

// applyNetwork reconciles FreeLocker-RF-* rules. In audit mode no block rule
// is created: audit is observed through WFP connection logging instead.
func (e *WinEnforcer) applyNetwork(r Ringfence) error {
	desired := map[string]Program{}
	if r.Mode == "enforce" {
		for _, p := range r.Programs {
			desired[RuleName(p.Path)] = p
		}
	}
	add, remove := Diff(e.existingRules(), desired)
	for _, name := range remove {
		netsh("advfirewall", "firewall", "delete", "rule", "name="+name)
	}
	for _, p := range add {
		if err := netshErr("advfirewall", "firewall", "add", "rule",
			"name="+RuleName(p.Path), "dir=out", "action=block", "enable=yes",
			"program="+p.Path); err != nil {
			return err
		}
	}
	// Audit needs WFP connection auditing on; enforce needs it for 5157.
	exec.Command("auditpol", "/set", "/subcategory:Filtering Platform Connection", "/success:enable").Run()
	return nil
}

// existingRules lists the names of firewall rules this package owns.
func (e *WinEnforcer) existingRules() []string {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all").Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, RulePrefix); i >= 0 {
			names = append(names, strings.TrimSpace(line[i:]))
		}
	}
	return names
}

func (e *WinEnforcer) applyASR(r Ringfence) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, asrKey, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("open ASR policy key: %w", err)
	}
	defer k.Close()
	want := map[string]string{}
	for _, p := range r.Protections {
		want[strings.ToUpper(p.ASRRule)] = p.Action
	}
	// Remove values we previously set that are no longer wanted. Errors here
	// are not ignored: a value that fails to delete (or a names list that
	// fails to read) leaves a stale ASR policy enforcing on the endpoint
	// after the ringfence is unassigned, silently breaking the reversibility
	// guarantee.
	names, err := k.ReadValueNames(0)
	if err != nil {
		return fmt.Errorf("read ASR policy values: %w", err)
	}
	for _, n := range names {
		if _, ok := want[strings.ToUpper(n)]; !ok {
			if err := k.DeleteValue(n); err != nil {
				return fmt.Errorf("remove stale ASR %s: %w", n, err)
			}
		}
	}
	for guid, action := range want {
		v := uint32(1) // block
		if action == "audit" {
			v = 2
		}
		if err := k.SetDWordValue(guid, v); err != nil {
			return fmt.Errorf("set ASR %s: %w", guid, err)
		}
	}
	return nil
}

// Violations reads both sources. Which WFP event id matters depends on mode:
// enforce produces 5157 (blocked), audit produces 5156 (allowed, would have
// been blocked).
func (e *WinEnforcer) Violations(_ context.Context) ([]Violation, error) {
	e.mu.Lock()
	last := e.last
	e.mu.Unlock()
	if last.Version == "" {
		return nil, nil
	}
	set := make(map[string]bool, len(last.Programs))
	for _, p := range last.Programs {
		if p.NetworkBlocked {
			set[strings.ToLower(p.Path)] = true
		}
	}
	id := "5156"
	if last.Mode == "enforce" {
		id = "5157"
	}
	var out []Violation
	if raw, err := exec.Command("wevtutil", "qe", "Security",
		"/q:*[System[(EventID="+id+")]]", "/c:500", "/rd:true", "/f:xml").Output(); err == nil {
		if v, err := ParseWFP(raw, set); err == nil {
			out = append(out, v...)
		}
	}
	if raw, err := exec.Command("wevtutil", "qe", "Microsoft-Windows-Windows Defender/Operational",
		"/q:*[System[(EventID=1121 or EventID=1122)]]", "/c:200", "/rd:true", "/f:xml").Output(); err == nil {
		if v, err := ParseDefenderASR(raw); err == nil {
			out = append(out, v...)
		}
	}
	return Dedupe(out, 200), nil
}

func (e *WinEnforcer) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Status{Applied: e.applied, ASRAvailable: defenderActive()}
}

// defenderActive reports whether Defender real-time protection is on, which
// is what makes ASR values actually bite. When it is off the values are
// inert and the console must say so rather than showing a green tick.
func defenderActive() bool {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-MpComputerStatus).RealTimeProtectionEnabled").Output()
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(string(out)), "True")
}

func netsh(args ...string) { exec.Command("netsh", args...).Run() }

func netshErr(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
