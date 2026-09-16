//go:build windows

package ringfence

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

const asrKey = `SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`

// defenderStatusTTL caps how often Status() shells out to PowerShell to ask
// Defender whether it is active. The runner calls Status() every
// app-control tick on every device, including devices with no ringfence at
// all, and Defender's real-time-protection state rarely changes, so a fresh
// process per tick buys nothing but cost.
const defenderStatusTTL = 3 * time.Minute

// WinEnforcer applies ringfences with netsh firewall rules and ASR machine
// policy. Both are reversible: rules are removed and values deleted.
type WinEnforcer struct {
	// agentImages are paths that must never be ringfenced, so a ringfence
	// can never sever the agent's own management link.
	agentImages []string

	mu      sync.Mutex
	applied string
	last    Ringfence

	// secRecordID/defRecordID are per-source watermarks (the Windows event
	// RecordId), so Violations only ever asks wevtutil for records newer
	// than the highest one already seen, instead of re-reading and
	// re-reporting the same events every tick.
	secRecordID int64
	defRecordID int64

	// defenderCache/defenderCachedAt back Status()'s TTL cache.
	defenderCache    bool
	defenderCachedAt time.Time
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
		// Unlike the historical netsh() fire-and-forget, a delete failure
		// here is logged: silently leaving a stale block/allow rule in
		// place on unassign is exactly the kind of residue the ASR side was
		// fixed to report loudly, and the firewall side should not be worse.
		if err := netshErr("advfirewall", "firewall", "delete", "rule", "name="+name); err != nil {
			slog.Error("ringfence: failed to delete firewall rule", "rule", name, "err", err)
		}
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
	// Remove values FreeLocker owns (CuratedASRRules — the same six GUIDs
	// the server accepts) that are no longer wanted. This key is also where
	// GPO and Intune write ASR policy, so it is NOT safe to delete every
	// value name that isn't in `want`: doing so silently strips org-wide ASR
	// configuration the first time an admin assigns a ringfence with no
	// protections. Errors here are not ignored: a value that fails to
	// delete (or a names list that fails to read) leaves a stale ASR policy
	// enforcing on the endpoint after the ringfence is unassigned, silently
	// breaking the reversibility guarantee.
	names, err := k.ReadValueNames(0)
	if err != nil {
		return fmt.Errorf("read ASR policy values: %w", err)
	}
	for _, n := range StaleASRValues(names, want) {
		if err := k.DeleteValue(n); err != nil {
			return fmt.Errorf("remove stale ASR %s: %w", n, err)
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

// Violations reads both sources, bounded to records newer than the
// per-source watermark (secRecordID/defRecordID) so the same events are not
// re-read and re-reported on every tick — see EventQuery/MaxRecordID.
// Which WFP event id matters depends on mode: enforce produces 5157
// (blocked), audit produces 5156 (allowed, would have been blocked).
func (e *WinEnforcer) Violations(_ context.Context) ([]Violation, error) {
	e.mu.Lock()
	last := e.last
	secWM := e.secRecordID
	defWM := e.defRecordID
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
	wfpID := 5156
	if last.Mode == "enforce" {
		wfpID = 5157
	}
	var out []Violation
	if raw, err := exec.Command("wevtutil", "qe", "Security",
		"/q:"+EventQuery([]int{wfpID}, secWM), "/c:500", "/rd:true", "/f:xml").Output(); err == nil {
		if v, err := ParseWFP(raw, set); err == nil {
			out = append(out, v...)
		}
		// The watermark advances past every record in the batch, including
		// ones ParseWFP dropped for not matching a ringfenced program —
		// otherwise those would be re-fetched forever.
		if m, err := MaxRecordID(raw); err == nil && m > secWM {
			secWM = m
		}
	}
	if raw, err := exec.Command("wevtutil", "qe", "Microsoft-Windows-Windows Defender/Operational",
		"/q:"+EventQuery([]int{1121, 1122}, defWM), "/c:200", "/rd:true", "/f:xml").Output(); err == nil {
		if v, err := ParseDefenderASR(raw); err == nil {
			out = append(out, v...)
		}
		if m, err := MaxRecordID(raw); err == nil && m > defWM {
			defWM = m
		}
	}
	e.mu.Lock()
	e.secRecordID = secWM
	e.defRecordID = defWM
	e.mu.Unlock()
	return Dedupe(out, 200), nil
}

func (e *WinEnforcer) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	if time.Since(e.defenderCachedAt) > defenderStatusTTL {
		e.defenderCache = defenderActive()
		e.defenderCachedAt = time.Now()
	}
	return Status{Applied: e.applied, ASRAvailable: e.defenderCache}
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

func netshErr(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
