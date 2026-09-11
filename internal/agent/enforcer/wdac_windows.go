//go:build windows

package enforcer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"freelocker/internal/agent/blocks"
)

// WDACEnforcer applies a WDAC policy via CiTool. It writes the policy XML,
// converts it to a binary .cip, and updates the active policy set.
//
// SAFETY: enforce mode is honored only when an explicit opt-in file exists
// at <dataDir>\allow-enforce. Without it, an "enforce" policy is downgraded
// to audit so a bad policy can never lock the machine unattended.
type WDACEnforcer struct {
	DataDir string // where policy files and the opt-in flag live

	mu     sync.Mutex
	status Status
}

func (e *WDACEnforcer) enforceAllowed() bool {
	_, err := os.Stat(filepath.Join(e.DataDir, "allow-enforce"))
	return err == nil
}

func (e *WDACEnforcer) Apply(ctx context.Context, version, mode string, xml []byte) error {
	if mode != "audit" && mode != "enforce" {
		return ErrBadMode
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.status.AppliedVersion == version {
		return nil // idempotent
	}
	effectiveMode := mode
	if mode == "enforce" && !e.enforceAllowed() {
		effectiveMode = "audit"
	}

	if err := os.MkdirAll(e.DataDir, 0o755); err != nil {
		return err
	}
	xmlPath := filepath.Join(e.DataDir, "policy.xml")
	cipPath := filepath.Join(e.DataDir, "policy.cip")
	if err := os.WriteFile(xmlPath, xml, 0o644); err != nil {
		return err
	}
	// Convert XML -> binary policy. ConvertFrom-CIPolicy ships with Windows.
	conv := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`ConvertFrom-CIPolicy -XmlFilePath '%s' -BinaryFilePath '%s'`, xmlPath, cipPath))
	if out, err := conv.CombinedOutput(); err != nil {
		return fmt.Errorf("ConvertFrom-CIPolicy: %v (%s)", err, out)
	}
	// Apply with CiTool (Windows 11 / Server 2022+).
	apply := exec.CommandContext(ctx, "CiTool.exe", "--update-policy", cipPath, "--json")
	if out, err := apply.CombinedOutput(); err != nil {
		return fmt.Errorf("CiTool --update-policy: %v (%s)", err, out)
	}
	e.status = Status{AppliedVersion: version, AppliedMode: effectiveMode}
	return nil
}

func (e *WDACEnforcer) Events(ctx context.Context) ([]blocks.BlockEvent, error) {
	// Query enforced (3077) and audit (3076) CodeIntegrity events as XML.
	cmd := exec.CommandContext(ctx, "wevtutil", "qe",
		"Microsoft-Windows-CodeIntegrity/Operational",
		`/q:*[System[(EventID=3076 or EventID=3077)]]`,
		"/c:200", "/rd:true", "/f:xml")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("wevtutil: %w", err)
	}
	return blocks.ParseCodeIntegrity(out)
}

func (e *WDACEnforcer) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}
