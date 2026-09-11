//go:build windows

package wdac

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"freelocker/internal/appcontrol/rules"
)

// powershell64 is the native Windows PowerShell (the ConfigCI module is
// not available to a 32-bit shell).
const powershell64 = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

// TestWindowsAcceptsCompiledPolicy converts compiled policies to binary
// with Microsoft's ConvertFrom-CIPolicy. That only writes a .cip file into
// a temp dir — nothing is deployed or activated — so it is safe on a dev
// box, and proves Windows accepts the XML we generate.
func TestWindowsAcceptsCompiledPolicy(t *testing.T) {
	probe, err := exec.Command(powershell64, "-NoProfile", "-Command",
		`if (Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }`).Output()
	if err != nil || strings.TrimSpace(string(probe)) != "yes" {
		t.Skip("ConfigCI (ConvertFrom-CIPolicy) not available")
	}

	withRules := []rules.Rule{
		{Kind: rules.Hash, Value: strings.Repeat("A1", 32), Description: `approved "tool" & more`},
		{Kind: rules.Path, Value: `C:\Tools\*`},
		{Kind: rules.Publisher, Value: strings.Repeat("B2", 32), PublisherName: "Acme Corp"},
	}
	cases := map[string]Policy{
		"empty-audit":          {Mode: "audit"},
		"rules-audit":          {Mode: "audit", Rules: withRules},
		"rules-enforce":        {Mode: "enforce", Rules: withRules},
		"hash-only-audit":      {Mode: "audit", Rules: withRules[:1]},
		"path-only-audit":      {Mode: "audit", Rules: withRules[1:2]},
		"publisher-only-audit": {Mode: "audit", Rules: withRules[2:3]},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			xml, err := Compile(p)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			xmlPath := filepath.Join(dir, "policy.xml")
			cipPath := filepath.Join(dir, "policy.cip")
			if err := os.WriteFile(xmlPath, xml, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(powershell64, "-NoProfile", "-Command",
				`$ErrorActionPreference = 'Stop'
				try { ConvertFrom-CIPolicy -XmlFilePath '`+xmlPath+`' -BinaryFilePath '`+cipPath+`' | Out-Null }
				catch {
					$e = $_.Exception
					$msg = ($_ | Out-String -Width 4096)
					while ($e) { $msg += [Environment]::NewLine + $e.GetType().FullName + ": " + $e.Message; $e = $e.InnerException }
					[Console]::Error.WriteLine($msg); exit 1
				}`).CombinedOutput()
			if err != nil {
				t.Fatalf("ConvertFrom-CIPolicy rejected the policy: %v\n%s\n--- xml ---\n%s", err, out, xml)
			}
			if st, err := os.Stat(cipPath); err != nil || st.Size() == 0 {
				t.Fatalf("no binary policy produced: %v", err)
			}
		})
	}
}
