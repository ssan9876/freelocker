// Package wdac compiles application-control rules into a Windows Defender
// Application Control (WDAC) SiPolicy XML document.
//
// The output is deterministic: rules are sorted and hashes upper-cased so
// an identical rule set always yields byte-identical XML, giving a stable
// content hash used as the policy version. The XML aims to be accepted by
// Microsoft's ConvertFrom-CIPolicy, but Windows acceptance is verified on
// a VM, not by these package tests (see the manual-test doc).
package wdac

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"freelocker/internal/appcontrol/rules"
)

// A fixed base policy GUID identifies FreeLocker-managed policies.
const basePolicyGUID = "{A244370E-44C9-4C06-B551-F6016E563076}"

type Policy struct {
	Mode  string // "audit" (default, blocks nothing) or "enforce"
	Rules []rules.Rule
}

// Compile renders the policy to SiPolicy XML.
func Compile(p Policy) ([]byte, error) {
	rs := make([]rules.Rule, 0, len(p.Rules))
	for _, r := range p.Rules {
		n, err := rules.Normalize(r)
		if err != nil {
			return nil, err
		}
		rs = append(rs, n)
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Kind != rs[j].Kind {
			return rs[i].Kind < rs[j].Kind
		}
		return rs[i].Value < rs[j].Value
	})

	var fileRules, fileRefs, signers, signerRefs strings.Builder
	id := 0
	for _, r := range rs {
		switch r.Kind {
		case rules.Hash:
			rid := fmt.Sprintf("ID_ALLOW_H_%d", id)
			fmt.Fprintf(&fileRules, `    <Allow ID="%s" FriendlyName="%s" Hash="%s" />`+"\n", rid, esc(r.Description), r.Value)
			fmt.Fprintf(&fileRefs, `      <FileRuleRef RuleID="%s" />`+"\n", rid)
		case rules.Path:
			rid := fmt.Sprintf("ID_ALLOW_P_%d", id)
			fmt.Fprintf(&fileRules, `    <Allow ID="%s" FriendlyName="%s" FilePath="%s" />`+"\n", rid, esc(r.Description), esc(r.Value))
			fmt.Fprintf(&fileRefs, `      <FileRuleRef RuleID="%s" />`+"\n", rid)
		case rules.Publisher:
			sid := fmt.Sprintf("ID_SIGNER_%d", id)
			name := r.PublisherName
			if name == "" {
				name = "Publisher"
			}
			fmt.Fprintf(&signers, `    <Signer ID="%s" Name="%s"><CertRoot Type="TBS" Value="%s" /></Signer>`+"\n", sid, esc(name), r.Value)
			fmt.Fprintf(&signerRefs, `      <AllowedSigner SignerId="%s" />`+"\n", sid)
		}
		id++
	}

	auditOption := ""
	if p.Mode != "enforce" {
		auditOption = `    <Rule><Option>Enabled:Audit Mode</Option></Rule>` + "\n"
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	b.WriteString(`<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">` + "\n")
	b.WriteString(`  <VersionEx>1.0.0.0</VersionEx>` + "\n")
	b.WriteString(`  <PolicyID>` + basePolicyGUID + `</PolicyID>` + "\n")
	b.WriteString(`  <BasePolicyID>` + basePolicyGUID + `</BasePolicyID>` + "\n")
	b.WriteString(`  <Rules>` + "\n")
	b.WriteString(`    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>` + "\n")
	b.WriteString(`    <Rule><Option>Enabled:UMCI</Option></Rule>` + "\n")
	b.WriteString(auditOption)
	b.WriteString(`  </Rules>` + "\n")
	b.WriteString(`  <EKUs />` + "\n")
	b.WriteString(`  <FileRules>` + "\n")
	b.WriteString(fileRules.String())
	b.WriteString(`  </FileRules>` + "\n")
	b.WriteString(`  <Signers>` + "\n")
	b.WriteString(signers.String())
	b.WriteString(`  </Signers>` + "\n")
	b.WriteString(`  <SigningScenarios>` + "\n")
	b.WriteString(`    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI" FriendlyName="User mode">` + "\n")
	b.WriteString(`      <ProductSigners>` + "\n")
	b.WriteString(`        <AllowedSigners>` + "\n")
	b.WriteString(indent(signerRefs.String(), "  "))
	b.WriteString(`        </AllowedSigners>` + "\n")
	b.WriteString(`        <FileRulesRef>` + "\n")
	b.WriteString(indent(fileRefs.String(), "  "))
	b.WriteString(`        </FileRulesRef>` + "\n")
	b.WriteString(`      </ProductSigners>` + "\n")
	b.WriteString(`    </SigningScenario>` + "\n")
	b.WriteString(`  </SigningScenarios>` + "\n")
	b.WriteString(`  <UpdatePolicySigners />` + "\n")
	b.WriteString(`  <CiSigners />` + "\n")
	b.WriteString(`  <HvciOptions>0</HvciOptions>` + "\n")
	b.WriteString(`</SiPolicy>` + "\n")
	return []byte(b.String()), nil
}

// ContentHash is the SHA-256 (hex) of the compiled XML; used as the version.
func ContentHash(xml []byte) string {
	sum := sha256.Sum256(xml)
	return hex.EncodeToString(sum[:])
}

func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func indent(s, pad string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n") + "\n"
}
