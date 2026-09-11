// Package wdac compiles application-control rules into a Windows Defender
// Application Control (WDAC) SiPolicy XML document.
//
// Every policy is built on Microsoft's DefaultWindows baseline (see
// C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml):
// code signed as a Windows component, WHQL driver, Store app, and a few other
// Microsoft roles is always allowed, so a policy never blocks Windows itself.
// The admin's hash, path and publisher rules are added on top, for user mode
// only; kernel mode stays limited to the Microsoft baseline.
//
// The output is deterministic: rules are sorted and hashes upper-cased so
// an identical rule set always yields byte-identical XML, giving a stable
// content hash used as the policy version. A Windows-only test converts the
// output with ConvertFrom-CIPolicy to prove Windows accepts it.
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

// platformID is required by the SiPolicy schema; this is the value
// Microsoft's example policies use.
const platformID = "{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}"

type Policy struct {
	Mode  string // "audit" (default, blocks nothing) or "enforce"
	Rules []rules.Rule
}

// baselineEKUs are the certificate usages the baseline signers require.
const baselineEKUs = `    <EKU ID="ID_EKU_WINDOWS" Value="010A2B0601040182370A0306" />
    <EKU ID="ID_EKU_WHQL" Value="010A2B0601040182370A0305" />
    <EKU ID="ID_EKU_ELAM" Value="010A2B0601040182373D0401" />
    <EKU ID="ID_EKU_HAL_EXT" Value="010A2B0601040182373D0501" />
    <EKU ID="ID_EKU_RT_EXT" Value="010A2B0601040182370A0315" />
    <EKU ID="ID_EKU_STORE" Value="010A2B0601040182374C0301" />
    <EKU ID="ID_EKU_DCODEGEN" Value="010A2B0601040182374C0501" />
    <EKU ID="ID_EKU_AM" Value="010A2B0601040182374C0B01" />
`

// baselineSigner is one Microsoft signer: a well-known root (or TBS hash)
// plus the EKU it must carry. Kernel signers go in the KMCI scenario, the
// rest in UMCI.
type baselineSigner struct {
	id, name, root, eku string
	kernel              bool
}

// Wellknown roots: 04/05 = Microsoft Product Root (MD5/SHA1),
// 06 = Microsoft Product Root 2010, 07 = Microsoft Standard Root 2011,
// 0C = Microsoft DMD Root 2005, 0E = Microsoft Flighting Root 2014.
var baselineSigners = []baselineSigner{
	{"ID_SIGNER_WINDOWS_PRODUCTION", "Microsoft Product Root 2010 Windows EKU", `Type="Wellknown" Value="06"`, "ID_EKU_WINDOWS", true},
	{"ID_SIGNER_ELAM_PRODUCTION", "Microsoft Product Root 2010 ELAM EKU", `Type="Wellknown" Value="06"`, "ID_EKU_ELAM", true},
	{"ID_SIGNER_HAL_PRODUCTION", "Microsoft Product Root 2010 HAL EKU", `Type="Wellknown" Value="06"`, "ID_EKU_HAL_EXT", true},
	{"ID_SIGNER_WHQL_SHA2", "Microsoft Product Root 2010 WHQL EKU", `Type="Wellknown" Value="06"`, "ID_EKU_WHQL", true},
	{"ID_SIGNER_WHQL_SHA1", "Microsoft Product Root WHQL EKU SHA1", `Type="Wellknown" Value="05"`, "ID_EKU_WHQL", true},
	{"ID_SIGNER_WHQL_MD5", "Microsoft Product Root WHQL EKU MD5", `Type="Wellknown" Value="04"`, "ID_EKU_WHQL", true},
	{"ID_SIGNER_WINDOWS_FLIGHT_ROOT", "Microsoft Flighting Root 2014 Windows EKU", `Type="Wellknown" Value="0E"`, "ID_EKU_WINDOWS", true},
	{"ID_SIGNER_ELAM_FLIGHT", "Microsoft Flighting Root 2014 ELAM EKU", `Type="Wellknown" Value="0E"`, "ID_EKU_ELAM", true},
	{"ID_SIGNER_HAL_FLIGHT", "Microsoft Flighting Root 2014 HAL EKU", `Type="Wellknown" Value="0E"`, "ID_EKU_HAL_EXT", true},
	{"ID_SIGNER_WHQL_FLIGHT_SHA2", "Microsoft Flighting Root 2014 WHQL EKU", `Type="Wellknown" Value="0E"`, "ID_EKU_WHQL", true},

	{"ID_SIGNER_WINDOWS_PRODUCTION_USER", "Microsoft Product Root 2010 Windows EKU", `Type="Wellknown" Value="06"`, "ID_EKU_WINDOWS", false},
	{"ID_SIGNER_ELAM_PRODUCTION_USER", "Microsoft Product Root 2010 ELAM EKU", `Type="Wellknown" Value="06"`, "ID_EKU_ELAM", false},
	{"ID_SIGNER_HAL_PRODUCTION_USER", "Microsoft Product Root 2010 HAL EKU", `Type="Wellknown" Value="06"`, "ID_EKU_HAL_EXT", false},
	{"ID_SIGNER_WHQL_SHA2_USER", "Microsoft Product Root 2010 WHQL EKU", `Type="Wellknown" Value="06"`, "ID_EKU_WHQL", false},
	{"ID_SIGNER_WHQL_SHA1_USER", "Microsoft Product Root WHQL EKU SHA1", `Type="Wellknown" Value="05"`, "ID_EKU_WHQL", false},
	{"ID_SIGNER_WHQL_MD5_USER", "Microsoft Product Root WHQL EKU MD5", `Type="Wellknown" Value="04"`, "ID_EKU_WHQL", false},
	{"ID_SIGNER_WINDOWS_FLIGHT_ROOT_USER", "Microsoft Flighting Root 2014 Windows EKU", `Type="Wellknown" Value="0E"`, "ID_EKU_WINDOWS", false},
	{"ID_SIGNER_ELAM_FLIGHT_USER", "Microsoft Flighting Root 2014 ELAM EKU", `Type="Wellknown" Value="0E"`, "ID_EKU_ELAM", false},
	{"ID_SIGNER_HAL_FLIGHT_USER", "Microsoft Flighting Root 2014 HAL EKU", `Type="Wellknown" Value="0E"`, "ID_EKU_HAL_EXT", false},
	{"ID_SIGNER_WHQL_FLIGHT_SHA2_USER", "Microsoft Flighting Root 2014 WHQL EKU", `Type="Wellknown" Value="0E"`, "ID_EKU_WHQL", false},
	{"ID_SIGNER_STORE", "Microsoft MarketPlace PCA 2011", `Type="TBS" Value="FC9EDE3DCCA09186B2D3BF9B738A2050CB1A554DA2DCADB55F3F72EE17721378"`, "ID_EKU_STORE", false},
	{"ID_SIGNER_STORE_FLIGHT_ROOT", "Microsoft Flighting Root 2014 Store EKU", `Type="Wellknown" Value="0E"`, "ID_EKU_STORE", false},
	{"ID_SIGNER_RT_PRODUCTION", "Microsoft Product Root 2010 RT EKU", `Type="Wellknown" Value="06"`, "ID_EKU_RT_EXT", false},
	{"ID_SIGNER_RT_FLIGHT", "Microsoft Flighting Root 2014 RT EKU", `Type="Wellknown" Value="0E"`, "ID_EKU_RT_EXT", false},
	{"ID_SIGNER_RT_STANDARD", "Microsoft Standard Root 2011 RT EKU", `Type="Wellknown" Value="07"`, "ID_EKU_RT_EXT", false},
	{"ID_SIGNER_DRM", "Microsoft DMD Root 2005", `Type="Wellknown" Value="0C"`, "", false},
	{"ID_SIGNER_DCODEGEN", "Microsoft Product Root 2010 Dynamic Code Generation EKU", `Type="Wellknown" Value="06"`, "ID_EKU_DCODEGEN", false},
	{"ID_SIGNER_AM", "Microsoft Standard Root 2011 AntiMalware EKU", `Type="Wellknown" Value="07"`, "ID_EKU_AM", false},
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

	var signers, kernelRefs, userRefs strings.Builder
	for _, s := range baselineSigners {
		fmt.Fprintf(&signers, `    <Signer ID="%s" Name="%s">`+"\n", s.id, s.name)
		fmt.Fprintf(&signers, `      <CertRoot %s />`+"\n", s.root)
		if s.eku != "" {
			fmt.Fprintf(&signers, `      <CertEKU ID="%s" />`+"\n", s.eku)
		}
		signers.WriteString("    </Signer>\n")
		ref := fmt.Sprintf(`          <AllowedSigner SignerId="%s" />`+"\n", s.id)
		if s.kernel {
			kernelRefs.WriteString(ref)
		} else {
			userRefs.WriteString(ref)
		}
	}

	var fileRules, fileRefs strings.Builder
	id := 0
	for _, r := range rs {
		switch r.Kind {
		case rules.Hash:
			rid := fmt.Sprintf("ID_ALLOW_H_%d", id)
			fmt.Fprintf(&fileRules, `    <Allow ID="%s" FriendlyName="%s" Hash="%s" />`+"\n", rid, esc(r.Description), r.Value)
			fmt.Fprintf(&fileRefs, `          <FileRuleRef RuleID="%s" />`+"\n", rid)
		case rules.Path:
			rid := fmt.Sprintf("ID_ALLOW_P_%d", id)
			fmt.Fprintf(&fileRules, `    <Allow ID="%s" FriendlyName="%s" FilePath="%s" />`+"\n", rid, esc(r.Description), esc(r.Value))
			fmt.Fprintf(&fileRefs, `          <FileRuleRef RuleID="%s" />`+"\n", rid)
		case rules.Publisher:
			// The schema requires a letter after "ID_SIGNER_" (ID_SIGNER_[A-Z][_A-Z0-9]*).
			sid := fmt.Sprintf("ID_SIGNER_P_%d", id)
			name := r.PublisherName
			if name == "" {
				name = "Publisher"
			}
			fmt.Fprintf(&signers, `    <Signer ID="%s" Name="%s">`+"\n", sid, esc(name))
			fmt.Fprintf(&signers, `      <CertRoot Type="TBS" Value="%s" />`+"\n", r.Value)
			signers.WriteString("    </Signer>\n")
			fmt.Fprintf(&userRefs, `          <AllowedSigner SignerId="%s" />`+"\n", sid)
		}
		id++
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	b.WriteString(`<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">` + "\n")
	b.WriteString(`  <VersionEx>1.0.0.0</VersionEx>` + "\n")
	b.WriteString(`  <PolicyID>` + basePolicyGUID + `</PolicyID>` + "\n")
	b.WriteString(`  <BasePolicyID>` + basePolicyGUID + `</BasePolicyID>` + "\n")
	b.WriteString(`  <PlatformID>` + platformID + `</PlatformID>` + "\n")
	b.WriteString(`  <Rules>` + "\n")
	b.WriteString(`    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>` + "\n")
	if p.Mode != "enforce" {
		b.WriteString(`    <Rule><Option>Enabled:Audit Mode</Option></Rule>` + "\n")
	}
	b.WriteString(`    <Rule><Option>Enabled:UMCI</Option></Rule>` + "\n")
	b.WriteString(`    <Rule><Option>Enabled:Update Policy No Reboot</Option></Rule>` + "\n")
	b.WriteString(`    <Rule><Option>Enabled:Revoked Expired As Unsigned</Option></Rule>` + "\n")
	b.WriteString(`  </Rules>` + "\n")
	b.WriteString(`  <EKUs>` + "\n" + baselineEKUs + `  </EKUs>` + "\n")
	b.WriteString(`  <FileRules>` + "\n" + fileRules.String() + `  </FileRules>` + "\n")
	b.WriteString(`  <Signers>` + "\n" + signers.String() + `  </Signers>` + "\n")
	b.WriteString(`  <SigningScenarios>` + "\n")
	b.WriteString(`    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_KMCI" FriendlyName="Kernel mode">` + "\n")
	b.WriteString(`      <ProductSigners>` + "\n")
	b.WriteString(`        <AllowedSigners>` + "\n" + kernelRefs.String() + `        </AllowedSigners>` + "\n")
	b.WriteString(`      </ProductSigners>` + "\n")
	b.WriteString(`    </SigningScenario>` + "\n")
	b.WriteString(`    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI" FriendlyName="User mode">` + "\n")
	b.WriteString(`      <ProductSigners>` + "\n")
	b.WriteString(`        <AllowedSigners>` + "\n" + userRefs.String() + `        </AllowedSigners>` + "\n")
	if fileRefs.Len() > 0 {
		b.WriteString(`        <FileRulesRef>` + "\n" + fileRefs.String() + `        </FileRulesRef>` + "\n")
	}
	b.WriteString(`      </ProductSigners>` + "\n")
	b.WriteString(`    </SigningScenario>` + "\n")
	b.WriteString(`  </SigningScenarios>` + "\n")
	b.WriteString(`  <UpdatePolicySigners />` + "\n")
	// Store apps launch as Win32 apps signed by the Store certificate, so CI
	// itself must trust that signer (as in Microsoft's template).
	b.WriteString(`  <CiSigners>` + "\n" + `    <CiSigner SignerId="ID_SIGNER_STORE" />` + "\n" + `  </CiSigners>` + "\n")
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
