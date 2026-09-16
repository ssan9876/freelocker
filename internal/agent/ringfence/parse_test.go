package ringfence

import (
	"os"
	"strings"
	"testing"
)

func TestParseWFPKeepsOnlyRingfencedPrograms(t *testing.T) {
	raw, err := os.ReadFile("testdata/wfp_5156.xml")
	if err != nil {
		t.Fatal(err)
	}
	// Only app.exe is ringfenced; everything else on the box must be dropped
	// before it ever reaches the server.
	ringfenced := map[string]bool{`c:\program files\app\app.exe`: true}
	got, err := ParseWFP(raw, ringfenced)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture contains one event for the ringfenced app.exe and one for
	// an unrelated chrome.exe. Pinning the count proves both that the
	// ringfenced program was kept AND that the unrelated one was dropped —
	// without this, an empty result would pass the loop below vacuously.
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1", len(got))
	}
	for _, v := range got {
		if !ringfenced[strings.ToLower(v.Program)] {
			t.Errorf("parser leaked a non-ringfenced program: %+v", v)
		}
		if v.Kind != "network" || v.Enforced {
			t.Errorf("violation = %+v, want kind network and enforced false", v)
		}
		if v.Detail == "" {
			t.Error("a network violation must carry the remote endpoint")
		}
	}
}

func TestParseWFPNormalisesDevicePaths(t *testing.T) {
	// 5156 reports \device\harddiskvolumeN\... — the ringfence set holds
	// C:\... paths, so matching requires normalisation or every event is
	// silently dropped.
	raw := []byte(`<Events><Event><System><EventID>5156</EventID></System><EventData>` +
		`<Data Name="Application">\device\harddiskvolume3\program files\app\app.exe</Data>` +
		`<Data Name="DestAddress">203.0.113.5</Data><Data Name="DestPort">443</Data>` +
		`</EventData></Event></Events>`)
	got, err := ParseWFP(raw, map[string]bool{`c:\program files\app\app.exe`: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1 — device-path normalisation failed", len(got))
	}
	// 5156 is a connection ALLOWED / audit-mode observation, not a block.
	if got[0].Detail != "203.0.113.5:443" || got[0].Enforced {
		t.Errorf("violation = %+v, want Enforced false for a 5156 event", got[0])
	}
}

func TestParseWFPBlockedConnectionIsEnforced(t *testing.T) {
	// 5157 is a connection BLOCKED event, so it must be labelled enforced.
	// Pinned alongside TestParseWFPNormalisesDevicePaths so both directions
	// of the 5156/5157 -> Enforced mapping are covered.
	raw := []byte(`<Events><Event><System><EventID>5157</EventID></System><EventData>` +
		`<Data Name="Application">\device\harddiskvolume3\program files\app\app.exe</Data>` +
		`<Data Name="DestAddress">203.0.113.5</Data><Data Name="DestPort">443</Data>` +
		`</EventData></Event></Events>`)
	got, err := ParseWFP(raw, map[string]bool{`c:\program files\app\app.exe`: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1", len(got))
	}
	if !got[0].Enforced {
		t.Errorf("violation = %+v, want Enforced true for a 5157 event", got[0])
	}
}

func TestParseWFPRejectsSuffixOnlyMatch(t *testing.T) {
	// Regression for the too-loose suffix match: an unrelated program whose
	// path happens to end with the same tail as a ringfence entry must NOT
	// be misattributed to that entry.
	raw := []byte(`<Events><Event><System><EventID>5156</EventID></System><EventData>` +
		`<Data Name="Application">\device\harddiskvolume3\evil\app\app.exe</Data>` +
		`<Data Name="DestAddress">198.51.100.9</Data><Data Name="DestPort">443</Data>` +
		`</EventData></Event></Events>`)
	got, err := ParseWFP(raw, map[string]bool{`c:\app\app.exe`: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d violations, want 0 — suffix-only match misattributed an unrelated program: %+v", len(got), got)
	}
}

func TestParseDefenderASR(t *testing.T) {
	raw, err := os.ReadFile("testdata/defender_1121.xml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDefenderASR(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no ASR violations parsed")
	}
	if got[0].Kind != "child_process" || !got[0].Enforced {
		t.Errorf("1121 is a block: %+v", got[0])
	}
}

func TestDedupeCollapsesRepeatsAndCaps(t *testing.T) {
	v := []Violation{
		{Kind: "network", Program: `C:\a.exe`, Detail: "1.2.3.4:443"},
		{Kind: "network", Program: `C:\a.exe`, Detail: "1.2.3.4:443"},
		{Kind: "network", Program: `C:\a.exe`, Detail: "5.6.7.8:443"},
	}
	if got := Dedupe(v, 10); len(got) != 2 {
		t.Errorf("dedupe = %d, want 2 distinct endpoints", len(got))
	}
	if got := Dedupe(v, 1); len(got) != 1 {
		t.Errorf("cap ignored: %d", len(got))
	}
}
