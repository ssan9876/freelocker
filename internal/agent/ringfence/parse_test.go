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
	got, err := ParseWFP(raw, ringfenced, false)
	if err != nil {
		t.Fatal(err)
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
	got, err := ParseWFP(raw, map[string]bool{`c:\program files\app\app.exe`: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1 — device-path normalisation failed", len(got))
	}
	if got[0].Detail != "203.0.113.5:443" || !got[0].Enforced {
		t.Errorf("violation = %+v", got[0])
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
