package ringfence

import (
	"os"
	"strings"
	"testing"
	"time"
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

func TestParseWFPUsesRealEventTimestamp(t *testing.T) {
	// The fixture's first event carries TimeCreated SystemTime=
	// "2026-09-15T14:02:11.1234567Z" — the violation must carry that, not
	// wall-clock now, so the server can deduplicate/bookmark on it.
	raw, err := os.ReadFile("testdata/wfp_5156.xml")
	if err != nil {
		t.Fatal(err)
	}
	ringfenced := map[string]bool{`c:\program files\app\app.exe`: true}
	got, err := ParseWFP(raw, ringfenced)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1", len(got))
	}
	want, err := time.Parse(time.RFC3339Nano, "2026-09-15T14:02:11.1234567Z")
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].At.Equal(want) {
		t.Errorf("At = %v, want the event's real TimeCreated %v (not time.Now)", got[0].At, want)
	}
}

func TestParseWFPFallsBackToNowWhenTimestampMissing(t *testing.T) {
	before := time.Now()
	raw := []byte(`<Events><Event><System><EventID>5156</EventID></System><EventData>` +
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
	after := time.Now()
	if got[0].At.Before(before) || got[0].At.After(after) {
		t.Errorf("At = %v, want a fallback to time.Now() in [%v, %v] when TimeCreated is absent", got[0].At, before, after)
	}
}

func TestEventQueryNoWatermarkOnFirstRun(t *testing.T) {
	got := EventQuery([]int{5157}, 0)
	want := "*[System[(EventID=5157)]]"
	if got != want {
		t.Errorf("EventQuery(no watermark) = %q, want %q", got, want)
	}
}

func TestEventQueryWithWatermarkFiltersByRecordID(t *testing.T) {
	got := EventQuery([]int{1121, 1122}, 918273)
	want := "*[System[(EventID=1121 or EventID=1122) and (EventRecordID>918273)]]"
	if got != want {
		t.Errorf("EventQuery(watermark) = %q, want %q", got, want)
	}
}

func TestMaxRecordIDAdvancesPastDroppedEvents(t *testing.T) {
	// Both events in the fixture are 5156 events, but only app.exe is
	// ringfenced; chrome.exe is dropped by ParseWFP. MaxRecordID must still
	// report the record id of the chrome.exe event (918290) or the watermark
	// would never advance past events for programs outside the ringfence.
	raw, err := os.ReadFile("testdata/wfp_5156.xml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := MaxRecordID(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != 918290 {
		t.Errorf("MaxRecordID = %d, want 918290 (the higher of the two fixture events, including the dropped one)", got)
	}
}

func TestStaleASRValuesOnlyDeletesCuratedGUIDsNoLongerWanted(t *testing.T) {
	// A GPO/Intune-managed GUID outside the curated set must survive even
	// though it is not in `want` — this is the FINDING 1 regression: the old
	// code deleted every value name under the key, wiping org-wide policy.
	const curatedNoLongerWanted = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
	const curatedStillWanted = "3B576869-A4EC-4529-8536-B80A7769E899"
	const gpoManagedUnrelated = "26190899-1602-49E8-8B27-EB1D0A1CE869" // not in CuratedASRRules
	present := []string{curatedNoLongerWanted, curatedStillWanted, gpoManagedUnrelated}
	want := map[string]string{curatedStillWanted: "block"}

	got := StaleASRValues(present, want)
	if len(got) != 1 || got[0] != curatedNoLongerWanted {
		t.Fatalf("StaleASRValues = %v, want exactly [%s]", got, curatedNoLongerWanted)
	}
}

func TestStaleASRValuesIsCaseInsensitive(t *testing.T) {
	lower := "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
	got := StaleASRValues([]string{lower}, map[string]string{})
	if len(got) != 1 || got[0] != lower {
		t.Fatalf("StaleASRValues(lower-case curated GUID) = %v, want it flagged stale (case-insensitive match)", got)
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
