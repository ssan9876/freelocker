package motw

import "testing"

func TestParseBrowserMark(t *testing.T) {
	// What Edge and Chrome actually write.
	raw := []byte("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/downloads\r\nHostUrl=https://cdn.example.com/setup.exe\r\n")
	got := Parse(raw)

	if !got.Present || got.ZoneID != ZoneInternet {
		t.Fatalf("got %+v, want present with zone 3", got)
	}
	if !got.Downloaded() {
		t.Error("a zone 3 file must count as downloaded")
	}
	if got.HostURL != "https://cdn.example.com/setup.exe" {
		t.Errorf("HostURL = %q", got.HostURL)
	}
	// HostUrl wins over ReferrerUrl: it is where the bytes actually came from.
	if got.Source() != "https://cdn.example.com/setup.exe" {
		t.Errorf("Source() = %q, want the host url", got.Source())
	}
}

// A file from a corporate share carries a mark, but calling it "downloaded"
// would flood the console with internal software an admin does not mean.
func TestIntranetIsNotDownloaded(t *testing.T) {
	for _, zone := range []int{ZoneLocalMachine, ZoneIntranet, ZoneTrusted} {
		got := Parse([]byte("[ZoneTransfer]\nZoneId=" + string(rune('0'+zone)) + "\n"))
		if got.Downloaded() {
			t.Errorf("zone %d counted as downloaded", zone)
		}
		if !got.Present {
			t.Errorf("zone %d should still be Present", zone)
		}
	}
}

func TestRestrictedZoneIsDownloaded(t *testing.T) {
	if !Parse([]byte("[ZoneTransfer]\nZoneId=4\n")).Downloaded() {
		t.Error("zone 4 (restricted) must count as downloaded")
	}
}

// The stream is written by many tools; a partial one must degrade to
// "present, unknown" rather than break the scan of a whole machine.
func TestParseTolerant(t *testing.T) {
	for _, raw := range []string{
		"",
		"[ZoneTransfer]",
		"[ZoneTransfer]\nZoneId=notanumber\n",
		"garbage without any equals sign\n",
		"[ZoneTransfer]\n; a comment\nZoneId = 3 \n",
	} {
		got := Parse([]byte(raw))
		if !got.Present {
			t.Errorf("Parse(%q).Present = false; any stream at all means present", raw)
		}
	}
	// Whitespace around the key and value is tolerated, so this one still
	// resolves to a real zone.
	if z := Parse([]byte("[ZoneTransfer]\nZoneId = 3 \n")).ZoneID; z != 3 {
		t.Errorf("padded ZoneId parsed as %d, want 3", z)
	}
	// An unparseable zone must NOT silently become zone 0 "local machine"
	// in a way that reads as a deliberate trust decision... it does default
	// to 0, so Downloaded() is false. Pin that: absence of evidence is not
	// evidence of safety, but it is also not grounds to flag the file.
	if Parse([]byte("[ZoneTransfer]\nZoneId=notanumber\n")).Downloaded() {
		t.Error("an unparseable zone must not be reported as downloaded")
	}
}

func TestSourceFallsBackToReferrer(t *testing.T) {
	got := Parse([]byte("[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://example.com/page\n"))
	if got.Source() != "https://example.com/page" {
		t.Errorf("Source() = %q, want the referrer when there is no host url", got.Source())
	}
	if Parse([]byte("[ZoneTransfer]\nZoneId=3\n")).Source() != "" {
		t.Error("Source() should be empty when the mark carries no origin")
	}
}
