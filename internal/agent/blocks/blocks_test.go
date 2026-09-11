package blocks

import "testing"

const sample = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>3077</EventID>
    <TimeCreated SystemTime="2026-09-10T18:00:00.000000000Z"/>
  </System>
  <EventData>
    <Data Name="File Name">\Device\HarddiskVolume3\Users\bob\evil.exe</Data>
    <Data Name="SHA256 Hash">abc123</Data>
    <Data Name="Publisher">Unknown</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>3076</EventID>
    <TimeCreated SystemTime="2026-09-10T18:01:00.000000000Z"/>
  </System>
  <EventData>
    <Data Name="File Name">C:\tools\audit-me.exe</Data>
    <Data Name="SHA256 Hash">def456</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>3099</EventID><TimeCreated SystemTime="2026-09-10T18:02:00Z"/></System>
  <EventData></EventData>
</Event>`

func TestParseCodeIntegrity(t *testing.T) {
	evs, err := ParseCodeIntegrity([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("expected 2 block/audit events, got %d", len(evs))
	}
	if !evs[0].Blocked {
		t.Error("3077 must be an enforced block")
	}
	if evs[0].SHA256 != "ABC123" {
		t.Errorf("hash upper-cased: %q", evs[0].SHA256)
	}
	if evs[0].Path != `\Users\bob\evil.exe` {
		t.Errorf("device prefix not stripped: %q", evs[0].Path)
	}
	if evs[1].Blocked {
		t.Error("3076 must be audit-only (not blocked)")
	}
	if evs[1].Path != `C:\tools\audit-me.exe` {
		t.Errorf("plain path changed: %q", evs[1].Path)
	}
	if evs[0].At.IsZero() {
		t.Error("timestamp not parsed")
	}
}
