package events

import (
	"strings"
	"testing"
)

const sample = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4688</EventID><TimeCreated SystemTime="2026-09-11T18:00:00.000000000Z"/></System>
  <EventData>
    <Data Name="SubjectUserName">bob</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4624</EventID><TimeCreated SystemTime="2026-09-11T18:01:00.000000000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="LogonType">2</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4634</EventID><TimeCreated SystemTime="2026-09-11T18:02:00Z"/></System>
  <EventData></EventData>
</Event>`

func TestParseSecurity(t *testing.T) {
	evs, err := ParseSecurity([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("got %d events, want 2 (4634 ignored)", len(evs))
	}
	if evs[0].Kind != "process_launch" || evs[0].Summary != `bob launched C:\Windows\System32\cmd.exe` {
		t.Errorf("process event = %+v", evs[0])
	}
	if evs[1].Kind != "logon" || evs[1].Summary != "alice logged on (type 2)" {
		t.Errorf("logon event = %+v", evs[1])
	}
	if evs[0].At.IsZero() {
		t.Error("timestamp not parsed")
	}
}

// 4688 carries TokenElevationType. %%1937 (TokenElevationTypeFull) means the
// process got a full administrator token — the thing an admin means by "that
// app asked for system-level credentials". Reporting it as an ordinary
// process launch buries the one event worth looking at among thousands.
func TestParseSecurityFlagsElevatedLaunch(t *testing.T) {
	raw := []byte(`<Event><System><EventID>4688</EventID>` +
		`<TimeCreated SystemTime="2026-09-15T18:00:00.000000000Z"/></System><EventData>` +
		`<Data Name="SubjectUserName">alice</Data>` +
		`<Data Name="NewProcessName">C:\Users\alice\Downloads\setup.exe</Data>` +
		`<Data Name="TokenElevationType">%%1937</Data>` +
		`</EventData></Event>`)

	got, err := ParseSecurity(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Kind != "elevation" {
		t.Errorf("kind = %q, want elevation", got[0].Kind)
	}
	if !strings.Contains(got[0].Summary, "setup.exe") || !strings.Contains(got[0].Summary, "alice") {
		t.Errorf("summary = %q, want the user and the image", got[0].Summary)
	}
	if !strings.Contains(strings.ToLower(got[0].Summary), "elevated") {
		t.Errorf("summary = %q, want it to say the launch was elevated", got[0].Summary)
	}
}

// A limited or default token is an ordinary launch. Treating every 4688 as
// an elevation would make the feed meaningless.
func TestParseSecurityOrdinaryLaunchIsNotElevation(t *testing.T) {
	for _, tok := range []string{"%%1936", "%%1938", ""} {
		raw := []byte(`<Event><System><EventID>4688</EventID>` +
			`<TimeCreated SystemTime="2026-09-15T18:00:00.000000000Z"/></System><EventData>` +
			`<Data Name="SubjectUserName">alice</Data>` +
			`<Data Name="NewProcessName">C:\Windows\System32\notepad.exe</Data>` +
			`<Data Name="TokenElevationType">` + tok + `</Data>` +
			`</EventData></Event>`)
		got, err := ParseSecurity(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("token %q: got %d events, want 1", tok, len(got))
		}
		if got[0].Kind != "process_launch" {
			t.Errorf("token %q: kind = %q, want process_launch", tok, got[0].Kind)
		}
	}
}
