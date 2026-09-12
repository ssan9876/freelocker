package events

import "testing"

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
