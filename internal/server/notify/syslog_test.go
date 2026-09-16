package notify

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testEvent() Event {
	return Event{
		Kind:     "alert.raised",
		TenantID: uuid.MustParse("11111111-2222-3333-4444-555555555555"),
		Title:    "Disk nearly full on WS-01",
		Body:     "disk_pct is 94, threshold 90",
		Detail:   map[string]any{"device": "WS-01", "value": 94},
		At:       time.Date(2026, 9, 15, 12, 34, 56, 0, time.UTC),
	}
}

// udpSink listens on loopback and returns the address plus a channel of
// received datagrams. A real socket, not a fake: the framing and the
// datagram boundary are exactly what a syslog sender gets wrong.
func udpSink(t *testing.T) (string, <-chan string) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	out := make(chan string, 4)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			out <- string(buf[:n])
		}
	}()
	return conn.LocalAddr().String(), out
}

// cefSplit splits a CEF header on unescaped pipes. strings.Split cannot do
// this: it would treat the escaped \| inside a field as a delimiter, which
// is precisely the confusion the escaping exists to prevent — so a naive
// split makes a correctly-escaped message look broken.
func cefSplit(s string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			cur.WriteRune(r)
			esc = true
		case r == '|':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	out = append(out, cur.String())
	return out
}

func TestSyslogRFC5424OverUDP(t *testing.T) {
	addr, msgs := udpSink(t)

	if err := sendSyslog(context.Background(), "udp://"+addr, testEvent()); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-msgs:
		// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...
		if !strings.HasPrefix(got, "<") {
			t.Fatalf("message does not start with a priority: %q", got)
		}
		// Facility 13 (log audit) severity 4 (warning) = 13*8+4 = 108.
		if !strings.HasPrefix(got, "<108>1 ") {
			t.Errorf("prefix = %.10q, want <108>1 for an alert.raised", got)
		}
		if !strings.Contains(got, "2026-09-15T12:34:56") {
			t.Errorf("message lacks the event timestamp: %q", got)
		}
		if !strings.Contains(got, "freelocker") {
			t.Errorf("message lacks the app name: %q", got)
		}
		if !strings.Contains(got, "Disk nearly full on WS-01") {
			t.Errorf("message lacks the title: %q", got)
		}
		// The tenant has to be present or a multi-tenant SIEM feed is
		// unattributable.
		if !strings.Contains(got, "11111111-2222-3333-4444-555555555555") {
			t.Errorf("message lacks the tenant id: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no syslog datagram received")
	}
}

// Severity must track the event, or every alert looks equally urgent in the
// SIEM and the priority field carries no information.
func TestSyslogSeverityVariesByEvent(t *testing.T) {
	addr, msgs := udpSink(t)

	for _, tc := range []struct{ kind, wantPrefix string }{
		{"alert.raised", "<108>"},        // warning
		{"alert.resolved", "<110>"},      // informational
		{"approval.new", "<109>"},        // notice
		{"rollout.auto_paused", "<108>"}, // warning
		{"rollout.completed", "<110>"},   // informational
	} {
		e := testEvent()
		e.Kind = tc.kind
		if err := sendSyslog(context.Background(), "udp://"+addr, e); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-msgs:
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("%s prefix = %.8q, want %s", tc.kind, got, tc.wantPrefix)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no datagram", tc.kind)
		}
	}
}

func TestSyslogCEFFormat(t *testing.T) {
	addr, msgs := udpSink(t)

	if err := sendSyslog(context.Background(), "udp://"+addr+"?format=cef", testEvent()); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-msgs:
		i := strings.Index(got, "CEF:0|")
		if i < 0 {
			t.Fatalf("not a CEF message: %q", got)
		}
		// CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
		parts := cefSplit(got[i:])
		if len(parts) < 8 {
			t.Fatalf("CEF header has %d segments, want at least 8: %q", len(parts), got)
		}
		if parts[1] != "FreeLocker" || parts[2] != "FreeLocker" {
			t.Errorf("vendor/product = %q/%q", parts[1], parts[2])
		}
		if parts[4] != "alert.raised" {
			t.Errorf("signature id = %q, want the event kind", parts[4])
		}
		if parts[5] != "Disk nearly full on WS-01" {
			t.Errorf("name = %q, want the title", parts[5])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no syslog datagram received")
	}
}

// CEF uses | as its header delimiter, so a title containing one would forge
// extra header fields and shift every column after it. Escaping is the whole
// correctness story of this format.
func TestSyslogCEFEscapesDelimiters(t *testing.T) {
	addr, msgs := udpSink(t)

	e := testEvent()
	e.Title = `weird|title with \ backslash`
	e.Detail = map[string]any{"path": `C:\Program Files\app.exe`, "note": "a=b"}

	if err := sendSyslog(context.Background(), "udp://"+addr+"?format=cef", e); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-msgs:
		i := strings.Index(got, "CEF:0|")
		parts := cefSplit(got[i:])
		// The escaped pipe must NOT create a new header segment: with a raw
		// pipe the name field would split and severity would shift.
		if len(parts) < 8 {
			t.Fatalf("CEF header collapsed: %q", got)
		}
		if !strings.Contains(parts[5], `weird\|title`) {
			t.Errorf("name = %q, want the pipe escaped as \\|", parts[5])
		}
		// In the extension, = separates keys from values and must be escaped.
		if !strings.Contains(got, `a\=b`) {
			t.Errorf("extension does not escape '=': %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no syslog datagram received")
	}
}

// TCP syslog is newline-framed here (RFC 6587 non-transparent framing), which
// is what rsyslog, syslog-ng and Splunk accept by default.
func TestSyslogOverTCPIsNewlineFramed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	lines := make(chan string, 2)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, err := bufio.NewReader(c).ReadString('\n')
		if err == nil {
			lines <- line
		}
	}()

	if err := sendSyslog(context.Background(), "tcp://"+ln.Addr().String(), testEvent()); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-lines:
		if !strings.HasSuffix(got, "\n") {
			t.Error("TCP syslog message is not newline-terminated")
		}
		if !strings.Contains(got, "Disk nearly full") {
			t.Errorf("unexpected message: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no TCP syslog message received")
	}
}

// A message must never contain an embedded newline in RFC 5424 mode: a
// receiver framing on newlines would read the tail as a separate, malformed
// record — an easy way to forge log entries through any field an attacker
// influences, such as a file path.
func TestSyslogStripsEmbeddedNewlines(t *testing.T) {
	addr, msgs := udpSink(t)

	e := testEvent()
	e.Title = "line one\nline two"
	e.Body = "body\r\nsecond"

	if err := sendSyslog(context.Background(), "udp://"+addr, e); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-msgs:
		if strings.ContainsAny(strings.TrimSuffix(got, "\n"), "\n\r") {
			t.Errorf("message contains an embedded newline: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no syslog datagram received")
	}
}

func TestSyslogRejectsBadURL(t *testing.T) {
	for _, u := range []string{"http://example.com", "notaurl", "udp://"} {
		if err := sendSyslog(context.Background(), u, testEvent()); err == nil {
			t.Errorf("sendSyslog(%q) = nil, want an error", u)
		}
	}
}
