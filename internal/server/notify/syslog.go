package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Syslog forwarding for SIEM ingestion. Two wire formats are supported:
// RFC 5424 (the default, what rsyslog and syslog-ng speak natively) and CEF
// (what ArcSight-lineage tools and several Splunk add-ons expect).
//
// The transport and format come from the channel URL, which keeps syslog on
// the existing channel model with no schema change:
//
//	udp://siem.example.com:514
//	tcp://siem.example.com:514?format=cef
//
// TCP is newline-framed (RFC 6587 non-transparent framing), which is what
// rsyslog, syslog-ng and Splunk accept without extra configuration.

// syslogFacility 13 is "log audit" — the closest standard facility for
// security-relevant administrative events, and it keeps FreeLocker's records
// out of the general application stream a SIEM already filters heavily.
const syslogFacility = 13

const syslogAppName = "freelocker"

// syslogTimeout bounds a single send. A SIEM that has stopped reading must
// not wedge the notification worker; the outbox will retry.
const syslogTimeout = 5 * time.Second

// severityFor maps an event to an RFC 5424 severity. A feed where everything
// is the same severity cannot be triaged, which is most of the value of
// sending it to a SIEM at all.
func severityFor(kind string) int {
	switch kind {
	case "alert.raised", "rollout.auto_paused":
		return 4 // warning
	case "approval.new":
		return 5 // notice
	case "alert.resolved", "rollout.completed":
		return 6 // informational
	default:
		return 6
	}
}

// scrub removes CR and LF. A receiver that frames on newlines would read
// anything after one as a separate record, so a field an attacker can
// influence — a file path, a hostname — would let them forge log entries.
// This is the log-injection guard, not cosmetic.
func scrub(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// cefEscapeHeader escapes the CEF header delimiters. An unescaped pipe in a
// title would forge an extra header field and shift severity and every
// column after it.
func cefEscapeHeader(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(scrub(s))
}

// cefEscapeValue escapes an extension value, where "=" separates keys from
// values and so must not appear raw.
func cefEscapeValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`).Replace(scrub(s))
}

func formatRFC5424(e Event, hostname string) string {
	pri := syslogFacility*8 + severityFor(e.Kind)
	ts := e.At.UTC().Format(time.RFC3339)

	detail := ""
	if len(e.Detail) > 0 {
		if b, err := json.Marshal(e.Detail); err == nil {
			detail = " " + string(b)
		}
	}
	msg := scrub(e.Title)
	if e.Body != "" {
		msg += " — " + scrub(e.Body)
	}
	msg += scrub(detail)

	// STRUCTURED-DATA carries the tenant so a multi-tenant feed stays
	// attributable even after the message text is reformatted downstream.
	sd := fmt.Sprintf(`[freelocker@0 tenant="%s" event="%s"]`, e.TenantID, scrub(e.Kind))

	return fmt.Sprintf("<%d>1 %s %s %s %d %s %s %s",
		pri, ts, hostname, syslogAppName, os.Getpid(), scrub(e.Kind), sd, msg)
}

func formatCEF(e Event, hostname string) string {
	pri := syslogFacility*8 + severityFor(e.Kind)
	ts := e.At.UTC().Format(time.RFC3339)

	// CEF severity is 0-10, inverted relative to syslog's 0-7 where lower is
	// more urgent.
	sev := 3
	switch severityFor(e.Kind) {
	case 4:
		sev = 6
	case 5:
		sev = 4
	}

	ext := []string{
		"rt=" + cefEscapeValue(ts),
		"msg=" + cefEscapeValue(e.Body),
		"cs1Label=tenant",
		"cs1=" + cefEscapeValue(e.TenantID.String()),
	}
	// Sorted so the extension is stable across sends, which makes SIEM-side
	// field extraction and these tests deterministic.
	keys := make([]string, 0, len(e.Detail))
	for k := range e.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ext = append(ext, cefEscapeValue(k)+"="+cefEscapeValue(fmt.Sprint(e.Detail[k])))
	}

	header := fmt.Sprintf("CEF:0|FreeLocker|FreeLocker|1|%s|%s|%d|",
		cefEscapeHeader(e.Kind), cefEscapeHeader(e.Title), sev)

	// CEF is carried inside a syslog frame, so it keeps the priority prefix.
	return fmt.Sprintf("<%d>%s %s %s %s%s",
		pri, ts, hostname, syslogAppName, header, strings.Join(ext, " "))
}

// sendSyslog delivers one event to a syslog collector.
//
// Returns permanentError for a URL that can never work, so the outbox stops
// retrying a misconfigured channel instead of burning attempts on it; a
// network failure returns an ordinary error and is retried.
func sendSyslog(ctx context.Context, rawURL string, e Event) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return permanentError{"syslog url is not a url: " + err.Error()}
	}
	network := u.Scheme
	if network != "udp" && network != "tcp" {
		return permanentError{"syslog url scheme must be udp or tcp, got " + u.Scheme}
	}
	if u.Host == "" {
		return permanentError{"syslog url has no host"}
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "-"
	}
	hostname = scrub(hostname)

	var msg string
	switch f := strings.ToLower(u.Query().Get("format")); f {
	case "", "rfc5424":
		msg = formatRFC5424(e, hostname)
	case "cef":
		msg = formatCEF(e, hostname)
	default:
		return permanentError{"unknown syslog format " + f}
	}

	d := net.Dialer{Timeout: syslogTimeout}
	conn, err := d.DialContext(ctx, network, u.Host)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(syslogTimeout))
	if network == "tcp" {
		msg += "\n"
	}
	_, err = conn.Write([]byte(msg))
	return err
}
