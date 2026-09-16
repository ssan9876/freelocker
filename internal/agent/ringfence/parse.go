package ringfence

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type evtData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type evt struct {
	EventID     int   `xml:"System>EventID"`
	RecordID    int64 `xml:"System>EventRecordID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"System>TimeCreated"`
	Data []evtData `xml:"EventData>Data"`
}

type evtList struct {
	Events []evt `xml:"Event"`
}

func (e evt) field(name string) string {
	for _, d := range e.Data {
		if d.Name == name {
			return strings.TrimSpace(d.Value)
		}
	}
	return ""
}

// parseEvents tolerates both a wrapped <Events> document and the bare
// concatenated <Event> elements wevtutil emits without /e.
func parseEvents(raw []byte) ([]evt, error) {
	var l evtList
	if err := xml.Unmarshal(raw, &l); err == nil && len(l.Events) > 0 {
		return l.Events, nil
	}
	wrapped := append(append([]byte("<Events>"), raw...), []byte("</Events>")...)
	if err := xml.Unmarshal(wrapped, &l); err != nil {
		return nil, fmt.Errorf("parse event xml: %w", err)
	}
	return l.Events, nil
}

// eventTime parses the SystemTime attribute of <TimeCreated>, which Windows
// event XML always renders in RFC3339-with-fractional-seconds form. A
// missing or unparseable value falls back to time.Now rather than failing
// the whole batch — a timestamp we cannot trust is still better reported
// approximately than dropped.
func eventTime(raw string) time.Time {
	if raw == "" {
		return time.Now()
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	return time.Now()
}

// EventQuery builds the wevtutil XPath filter for one or more event IDs,
// optionally bounded to records newer than a watermark. afterRecordID <= 0
// means no lower bound — the first run against a source, which is
// deliberately NOT "replay the whole log": the caller still bounds the
// query with /c:N, so this only ever returns the most recent batch.
func EventQuery(eventIDs []int, afterRecordID int64) string {
	parts := make([]string, len(eventIDs))
	for i, id := range eventIDs {
		parts[i] = fmt.Sprintf("EventID=%d", id)
	}
	idExpr := strings.Join(parts, " or ")
	if afterRecordID > 0 {
		return fmt.Sprintf("*[System[(%s) and (EventRecordID>%d)]]", idExpr, afterRecordID)
	}
	return fmt.Sprintf("*[System[(%s)]]", idExpr)
}

// MaxRecordID returns the highest EventRecordID among all events in raw,
// regardless of whether ParseWFP/ParseDefenderASR keep or drop them — the
// watermark must advance past events dropped for not matching a ringfenced
// program too, or they would be re-fetched on every tick forever.
func MaxRecordID(raw []byte) (int64, error) {
	evts, err := parseEvents(raw)
	if err != nil {
		return 0, err
	}
	var max int64
	for _, e := range evts {
		if e.RecordID > max {
			max = e.RecordID
		}
	}
	return max, nil
}

var devicePath = regexp.MustCompile(`^\\device\\harddiskvolume\d+`)

// normalisePath turns the \device\harddiskvolumeN\... form that WFP events
// use into a comparable lower-case path. The volume number cannot be mapped
// to a drive letter without more work, so the leading segment is dropped and
// matching is done on the remainder.
func normalisePath(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	return devicePath.ReplaceAllString(p, "")
}

// ParseWFP extracts network violations for ringfenced programs only. Keys of
// `ringfenced` must be lower-case full paths; matching normalises both the
// event's \device\harddiskvolumeN\... path and the ringfence entry's C:\...
// path and requires an exact match — a path suffix match would misattribute
// an unrelated program's connections to a ringfenced entry. Enforced is
// derived per-event from the EventID: 5157 is a block, 5156 is an
// audit-mode observation.
func ParseWFP(raw []byte, ringfenced map[string]bool) ([]Violation, error) {
	evts, err := parseEvents(raw)
	if err != nil {
		return nil, err
	}
	var out []Violation
	for _, e := range evts {
		if e.EventID != 5156 && e.EventID != 5157 {
			continue
		}
		app := normalisePath(e.field("Application"))
		matched := ""
		for want := range ringfenced {
			tail := normalisePath(want)
			if i := strings.Index(tail, ":"); i == 1 { // strip "c:"
				tail = tail[2:]
			}
			if app == tail {
				matched = want
				break
			}
		}
		if matched == "" {
			continue // not ringfenced: drop before it reaches the server
		}
		out = append(out, Violation{
			Kind:     "network",
			Program:  matched,
			Detail:   e.field("DestAddress") + ":" + e.field("DestPort"),
			Enforced: e.EventID == 5157,
			At:       eventTime(e.TimeCreated.SystemTime),
		})
	}
	return out, nil
}

// ParseDefenderASR extracts child-process violations. 1121 is a block, 1122
// is an audit-mode detection.
func ParseDefenderASR(raw []byte) ([]Violation, error) {
	evts, err := parseEvents(raw)
	if err != nil {
		return nil, err
	}
	var out []Violation
	for _, e := range evts {
		if e.EventID != 1121 && e.EventID != 1122 {
			continue
		}
		out = append(out, Violation{
			Kind:     "child_process",
			Program:  e.field("Path"),
			Detail:   "ASR " + e.field("ID") + ": " + e.field("ProcessName"),
			Enforced: e.EventID == 1121,
			At:       eventTime(e.TimeCreated.SystemTime),
		})
	}
	return out, nil
}

// Dedupe collapses repeats of the same (kind, program, detail) and caps the
// batch. 5156 fires for every outbound connection on the machine, so without
// this an audit-mode ringfence floods the tenant's event table.
func Dedupe(v []Violation, cap int) []Violation {
	seen := make(map[string]bool, len(v))
	out := make([]Violation, 0, len(v))
	for _, x := range v {
		k := x.Kind + "|" + x.Program + "|" + x.Detail
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, x)
		if len(out) == cap {
			break
		}
	}
	return out
}
