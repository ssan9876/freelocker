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
	EventID int       `xml:"System>EventID"`
	Data    []evtData `xml:"EventData>Data"`
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
// `ringfenced` must be lower-case full paths; matching is on the path tail so
// a \device\harddiskvolume3\... event matches a C:\... ringfence entry.
func ParseWFP(raw []byte, ringfenced map[string]bool, enforced bool) ([]Violation, error) {
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
			if app == tail || strings.HasSuffix(app, tail) {
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
			Enforced: enforced,
			At:       time.Now(),
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
			At:       time.Now(),
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
