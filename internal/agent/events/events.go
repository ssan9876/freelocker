// Package events reports notable endpoint activity — process launches and
// interactive logons — for monitoring ("make sure nothing weird is going
// on"). Events are parsed from the Windows Security event log; the parser
// is portable and unit-tested on sample XML, while reading the live log is
// Windows-only and VM-verified.
package events

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

type Event struct {
	Kind    string // "process_launch" | "logon"
	Summary string // human-readable one-liner
	At      time.Time
}

// Reader returns events observed since the last call.
type Reader interface {
	Read() ([]Event, error)
}

type securityXML struct {
	Events []struct {
		System struct {
			EventID     int `xml:"EventID"`
			TimeCreated struct {
				SystemTime string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
		} `xml:"System"`
		EventData struct {
			Data []struct {
				Name  string `xml:"Name,attr"`
				Value string `xml:",chardata"`
			} `xml:"Data"`
		} `xml:"EventData"`
	} `xml:"Event"`
}

// ParseSecurity extracts process-creation (4688) and logon (4624) events
// from wevtutil Security-log XML.
func ParseSecurity(raw []byte) ([]Event, error) {
	var sx securityXML
	if err := xml.Unmarshal(append(append([]byte("<Events>"), raw...), []byte("</Events>")...), &sx); err != nil {
		return nil, err
	}
	var out []Event
	for _, e := range sx.Events {
		data := map[string]string{}
		for _, d := range e.EventData.Data {
			data[d.Name] = strings.TrimSpace(d.Value)
		}
		at, _ := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime)
		switch e.System.EventID {
		case 4688: // process creation
			out = append(out, Event{
				Kind:    "process_launch",
				Summary: fmt.Sprintf("%s launched %s", firstNonEmpty(data["SubjectUserName"], "?"), firstNonEmpty(data["NewProcessName"], "?")),
				At:      at,
			})
		case 4624: // successful logon
			out = append(out, Event{
				Kind:    "logon",
				Summary: fmt.Sprintf("%s logged on (type %s)", firstNonEmpty(data["TargetUserName"], "?"), firstNonEmpty(data["LogonType"], "?")),
				At:      at,
			})
		}
	}
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
