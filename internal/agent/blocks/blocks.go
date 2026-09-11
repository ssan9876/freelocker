// Package blocks models application-control block events and parses them
// from the Windows CodeIntegrity operational log (as rendered by
// `wevtutil ... /f:xml`). The parser handles the documented event schema;
// field fidelity against real logs is verified on a VM.
package blocks

import (
	"encoding/xml"
	"strings"
	"time"
)

type BlockEvent struct {
	SHA256  string
	Path    string
	Signer  string
	Blocked bool // true = enforced (3077); false = audit would-block (3076)
	At      time.Time
}

// wevtutil renders a sequence of <Event> elements (not wrapped in a root),
// so we wrap the input before decoding.
type eventsXML struct {
	Events []eventXML `xml:"Event"`
}

type eventXML struct {
	System struct {
		EventID     int    `xml:"EventID"`
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
}

// ParseCodeIntegrity extracts block events from wevtutil XML. Event 3077
// is an enforced block; 3076 is an audit-mode would-block.
func ParseCodeIntegrity(raw []byte) ([]BlockEvent, error) {
	wrapped := append([]byte("<Events>"), raw...)
	wrapped = append(wrapped, []byte("</Events>")...)
	var evs eventsXML
	if err := xml.Unmarshal(wrapped, &evs); err != nil {
		return nil, err
	}
	out := make([]BlockEvent, 0, len(evs.Events))
	for _, e := range evs.Events {
		if e.System.EventID != 3076 && e.System.EventID != 3077 {
			continue
		}
		be := BlockEvent{Blocked: e.System.EventID == 3077}
		if t, err := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime); err == nil {
			be.At = t
		}
		for _, d := range e.EventData.Data {
			v := strings.TrimSpace(d.Value)
			switch d.Name {
			case "File Name", "FileName", "FilePath":
				be.Path = stripDevicePrefix(v)
			case "SHA256 Hash", "SHA256Hash", "Sha256":
				be.SHA256 = strings.ToUpper(v)
			case "Publisher", "PublisherName", "Signer":
				be.Signer = v
			}
		}
		out = append(out, be)
	}
	return out, nil
}

// stripDevicePrefix turns a \Device\HarddiskVolumeN\path into something
// closer to a normal path when present; otherwise returns the input.
func stripDevicePrefix(p string) string {
	const marker = `HarddiskVolume`
	if i := strings.Index(p, marker); i >= 0 {
		if j := strings.IndexByte(p[i:], '\\'); j >= 0 {
			return p[i+j:]
		}
	}
	return p
}
