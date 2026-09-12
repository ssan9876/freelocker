//go:build windows

package events

import (
	"fmt"
	"os/exec"
)

// winReader reads recent process-creation (4688) and logon (4624) events
// from the Windows Security log. Process-creation auditing must be enabled
// (Audit Process Creation) for 4688 to appear.
type winReader struct{}

func NewReader() Reader { return winReader{} }

func (winReader) Read() ([]Event, error) {
	out, err := exec.Command("wevtutil", "qe", "Security",
		`/q:*[System[(EventID=4688 or EventID=4624)]]`,
		"/c:200", "/rd:true", "/f:xml").Output()
	if err != nil {
		return nil, fmt.Errorf("wevtutil: %w", err)
	}
	return ParseSecurity(out)
}
