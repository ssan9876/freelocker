//go:build windows

package ringfence

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// volumeMapTTL caps how often the drive-letter table is rebuilt. Volume
// assignments change only when a disk is mounted or removed, while
// Violations() runs every tick, so rebuilding per call would mean 26
// QueryDosDevice calls a tick for a table that almost never changes.
const volumeMapTTL = 5 * time.Minute

var (
	volMu     sync.Mutex
	volCache  map[string]string
	volExpiry time.Time
)

// volumeMap returns a mapping of NT device volume names to their drive
// letters, e.g. "harddiskvolume3" -> "c:".
//
// WFP audit events (5156/5157) report the program as
// \Device\HarddiskVolume3\path\app.exe, while a ringfence entry is written
// as C:\path\app.exe. Resolving the volume is what makes those two
// comparable WITHOUT throwing the volume away — discarding it would let a
// ringfence on C:\app\app.exe match an unrelated binary at D:\app\app.exe.
func volumeMap() map[string]string {
	volMu.Lock()
	defer volMu.Unlock()

	if volCache != nil && time.Now().Before(volExpiry) {
		return volCache
	}

	m := make(map[string]string, 4)
	buf := make([]uint16, 1024)
	for c := 'a'; c <= 'z'; c++ {
		letter := string(c) + ":"
		name, err := windows.UTF16PtrFromString(letter)
		if err != nil {
			continue
		}
		n, err := windows.QueryDosDevice(name, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue // letter not assigned: the common case for most of A-Z
		}
		// The result is a NUL-separated list; the first entry is the target.
		target := strings.ToLower(strings.TrimRight(windows.UTF16ToString(buf[:n]), "\x00"))
		if i := strings.Index(target, "\x00"); i >= 0 {
			target = target[:i]
		}
		// \device\harddiskvolume3 -> harddiskvolume3
		target = strings.TrimPrefix(target, `\device\`)
		if target == "" {
			continue
		}
		m[target] = letter
	}

	if len(m) == 0 {
		// Every event will now be dropped as unresolvable. That is the safe
		// direction — misattributing a connection to the wrong program is
		// worse than reporting none — but it is silent, so say so once per
		// TTL rather than letting audit mode look mysteriously empty.
		slog.Warn("ringfence: could not resolve any drive letters; network violations cannot be attributed and will be dropped")
	}

	volCache, volExpiry = m, time.Now().Add(volumeMapTTL)
	return m
}
