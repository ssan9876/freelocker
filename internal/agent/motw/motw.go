// Package motw reads Windows' Mark-of-the-Web: the Zone.Identifier alternate
// data stream that browsers, mail clients and archive tools attach to files
// that came from outside the machine.
//
// This is how "downloaded" is distinguished from "installed". A binary that
// shipped with Windows or was laid down by an installer has no such stream;
// one a user fetched from a browser does.
//
// IMPORTANT: Mark-of-the-Web is a provenance hint, NOT a security boundary.
// A standard user can delete the stream from a file they own, some archive
// formats do not propagate it, and mounted images historically did not
// either. Treat its presence as meaningful and its absence as unproven — it
// is sound for reporting and for policy defaults, and must never be the only
// thing standing between a user and a privilege they should not have.
package motw

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// Security zones, as written by Windows into ZoneId.
const (
	ZoneLocalMachine = 0
	ZoneIntranet     = 1
	ZoneTrusted      = 2
	ZoneInternet     = 3
	ZoneRestricted   = 4
)

// streamName is the alternate data stream Windows stores the mark in.
const streamName = ":Zone.Identifier"

// Info is what a file's Zone.Identifier stream says about where it came from.
type Info struct {
	// Present reports whether the stream existed at all. Distinguishing
	// "no mark" from "mark saying local" matters: the first is the normal
	// state of an installed file, the second is rare and deliberate.
	Present bool
	ZoneID  int
	// HostURL and ReferrerURL are written by most browsers but not by every
	// tool that sets a mark, so both are frequently empty even when Present.
	HostURL     string
	ReferrerURL string
}

// Downloaded reports whether the file carries a mark from outside the
// machine's trust boundary. Intranet and Trusted zones are deliberately NOT
// counted: a file pulled from a corporate file share is not "downloaded from
// the internet" in the sense an admin means when reviewing it.
func (i Info) Downloaded() bool {
	return i.Present && i.ZoneID >= ZoneInternet
}

// Parse reads the INI-shaped Zone.Identifier stream contents.
//
// Tolerant on purpose: the stream is written by many different tools, and a
// malformed or partial one should degrade to "present but unknown zone"
// rather than fail the whole scan of a machine.
func Parse(raw []byte) Info {
	info := Info{Present: true}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "zoneid":
			if n, err := strconv.Atoi(value); err == nil {
				info.ZoneID = n
			}
		case "hosturl":
			info.HostURL = value
		case "referrerurl":
			info.ReferrerURL = value
		}
	}
	return info
}

// Source returns the most useful human-facing origin for the file, or "" when
// the mark carries none. HostURL is the direct download; ReferrerUrl is the
// page it was linked from, which is the better answer when the host is a CDN
// but the worse one when it is absent.
func (i Info) Source() string {
	if i.HostURL != "" {
		return i.HostURL
	}
	return i.ReferrerURL
}
