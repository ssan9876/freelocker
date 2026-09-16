package httpapi

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// exportMaxRows bounds any single export. A tenant with years of audit
// history would otherwise stream until something upstream times out.
//
// A truncated file that looks complete is the real hazard: someone reading
// it for a compliance question would silently miss rows. The status is
// already committed by the time the limit is reached, so truncation cannot
// be reported as an error — instead the last row is a visible marker (see
// writeTruncationMarker), which shows up in a spreadsheet.
const exportMaxRows = 100_000

// exportPage is how many audit rows are pulled per round trip while
// streaming. Large enough that a full export is not chatty, small enough
// that a page fits comfortably in memory.
const exportPage = 1000

// csvExport sets the headers that make a browser save the response as a
// dated file rather than render it, then hands back a writer.
//
// The response is streamed: rows are flushed as they are produced instead of
// being buffered into one big slice, so exporting a large audit log does not
// scale server memory with the tenant's history.
func csvExport(w http.ResponseWriter, name string, header []string) (*csv.Writer, error) {
	filename := fmt.Sprintf("freelocker-%s-%s.csv", name, time.Now().UTC().Format("2006-01-02"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	// Exports are point-in-time; a cached copy silently goes stale.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	if err := cw.Write(header); err != nil {
		return nil, err
	}
	return cw, nil
}

// writeTruncationMarker appends a final row saying the export stopped at the
// limit. It keeps the row's field count so the file stays valid CSV and
// spreadsheet software still opens it cleanly.
func writeTruncationMarker(cw *csv.Writer, w http.ResponseWriter, fields int) {
	row := make([]string, fields)
	row[0] = fmt.Sprintf("TRUNCATED: export limit of %d rows reached; narrow the range or use the API", exportMaxRows)
	_ = flushRow(cw, w, row)
}

// flushRow writes a row and pushes it toward the client so a long export
// makes visible progress instead of arriving all at once at the end.
func flushRow(cw *csv.Writer, w http.ResponseWriter, row []string) error {
	if err := cw.Write(row); err != nil {
		return err
	}
	cw.Flush()
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return cw.Error()
}

// exportCSV routes /api/exports/{resource}.csv.
//
// Exports mirror the JSON reads they correspond to: readable by any role,
// tenant-scoped through the store as everything else is. The audit export is
// additionally recorded in the audit log, because a bulk copy of "who did
// what" leaving the system is itself worth a record.
func (a *API) exportCSV(w http.ResponseWriter, r *http.Request) {
	resource := chi.URLParam(r, "resource")
	p := principalFrom(r)

	switch resource {
	case "audit.csv":
		a.exportAudit(w, r, p)
	case "devices.csv":
		a.exportDevices(w, r, p)
	case "blocks.csv":
		a.exportBlocks(w, r, p)
	case "ringfence-events.csv":
		a.exportRingfenceEvents(w, r, p)
	default:
		http.NotFound(w, r)
	}
}

func (a *API) exportAudit(w http.ResponseWriter, r *http.Request, p principal) {
	// Audited BEFORE the stream starts: once headers are written the status
	// is committed, so a failure to record the export could not be reported
	// to the caller afterwards. Recording an export that then fails midway
	// is the safe direction — it over-reports access rather than hiding it.
	a.audit(r, p, "export", "audit", "", map[string]any{"format": "csv"}, "success")

	cw, err := csvExport(w, "audit", []string{
		"time", "actor", "action", "target_type", "target_id", "result", "ip", "detail",
	})
	if err != nil {
		return
	}

	var before int64 // 0 = newest page
	written := 0
	for written < exportMaxRows {
		entries, err := a.Store.ListAudit(r.Context(), p.TenantID, exportPage, before)
		if err != nil || len(entries) == 0 {
			break
		}
		for _, e := range entries {
			detail := ""
			if len(e.Detail) > 0 {
				if b, err := json.Marshal(e.Detail); err == nil {
					detail = string(b)
				}
			}
			row := []string{
				e.CreatedAt.UTC().Format(time.RFC3339),
				e.Actor, e.Action, e.TargetType, e.TargetID, e.Result, e.IP, detail,
			}
			if err := flushRow(cw, w, row); err != nil {
				return
			}
			written++
			before = e.ID
			if written >= exportMaxRows {
				break
			}
		}
		if len(entries) < exportPage {
			break
		}
	}
	if written >= exportMaxRows {
		writeTruncationMarker(cw, w, 8)
	}
	cw.Flush()
}

func (a *API) exportDevices(w http.ResponseWriter, r *http.Request, p principal) {
	devices, err := a.Store.ListDevices(r.Context(), p.TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	cw, err := csvExport(w, "devices", []string{
		"id", "hostname", "os_build", "agent_version", "ip_addresses",
		"logged_on_user", "last_seen_at", "cert_expires_at", "enrolled_at", "revoked",
	})
	if err != nil {
		return
	}
	for _, d := range devices {
		lastSeen := ""
		if d.LastSeenAt != nil {
			lastSeen = d.LastSeenAt.UTC().Format(time.RFC3339)
		}
		row := []string{
			d.ID.String(), d.Hostname, d.OSBuild, d.AgentVersion,
			joinIPs(d.IPs), d.LoggedOnUser, lastSeen,
			d.CertExpiresAt.UTC().Format(time.RFC3339),
			d.EnrolledAt.UTC().Format(time.RFC3339),
			strconv.FormatBool(d.Revoked),
		}
		if err := flushRow(cw, w, row); err != nil {
			return
		}
	}
	cw.Flush()
}

// joinIPs renders the address list as a single space-separated field.
// Commas would be quoted correctly by the CSV writer but are needlessly
// awkward to split again in a spreadsheet.
func joinIPs(ips []string) string {
	out := ""
	for i, ip := range ips {
		if i > 0 {
			out += " "
		}
		out += ip
	}
	return out
}

func (a *API) exportBlocks(w http.ResponseWriter, r *http.Request, p principal) {
	events, err := a.Store.ListBlockEvents(r.Context(), p.TenantID, exportMaxRows)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	cw, err := csvExport(w, "blocks", []string{
		"time", "device_id", "sha256", "path", "signer", "signer_verified", "blocked",
	})
	if err != nil {
		return
	}
	for _, e := range events {
		row := []string{
			e.At.UTC().Format(time.RFC3339), e.DeviceID.String(), e.SHA256, e.Path, e.Signer,
			strconv.FormatBool(e.SignerVerified), strconv.FormatBool(e.Blocked),
		}
		if err := flushRow(cw, w, row); err != nil {
			return
		}
	}
	if len(events) >= exportMaxRows {
		writeTruncationMarker(cw, w, 7)
	}
	cw.Flush()
}

func (a *API) exportRingfenceEvents(w http.ResponseWriter, r *http.Request, p principal) {
	events, err := a.Store.ListRingfenceEvents(r.Context(), p.TenantID, exportMaxRows, nil)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	cw, err := csvExport(w, "ringfence-events", []string{
		"time", "device_id", "hostname", "kind", "program", "detail", "enforced",
	})
	if err != nil {
		return
	}
	for _, e := range events {
		row := []string{
			e.At.UTC().Format(time.RFC3339), e.DeviceID.String(), e.Hostname,
			e.Kind, e.Program, e.Detail, strconv.FormatBool(e.Enforced),
		}
		if err := flushRow(cw, w, row); err != nil {
			return
		}
	}
	if len(events) >= exportMaxRows {
		writeTruncationMarker(cw, w, 7)
	}
	cw.Flush()
}
