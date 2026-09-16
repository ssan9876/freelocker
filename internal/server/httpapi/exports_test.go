package httpapi_test

import (
	"encoding/csv"
	"strings"
	"testing"
)

// parseCSV fails the test on malformed output. Asserting on a substring
// instead would let a broken quoting bug pass — a field containing a comma
// or a newline is exactly what breaks naive CSV writers, and the audit log's
// detail column is JSON, so it contains both.
func parseCSV(t *testing.T, body string) [][]string {
	t.Helper()
	recs, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("response is not valid CSV: %v\n%s", err, body)
	}
	return recs
}

func TestExportAuditCSV(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	// Generate audit entries with a detail payload, which is JSON and so
	// contains commas and quotes — the characters CSV must escape.
	c.do("POST", "/api/groups", map[string]string{"name": "Workstations"}, nil)
	c.do("POST", "/api/policies", map[string]string{"name": "Baseline", "mode": "audit"}, nil)

	code, body, hdr := c.raw("GET", "/api/exports/audit.csv")
	if code != 200 {
		t.Fatalf("export = %d, want 200", code)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	// Without this the browser renders the CSV inline instead of saving it.
	if cd := hdr.Get("Content-Disposition"); !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, "freelocker-audit-") {
		t.Errorf("Content-Disposition = %q, want an attachment with a dated filename", cd)
	}

	recs := parseCSV(t, body)
	if len(recs) < 2 {
		t.Fatalf("got %d rows, want a header plus at least one entry", len(recs))
	}
	want := []string{"time", "actor", "action", "target_type", "target_id", "result", "ip", "detail"}
	for i, h := range want {
		if i >= len(recs[0]) || recs[0][i] != h {
			t.Fatalf("header = %v, want %v", recs[0], want)
		}
	}
	// Every data row must have exactly as many fields as the header, which
	// is what a quoting bug breaks.
	for i, r := range recs[1:] {
		if len(r) != len(want) {
			t.Fatalf("row %d has %d fields, want %d: %v", i, len(r), len(want), r)
		}
	}

	var actions []string
	for _, r := range recs[1:] {
		actions = append(actions, r[2])
	}
	joined := strings.Join(actions, " ")
	if !strings.Contains(joined, "group.create") || !strings.Contains(joined, "policy.create") {
		t.Errorf("actions = %v, want the group and policy creates", actions)
	}
}

// Exporting the audit log is itself security-relevant — it is the record of
// who did what, leaving the system in bulk — so the export is audited.
func TestExportAuditIsItselfAudited(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	if code, _, _ := c.raw("GET", "/api/exports/audit.csv"); code != 200 {
		t.Fatalf("export = %d", code)
	}

	var entries []struct {
		Action     string `json:"action"`
		TargetType string `json:"target_type"`
	}
	c.do("GET", "/api/audit?limit=50", nil, &entries)
	found := false
	for _, en := range entries {
		if en.Action == "export" && en.TargetType == "audit" {
			found = true
		}
	}
	if !found {
		t.Errorf("no export audit entry found in %+v", entries)
	}
}

func TestExportOtherFeedsCSV(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	e.fakeDevice(t)

	for _, tc := range []struct {
		path   string
		header string
	}{
		{"/api/exports/devices.csv", "hostname"},
		{"/api/exports/blocks.csv", "sha256"},
		{"/api/exports/ringfence-events.csv", "program"},
	} {
		code, body, _ := c.raw("GET", tc.path)
		if code != 200 {
			t.Errorf("%s = %d, want 200", tc.path, code)
			continue
		}
		recs := parseCSV(t, body)
		if len(recs) == 0 {
			t.Errorf("%s returned no header row", tc.path)
			continue
		}
		// A feed with no rows still emits its header, so an empty export is
		// an empty spreadsheet rather than an empty file.
		if !strings.Contains(strings.Join(recs[0], ","), tc.header) {
			t.Errorf("%s header = %v, want a %q column", tc.path, recs[0], tc.header)
		}
	}
}

func TestExportUnknownResourceIs404(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	if code, _, _ := c.raw("GET", "/api/exports/passwords.csv"); code != 404 {
		t.Errorf("unknown export = %d, want 404", code)
	}
}

// Exports follow the same rule as the JSON reads they mirror: any role may
// read. A readonly admin who can see the audit page can export it.
func TestExportReadableByReadOnlyRole(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	c.do("POST", "/api/admins", map[string]string{
		"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")

	if code, _, _ := ro.raw("GET", "/api/exports/audit.csv"); code != 200 {
		t.Errorf("readonly export = %d, want 200", code)
	}
}

// An unauthenticated caller must not be able to pull the audit log.
func TestExportRequiresAuth(t *testing.T) {
	e := newEnv(t)
	e.initialized(t)
	anon := e.client(t)
	if code, _, _ := anon.raw("GET", "/api/exports/audit.csv"); code != 401 {
		t.Errorf("anonymous export = %d, want 401", code)
	}
}
