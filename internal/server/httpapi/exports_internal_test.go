package httpapi

import (
	"encoding/csv"
	"net/http/httptest"
	"strings"
	"testing"
)

// The truncation marker is the only signal a caller gets that an export
// stopped early — the HTTP status is already committed by then. If it broke
// the file's shape, spreadsheet software would refuse the whole export and
// the warning would be worse than useless.
func TestTruncationMarkerKeepsTheFileValid(t *testing.T) {
	rec := httptest.NewRecorder()
	cw := csv.NewWriter(rec)
	header := []string{"time", "actor", "action"}
	if err := cw.Write(header); err != nil {
		t.Fatal(err)
	}

	writeTruncationMarker(cw, rec, len(header))
	cw.Flush()

	recs, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("marker broke the CSV: %v\n%s", err, rec.Body.String())
	}
	if len(recs) != 2 {
		t.Fatalf("got %d rows, want header plus marker", len(recs))
	}
	// encoding/csv rejects a file whose rows differ in field count, so this
	// is what keeps the export openable.
	if len(recs[1]) != len(header) {
		t.Fatalf("marker row has %d fields, want %d", len(recs[1]), len(header))
	}
	if !strings.HasPrefix(recs[1][0], "TRUNCATED:") {
		t.Errorf("marker = %q, want it to start with TRUNCATED:", recs[1][0])
	}
	// The remaining columns stay empty so the marker cannot be mistaken for
	// a real record.
	for i, f := range recs[1][1:] {
		if f != "" {
			t.Errorf("marker field %d = %q, want empty", i+1, f)
		}
	}
}
