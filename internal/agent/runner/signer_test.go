package runner_test

import (
	"os"
	"path/filepath"
	"testing"

	"freelocker/internal/agent/blocks"
	"freelocker/internal/agent/runner"
)

func TestEnrichBlockEventsFillsPublisher(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone.exe")
	unsigned := filepath.Join(t.TempDir(), "plain.exe")
	if err := os.WriteFile(unsigned, []byte("not a PE"), 0o600); err != nil {
		t.Fatal(err)
	}

	in := []blocks.BlockEvent{
		{SHA256: "AA", Path: missing, Signer: "Contoso"},
		{SHA256: "BB", Path: unsigned},
		{SHA256: "CC", Path: "", Signer: ""},
	}
	got := runner.EnrichBlockEvents(in)
	if len(got) != 3 {
		t.Fatalf("enrich dropped events: %d", len(got))
	}
	for i, e := range got {
		if e.SignerTBS != "" || e.SignerVerified {
			t.Errorf("event %d: unreadable/unsigned file must leave publisher empty, got %+v", i, e)
		}
	}
	if got[0].Signer != "Contoso" {
		t.Errorf("existing signer name must survive enrichment: %q", got[0].Signer)
	}
}
