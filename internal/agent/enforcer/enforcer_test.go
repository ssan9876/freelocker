package enforcer

import (
	"context"
	"testing"
)

func TestNoopRecordsApplied(t *testing.T) {
	n := &NoopEnforcer{}
	if err := n.Apply(context.Background(), "v1", "audit", []byte("<x/>")); err != nil {
		t.Fatal(err)
	}
	if s := n.Status(); s.AppliedVersion != "v1" || s.AppliedMode != "audit" {
		t.Fatalf("status = %+v", s)
	}
	if err := n.Apply(context.Background(), "v2", "bogus", nil); err == nil {
		t.Error("bad mode must be rejected")
	}
	ev, err := n.Events(context.Background())
	if err != nil || ev != nil {
		t.Errorf("noop events = %v, %v", ev, err)
	}
}
