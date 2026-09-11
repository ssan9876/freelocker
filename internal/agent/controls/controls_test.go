package controls

import (
	"context"
	"testing"
)

func TestNoopRecordsLast(t *testing.T) {
	n := &NoopEnforcer{}
	if err := n.Apply(context.Background(), Controls{USBStorageBlocked: true}); err != nil {
		t.Fatal(err)
	}
	if !n.Last().USBStorageBlocked {
		t.Error("Noop should record last applied controls")
	}
}
