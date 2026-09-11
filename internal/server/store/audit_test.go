package store_test

import (
	"context"
	"testing"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestAuditAppendListAndImmutability(t *testing.T) {
	ctx := context.Background()
	s, execSQL := storetest.NewWithSQL(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	for _, action := range []string{"a1", "a2", "a3"} {
		err := s.AppendAudit(ctx, tenant, store.AuditEntry{
			Actor: "admin:x@example.com", Action: action, TargetType: "device", TargetID: "d1",
			Detail: map[string]any{"k": "v"}, IP: "10.0.0.1", Result: "success",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListAudit(ctx, tenant, 2, 0)
	if err != nil || len(page) != 2 || page[0].Action != "a3" || page[1].Action != "a2" {
		t.Fatalf("page1 = %+v, %v", page, err)
	}
	if page[0].Detail["k"] != "v" || page[0].IP != "10.0.0.1" || page[0].CreatedAt.IsZero() {
		t.Errorf("entry fields = %+v", page[0])
	}
	next, _ := s.ListAudit(ctx, tenant, 2, page[1].ID)
	if len(next) != 1 || next[0].Action != "a1" {
		t.Fatalf("page2 = %+v", next)
	}

	if err := execSQL("UPDATE audit_log SET action = 'tampered'"); err == nil {
		t.Error("UPDATE on audit_log must fail")
	}
	if err := execSQL("DELETE FROM audit_log"); err == nil {
		t.Error("DELETE on audit_log must fail")
	}
}
