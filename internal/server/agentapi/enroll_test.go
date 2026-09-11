package agentapi_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"
	"freelocker/internal/sim"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var hw = &flv1.HardwareInfo{Hostname: "pc-01", OsBuild: "26100", MachineGuid: "g-1"}

func TestEnrollSuccess(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)

	id, err := sim.Enroll(ctx, ts.Addr, ts.Token, hw)
	if err != nil {
		t.Fatal(err)
	}
	devID := uuid.MustParse(id.DeviceID)
	d, err := ts.Deps.Store.GetDevice(ctx, ts.Deps.Keys.TenantID, devID)
	if err != nil || d.Hostname != "pc-01" || d.MachineGUID != "g-1" {
		t.Fatalf("device = %+v, %v", d, err)
	}
	sum := sha256.Sum256([]byte(ts.Deps.Keys.UninstallCode(devID)))
	if string(id.UninstallHash) != string(sum[:]) || len(id.CommandPub) != 32 {
		t.Error("enroll response missing uninstall hash or command key")
	}
	entries, _ := ts.Deps.Store.ListAudit(ctx, ts.Deps.Keys.TenantID, 10, 0)
	if len(entries) != 1 || entries[0].Action != "device.enroll" || entries[0].TargetID != id.DeviceID {
		t.Errorf("audit = %+v", entries)
	}
}

func TestEnrollRejectsBadToken(t *testing.T) {
	ts := startServer(t)
	_, pin, _ := tokens.Parse(ts.Token)
	bad, _, _ := tokens.Generate(pin) // right pin, unknown secret
	_, err := sim.Enroll(context.Background(), ts.Addr, bad, hw)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}

func TestEnrollRejectsWrongServerPin(t *testing.T) {
	ts := startServer(t)
	secret, _, _ := tokens.Parse(ts.Token)
	_, err := sim.Enroll(context.Background(), ts.Addr, secret+"."+strings.Repeat("0", 32), hw)
	if err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("err = %v, want pin mismatch", err)
	}
}

func TestEnrollHonorsMaxUses(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	one := 1
	full, hash, _ := tokens.Generate(ts.Deps.Keys.CA.Pin())
	ts.Deps.Store.CreateInstallToken(ctx, ts.Deps.Keys.TenantID, store.InstallToken{Name: "once", MaxUses: &one}, hash)

	if _, err := sim.Enroll(ctx, ts.Addr, full, hw); err != nil {
		t.Fatal(err)
	}
	if _, err := sim.Enroll(ctx, ts.Addr, full, hw); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("second enroll err = %v", err)
	}
}
