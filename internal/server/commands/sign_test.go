package commands

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	c := &flv1.Command{Id: "c1", Type: flv1.CommandType_COMMAND_TYPE_PING, DeviceId: "dev-1",
		IssuedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(time.Hour).Unix()}
	sc, err := Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(pub, sc, "dev-1", now)
	if err != nil || got.GetId() != "c1" {
		t.Fatalf("Verify = %v, %v", got, err)
	}
	if _, err := Verify(pub, sc, "dev-2", now); err == nil {
		t.Error("wrong device must fail")
	}
	if _, err := Verify(pub, sc, "dev-1", now.Add(2*time.Hour)); err == nil {
		t.Error("expired command must fail")
	}
	sc.Command[0] ^= 1
	if _, err := Verify(pub, sc, "dev-1", now); err == nil {
		t.Error("tampered command must fail")
	}
}

func TestTypeNames(t *testing.T) {
	for _, name := range []string{"ping", "refresh_inventory", "rotate_certificate", "uninstall", "update_agent"} {
		typ, err := ParseType(name)
		if err != nil || TypeName(typ) != name {
			t.Errorf("%s: %v %v", name, typ, err)
		}
	}
	if _, err := ParseType("format_c"); err == nil {
		t.Error("unknown type must fail")
	}
}
