package config

import (
	"path/filepath"
	"testing"
)

func TestWriteLoadAndEnvOverride(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := Write(p, Config{ServerURL: "fl.example.com:8443", Token: "sec.pin"}); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c.ServerURL != "fl.example.com:8443" || c.Token != "sec.pin" {
		t.Fatalf("Load = %+v, %v", c, err)
	}
	t.Setenv("FREELOCKER_SERVER_URL", "other:9443")
	if c, _ := Load(p); c.ServerURL != "other:9443" {
		t.Errorf("env override = %q", c.ServerURL)
	}
}

func TestLoadRequiresServerURL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	Write(p, Config{Token: "x"})
	if _, err := Load(p); err == nil {
		t.Fatal("expected ErrNoServerURL")
	}
}
