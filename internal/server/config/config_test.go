package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileThenEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.yaml")
	yaml := "database_url: postgres://file\nagent_listen: \":9443\"\npublic_hostnames: [a.example.com]\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FREELOCKER_DATABASE_URL", "postgres://env")

	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != "postgres://env" {
		t.Errorf("DatabaseURL = %q, want env override", c.DatabaseURL)
	}
	if c.AgentListen != ":9443" {
		t.Errorf("AgentListen = %q", c.AgentListen)
	}
	if c.ConsoleListen != ":8080" {
		t.Errorf("ConsoleListen default = %q, want :8080", c.ConsoleListen)
	}
	if len(c.PublicHostnames) != 1 || c.PublicHostnames[0] != "a.example.com" {
		t.Errorf("PublicHostnames = %v", c.PublicHostnames)
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("FREELOCKER_DATABASE_URL", "")
	if _, err := Load(""); err == nil {
		t.Fatal("expected error when database_url missing")
	}
}

func TestReleaseURLDefaultsAndOverride(t *testing.T) {
	c := Config{PublicHostnames: []string{"console.example.com"}, ConsoleListen: ":8080"}
	if got := c.ReleaseURL("1.2.3"); got != "http://console.example.com:8080/agent/releases/1.2.3" {
		t.Errorf("plain default = %q", got)
	}
	c.ConsoleTLSCert = "cert.pem"
	if got := c.ReleaseURL("1.2.3"); got != "https://console.example.com:8080/agent/releases/1.2.3" {
		t.Errorf("tls default = %q", got)
	}
	c.ReleaseBaseURL = "https://updates.example.com/"
	if got := c.ReleaseURL("1.2.3"); got != "https://updates.example.com/agent/releases/1.2.3" {
		t.Errorf("override = %q (trailing slash must be trimmed)", got)
	}
	c = Config{ConsoleListen: "0.0.0.0:443"}
	if got := c.ReleaseURL("v"); got != "http://localhost:443/agent/releases/v" {
		t.Errorf("no hostnames = %q", got)
	}
}
