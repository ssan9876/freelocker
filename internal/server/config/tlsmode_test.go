package config

import "testing"

func TestConsoleTLSMode(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"plain", Config{}, "plain"},
		{"file", Config{ConsoleTLSCert: "c.pem", ConsoleTLSKey: "k.pem"}, "file"},
		{"acme", Config{ACMEDomains: []string{"fl.example.com"}}, "acme"},
		{"acme wins over file", Config{ACMEDomains: []string{"fl.example.com"}, ConsoleTLSCert: "c.pem"}, "acme"},
	}
	for _, c := range cases {
		if got := c.cfg.ConsoleTLSMode(); got != c.want {
			t.Errorf("%s: mode = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestACMEEnvOverride(t *testing.T) {
	t.Setenv("FREELOCKER_DATABASE_URL", "postgres://x")
	t.Setenv("FREELOCKER_ACME_DOMAINS", "a.example.com,b.example.com")
	t.Setenv("FREELOCKER_ACME_EMAIL", "ops@example.com")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ACMEDomains) != 2 || c.ACMEDomains[0] != "a.example.com" || c.ACMEEmail != "ops@example.com" {
		t.Fatalf("acme config = %+v", c)
	}
	if c.ConsoleTLSMode() != "acme" {
		t.Errorf("mode = %q, want acme", c.ConsoleTLSMode())
	}
}
