// Package config loads server configuration from an optional YAML file,
// with FREELOCKER_* environment variables taking precedence.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DatabaseURL          string   `yaml:"database_url"`
	AgentListen          string   `yaml:"agent_listen"`
	ConsoleListen        string   `yaml:"console_listen"`
	PublicHostnames      []string `yaml:"public_hostnames"`
	MasterSecretFile     string   `yaml:"master_secret_file"`
	ConsoleTLSCert       string   `yaml:"console_tls_cert"`
	ConsoleTLSKey        string   `yaml:"console_tls_key"`
	InsecureCookies      bool     `yaml:"insecure_cookies"`
	ReleaseDir           string   `yaml:"release_dir"`
	ReleaseBaseURL       string   `yaml:"release_base_url"`       // agents download releases from <this>/agent/releases/<version>; default derived from public_hostnames + console_listen
	ACMEDomains          []string `yaml:"acme_domains"`           // enable Let's Encrypt for the console on these domains
	ACMEEmail            string   `yaml:"acme_email"`             // contact email for the ACME account
	ACMECacheDir         string   `yaml:"acme_cache_dir"`         // where issued certs are cached
	MetricsRetentionDays int      `yaml:"metrics_retention_days"` // delete metrics/block-events/resolved-alerts older than this
	ApprovalExpiryDays   int      `yaml:"approval_expiry_days"`   // pending approval requests idle this long become expired (0 disables)
}

// ConsoleTLSMode reports how the console listener obtains TLS:
// "acme" (Let's Encrypt), "file" (cert+key), or "plain" (no TLS).
// ACME takes precedence over a cert file if both are set.
func (c Config) ConsoleTLSMode() string {
	switch {
	case len(c.ACMEDomains) > 0:
		return "acme"
	case c.ConsoleTLSCert != "":
		return "file"
	default:
		return "plain"
	}
}

// ReleaseURL is the URL an agent downloads a release from. ReleaseBaseURL
// wins when set; otherwise it is built from the first public hostname and
// the console listener's port, https unless the console has no TLS.
func (c Config) ReleaseURL(version string) string {
	base := strings.TrimRight(c.ReleaseBaseURL, "/")
	if base == "" {
		host := "localhost"
		if len(c.PublicHostnames) > 0 && c.PublicHostnames[0] != "" {
			host = c.PublicHostnames[0]
		}
		scheme := "https"
		if c.ConsoleTLSMode() == "plain" {
			scheme = "http"
		}
		_, port, err := net.SplitHostPort(c.ConsoleListen)
		if err != nil || port == "" {
			port = "8080"
		}
		base = scheme + "://" + host + ":" + port
	}
	return base + "/agent/releases/" + url.PathEscape(version)
}

func Load(path string) (Config, error) {
	c := Config{
		AgentListen:          ":8443",
		ConsoleListen:        ":8080",
		PublicHostnames:      []string{"localhost"},
		MasterSecretFile:     "master.key",
		ReleaseDir:           "releases",
		ACMECacheDir:         "acme-cache",
		MetricsRetentionDays: 30,
		ApprovalExpiryDays:   30,
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return c, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("parse config: %w", err)
		}
	}
	envStr(&c.DatabaseURL, "FREELOCKER_DATABASE_URL")
	envStr(&c.AgentListen, "FREELOCKER_AGENT_LISTEN")
	envStr(&c.ConsoleListen, "FREELOCKER_CONSOLE_LISTEN")
	envStr(&c.MasterSecretFile, "FREELOCKER_MASTER_SECRET_FILE")
	envStr(&c.ConsoleTLSCert, "FREELOCKER_CONSOLE_TLS_CERT")
	envStr(&c.ConsoleTLSKey, "FREELOCKER_CONSOLE_TLS_KEY")
	envStr(&c.ReleaseDir, "FREELOCKER_RELEASE_DIR")
	envStr(&c.ReleaseBaseURL, "FREELOCKER_RELEASE_BASE_URL")
	envStr(&c.ACMEEmail, "FREELOCKER_ACME_EMAIL")
	envStr(&c.ACMECacheDir, "FREELOCKER_ACME_CACHE_DIR")
	if v := os.Getenv("FREELOCKER_ACME_DOMAINS"); v != "" {
		c.ACMEDomains = strings.Split(v, ",")
	}
	if os.Getenv("FREELOCKER_INSECURE_COOKIES") == "true" {
		c.InsecureCookies = true
	}
	if v := os.Getenv("FREELOCKER_PUBLIC_HOSTNAMES"); v != "" {
		c.PublicHostnames = strings.Split(v, ",")
	}
	if c.DatabaseURL == "" {
		return c, errors.New("database_url is required")
	}
	return c, nil
}

func envStr(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}
