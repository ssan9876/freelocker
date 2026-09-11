// Package config loads server configuration from an optional YAML file,
// with FREELOCKER_* environment variables taking precedence.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DatabaseURL      string   `yaml:"database_url"`
	AgentListen      string   `yaml:"agent_listen"`
	ConsoleListen    string   `yaml:"console_listen"`
	PublicHostnames  []string `yaml:"public_hostnames"`
	MasterSecretFile string   `yaml:"master_secret_file"`
	ConsoleTLSCert   string   `yaml:"console_tls_cert"`
	ConsoleTLSKey    string   `yaml:"console_tls_key"`
}

func Load(path string) (Config, error) {
	c := Config{
		AgentListen:      ":8443",
		ConsoleListen:    ":8080",
		PublicHostnames:  []string{"localhost"},
		MasterSecretFile: "master.key",
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
