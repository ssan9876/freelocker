// Package config loads the agent's server URL and (pre-enrollment) install token.
package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

var ErrNoServerURL = errors.New("server_url is required")

type Config struct {
	ServerURL string `yaml:"server_url"`
	Token     string `yaml:"token"`
}

func Load(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return c, fmt.Errorf("read config: %w", err)
	}
	if err == nil {
		if err := yaml.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("parse config: %w", err)
		}
	}
	if v := os.Getenv("FREELOCKER_SERVER_URL"); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv("FREELOCKER_TOKEN"); v != "" {
		c.Token = v
	}
	if c.ServerURL == "" {
		return c, ErrNoServerURL
	}
	return c, nil
}

func Write(path string, c Config) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
