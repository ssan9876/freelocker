//go:build !windows

package ringfence

// Default returns the no-op enforcer off Windows.
func Default(agentImages []string) Enforcer { return &NoopEnforcer{} }
