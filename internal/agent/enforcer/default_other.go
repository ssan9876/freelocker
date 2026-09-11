//go:build !windows

package enforcer

// Default returns a no-op enforcer off-Windows (development only).
func Default(string) Enforcer { return &NoopEnforcer{} }
