//go:build !windows

package controls

// Default returns a no-op enforcer off-Windows (development only).
func Default() Enforcer { return &NoopEnforcer{} }
