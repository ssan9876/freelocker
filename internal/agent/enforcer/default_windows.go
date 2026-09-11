//go:build windows

package enforcer

// Default returns the WDAC enforcer, which applies real policy (audit mode
// unless explicitly opted in to enforce).
func Default(dataDir string) Enforcer { return &WDACEnforcer{DataDir: dataDir} }
