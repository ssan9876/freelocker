//go:build windows

package signature

// verify is implemented with WinVerifyTrust in the next task.
func verify(string) bool { return false }
