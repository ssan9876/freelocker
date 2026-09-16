//go:build !windows

package motw

// Read reports no mark on non-Windows platforms. Alternate data streams are
// an NTFS feature; the agent only enforces on Windows, and this exists so the
// scan path compiles and tests run on the build machine.
func Read(string) (Info, error) { return Info{}, nil }
