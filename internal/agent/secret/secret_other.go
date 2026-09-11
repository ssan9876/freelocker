//go:build !windows

package secret

func Default() Protector { return FileProtector{} }
