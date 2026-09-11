//go:build windows

package controls

import (
	"context"
	"sync"

	"golang.org/x/sys/windows/registry"
)

const usbstorKey = `SYSTEM\CurrentControlSet\Services\USBSTOR`

// usbstorStart values: 3 = manual (allowed), 4 = disabled (blocked).
const (
	usbAllow = 3
	usbBlock = 4
)

type WinEnforcer struct {
	mu   sync.Mutex
	last Controls
	set  bool
}

func Default() Enforcer { return &WinEnforcer{} }

func (e *WinEnforcer) Apply(_ context.Context, c Controls) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.set && e.last == c {
		return nil // idempotent
	}
	want := uint32(usbAllow)
	if c.USBStorageBlocked {
		want = usbBlock
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, usbstorKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("Start", want); err != nil {
		return err
	}
	e.last, e.set = c, true
	return nil
}

func (e *WinEnforcer) Last() Controls {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.last
}
