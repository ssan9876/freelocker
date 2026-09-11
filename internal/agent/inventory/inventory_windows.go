//go:build windows

package inventory

import (
	"time"

	flv1 "freelocker/gen/freelocker/v1"

	"golang.org/x/sys/windows/registry"
)

type winCollector struct{ Base }

func New() Collector { return winCollector{Base{StartedAt: time.Now()}} }

func (w winCollector) Collect() *flv1.Inventory {
	inv := w.base()
	inv.OsBuild = osBuild()
	inv.LoggedOnUser = loggedOnUser()
	return inv
}

func osBuild() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	product, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuild")
	if build != "" {
		return product + " " + build
	}
	return product
}

// loggedOnUser reads the interactive user recorded under LogonUI, best effort.
func loggedOnUser() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	user, _, _ := k.GetStringValue("LastLoggedOnUser")
	return user
}
