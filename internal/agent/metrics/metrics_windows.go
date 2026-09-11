//go:build windows

package metrics

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes   = kernel32.NewProc("GetSystemTimes")
	procGlobalMemStatus  = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpace = kernel32.NewProc("GetDiskFreeSpaceExW")
)

type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

func collect() (Sample, error) {
	var s Sample
	s.CPUPct = clampPct(cpuPercent())
	s.MemPct = clampPct(memPercent())
	s.DiskPct = clampPct(diskPercent())
	return s, nil
}

func fileTimeToUint64(lo, hi uint32) uint64 { return uint64(hi)<<32 | uint64(lo) }

func systemTimes() (idle, kernel, user uint64) {
	var i, k, u windows.Filetime
	procGetSystemTimes.Call(uintptr(unsafe.Pointer(&i)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u)))
	return fileTimeToUint64(i.LowDateTime, i.HighDateTime),
		fileTimeToUint64(k.LowDateTime, k.HighDateTime),
		fileTimeToUint64(u.LowDateTime, u.HighDateTime)
}

// cpuPercent samples system times over a short window. kernel time
// includes idle, so busy = (kernel+user) - idle over the interval.
func cpuPercent() float64 {
	i0, k0, u0 := systemTimes()
	time.Sleep(200 * time.Millisecond)
	i1, k1, u1 := systemTimes()
	idle := float64(i1 - i0)
	total := float64((k1 + u1) - (k0 + u0))
	if total <= 0 {
		return 0
	}
	return (total - idle) / total * 100
}

func memPercent() float64 {
	var m memoryStatusEx
	m.length = uint32(unsafe.Sizeof(m))
	r, _, _ := procGlobalMemStatus.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0
	}
	return float64(m.memoryLoad)
}

func diskPercent() float64 {
	root, _ := windows.UTF16PtrFromString(`C:\`)
	var freeToCaller, total, totalFree uint64
	r, _, _ := procGetDiskFreeSpace.Call(
		uintptr(unsafe.Pointer(root)),
		uintptr(unsafe.Pointer(&freeToCaller)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 || total == 0 {
		return 0
	}
	used := total - totalFree
	return float64(used) / float64(total) * 100
}
