//go:build windows

package scan

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// runningImpl enumerates running processes, resolves each full image path,
// and hashes the distinct executables. Signer resolution is deferred
// (verified on a VM); Signer is left empty for now.
func runningImpl() ([]Observed, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var out []Observed
	for {
		if path := imagePath(entry.ProcessID); path != "" {
			if _, dup := seen[path]; !dup {
				seen[path] = struct{}{}
				if sum, err := AuthenticodeHash(path); err == nil {
					out = append(out, Observed{SHA256: sum, Path: path})
				}
			}
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break // ERROR_NO_MORE_FILES ends enumeration
		}
	}
	return out, nil
}

func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
