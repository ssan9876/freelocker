//go:build windows

package scan

import (
	"unsafe"

	"freelocker/internal/appcontrol/signature"

	"golang.org/x/sys/windows"
)

// runningImpl enumerates running processes, resolves each full image path,
// and records the Authenticode hash plus the publisher identity of each
// distinct executable. Publisher lookup is best effort: a file we cannot
// parse is still reported, just without a publisher.
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
					o := Observed{SHA256: sum, Path: path}
					if info, err := signature.FromFile(path); err == nil {
						o.Signer, o.SignerTBS, o.SignerVerified = info.SubjectName, info.TBSHash, info.Verified
					}
					out = append(out, o)
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
