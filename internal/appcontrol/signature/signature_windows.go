//go:build windows

package signature

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrust           = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")
)

// WINTRUST_ACTION_GENERIC_VERIFY_V2
var actionGenericVerifyV2 = windows.GUID{
	Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

const (
	wtdUINone            = 2
	wtdRevokeNone        = 0
	wtdChoiceFile        = 1
	wtdStateActionVerify = 1
	wtdStateActionClose  = 2
	wtdSafer             = 0x100
	invalidHandle        = ^uintptr(0)
)

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject uintptr
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *wintrustFileInfo
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

// verify asks Windows whether path carries a valid, trusted Authenticode
// signature. Revocation checking is off so an offline machine still gets a
// usable answer; the publisher identity itself comes from the certificate.
func verify(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	fi := wintrustFileInfo{pcwszFilePath: p, hFile: windows.Handle(invalidHandle)}
	fi.cbStruct = uint32(unsafe.Sizeof(fi))
	d := wintrustData{
		dwUIChoice: wtdUINone, fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice: wtdChoiceFile, pFile: &fi,
		dwStateAction: wtdStateActionVerify, dwProvFlags: wtdSafer,
	}
	d.cbStruct = uint32(unsafe.Sizeof(d))

	rc, _, _ := procWinVerifyTrust.Call(invalidHandle,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&d)))

	// Release the provider's state data whatever the verdict.
	d.dwStateAction = wtdStateActionClose
	procWinVerifyTrust.Call(invalidHandle,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&d)))

	return rc == 0 // ERROR_SUCCESS: signed and trusted
}
