//go:build windows

package auth

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privateFileSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, string, error) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, "", fmt.Errorf("get current Windows user: %w", err)
	}
	userSID := tokenUser.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + userSID + ")",
	)
	if err != nil {
		return nil, "", fmt.Errorf("build private-file DACL: %w", err)
	}
	return descriptor, userSID, nil
}

func writePrivateFile(path string, data []byte) error {
	descriptor, _, err := privateFileSecurityDescriptor()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read private-file DACL: %w", err)
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode private-file path: %w", err)
	}
	securityAttributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateFile(
		pathUTF16,
		windows.GENERIC_WRITE|windows.WRITE_DAC,
		0,
		securityAttributes,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("open private file: %w", err)
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		windows.CloseHandle(handle)
		return fmt.Errorf("protect private-file DACL: %w", err)
	}

	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return fmt.Errorf("wrap private-file handle")
	}
	if err := file.Truncate(0); err != nil {
		file.Close()
		return fmt.Errorf("truncate private file: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return fmt.Errorf("seek private file: %w", err)
	}
	written, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write private file: %w", writeErr)
	}
	if written != len(data) {
		return fmt.Errorf("write private file: short write %d of %d bytes", written, len(data))
	}
	if closeErr != nil {
		return fmt.Errorf("close private file: %w", closeErr)
	}
	return nil
}

func checkPrivateFilePermissions(path string) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read private-file security descriptor: %w", err)
	}
	if descriptor == nil {
		return fmt.Errorf("private file has no security descriptor")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read private-file DACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private-file DACL inherits permissions")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read private-file DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("private file has no DACL")
	}
	if dacl.AceCount != 3 {
		return fmt.Errorf("private-file DACL contains %d access entries; want 3", dacl.AceCount)
	}

	_, userSIDString, err := privateFileSecurityDescriptor()
	if err != nil {
		return err
	}
	userSID, err := windows.StringToSid(userSIDString)
	if err != nil {
		return fmt.Errorf("parse current Windows user SID: %w", err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("create SYSTEM SID: %w", err)
	}
	administratorsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("create Administrators SID: %w", err)
	}

	type expectedTrustee struct {
		name string
		sid  *windows.SID
		seen bool
	}
	expected := []expectedTrustee{
		{name: "SYSTEM", sid: systemSID},
		{name: "Administrators", sid: administratorsSID},
		{name: "current user", sid: userSID},
	}
	const fileAllAccess windows.ACCESS_MASK = windows.STANDARD_RIGHTS_REQUIRED |
		windows.SYNCHRONIZE | 0x1ff

	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("read private-file DACL entry %d: %w", index, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("private-file DACL entry %d is not an allow entry", index)
		}
		if ace.Header.AceFlags != 0 {
			return fmt.Errorf("private-file DACL entry %d has unexpected inheritance flags", index)
		}
		if ace.Mask != fileAllAccess {
			return fmt.Errorf("private-file DACL entry %d does not grant full file access", index)
		}

		trusteeSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		matched := false
		for trusteeIndex := range expected {
			if !expected[trusteeIndex].sid.Equals(trusteeSID) {
				continue
			}
			if expected[trusteeIndex].seen {
				return fmt.Errorf("private-file DACL contains duplicate trustee %s", expected[trusteeIndex].name)
			}
			expected[trusteeIndex].seen = true
			matched = true
			break
		}
		if !matched {
			return fmt.Errorf("private-file DACL contains an unexpected trustee")
		}
	}
	for _, trustee := range expected {
		if !trustee.seen {
			return fmt.Errorf("private-file DACL is missing trustee %s", trustee.name)
		}
	}
	return nil
}
