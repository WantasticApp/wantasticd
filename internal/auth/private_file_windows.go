//go:build windows

package auth

import (
	"fmt"
	"os"
	"strings"
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
	_, userSID, err := privateFileSecurityDescriptor()
	if err != nil {
		return err
	}
	sddl := descriptor.String()
	if sddl == "" {
		return fmt.Errorf("encode private-file security descriptor")
	}
	if strings.Count(sddl, "(") != 3 || strings.Contains(sddl, "(D;") {
		return fmt.Errorf("private-file DACL contains unexpected access entries")
	}
	for _, trustee := range []string{"SY", "BA", userSID} {
		if !strings.Contains(sddl, ";;;"+trustee+")") {
			return fmt.Errorf("private-file DACL is missing trustee %s", trustee)
		}
	}
	return nil
}
