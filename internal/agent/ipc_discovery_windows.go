//go:build windows

package agent

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func protectIPCDiscovery(data []byte) ([]byte, error) {
	return transformIPCDiscovery(data, true)
}

func unprotectIPCDiscovery(data []byte) ([]byte, error) {
	return transformIPCDiscovery(data, false)
}

func transformIPCDiscovery(data []byte, protect bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("IPC discovery data is empty")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	if out.Data == nil || out.Size == 0 {
		return nil, fmt.Errorf("Windows DPAPI returned empty data")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	result := make([]byte, int(out.Size))
	copy(result, unsafe.Slice(out.Data, int(out.Size)))
	return result, nil
}
