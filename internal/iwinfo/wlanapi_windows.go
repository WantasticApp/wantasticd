//go:build windows

package iwinfo

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Native Wifi API (wlanapi.dll), loaded lazily so systems without the WLAN
// service still start. Documented at
// https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/.

var (
	modWlanapi                     = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle             = modWlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle            = modWlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces         = modWlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface         = modWlanapi.NewProc("WlanQueryInterface")
	procWlanGetInterfaceCapability = modWlanapi.NewProc("WlanGetInterfaceCapability")
	procWlanFreeMemory             = modWlanapi.NewProc("WlanFreeMemory")
)

const (
	wlanOpcodeCurrentConnection = 7
	wlanOpcodeChannelNumber     = 8
	wlanOpcodeRSSI              = 0x10000102 // wlan_intf_opcode_msm_start + 2
)

type wlanClient struct{ handle windows.Handle }

func openWlanClient() (*wlanClient, error) {
	if err := procWlanOpenHandle.Find(); err != nil {
		return nil, err
	}
	var negotiated uint32
	var handle windows.Handle
	r, _, _ := procWlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle)))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	return &wlanClient{handle: handle}, nil
}

func (c *wlanClient) close() { _, _, _ = procWlanCloseHandle.Call(uintptr(c.handle), 0) }

// copyAndFree copies size bytes of a wlanapi allocation and releases it.
func copyAndFree(p *byte, size int) []byte {
	if p == nil || size <= 0 {
		return nil
	}
	out := append([]byte(nil), unsafe.Slice(p, size)...)
	_, _, _ = procWlanFreeMemory.Call(uintptr(unsafe.Pointer(p)))
	return out
}

func (c *wlanClient) interfaces() ([]wlanInterface, error) {
	var list *byte
	r, _, _ := procWlanEnumInterfaces.Call(uintptr(c.handle), 0, uintptr(unsafe.Pointer(&list)))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	count := int(*(*uint32)(unsafe.Pointer(list)))
	if count > 64 {
		count = 64
	}
	return decodeWlanInterfaceList(copyAndFree(list, 8+count*wlanInterfaceInfoSize)), nil
}

func (c *wlanClient) query(guid *[16]byte, opcode uint32) ([]byte, error) {
	var size uint32
	var data *byte
	r, _, _ := procWlanQueryInterface.Call(uintptr(c.handle), uintptr(unsafe.Pointer(guid)), uintptr(opcode), 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0)
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	return copyAndFree(data, int(size)), nil
}

// friendlyNames maps adapter GUIDs ("{…}") to their friendly names (Wi-Fi).
func friendlyNames() map[string]string {
	names := map[string]string{}
	size := uint32(15000)
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return names
		}
		for a := first; a != nil; a = a.Next {
			names[strings.ToUpper(windows.BytePtrToString(a.AdapterName))] = windows.UTF16PtrToString(a.FriendlyName)
		}
		return names
	}
	return names
}

// findWlanInterface picks the interface named ifname (friendly name or
// description), or the only Wi-Fi interface when ifname matches none.
func (c *wlanClient) findWlanInterface(ifname string) (wlanInterface, bool) {
	ifaces, err := c.interfaces()
	if err != nil || len(ifaces) == 0 {
		return wlanInterface{}, false
	}
	names := friendlyNames()
	for _, iface := range ifaces {
		guid := strings.ToUpper((*windows.GUID)(unsafe.Pointer(&iface.guid)).String())
		if strings.EqualFold(names[guid], ifname) || strings.EqualFold(iface.description, ifname) {
			return iface, true
		}
	}
	if len(ifaces) == 1 {
		return ifaces[0], true
	}
	return wlanInterface{}, false
}

func wlanInterfaceAvailable(ifname string) (wlanInterface, bool) {
	c, err := openWlanClient()
	if err != nil {
		return wlanInterface{}, false
	}
	defer c.close()
	return c.findWlanInterface(ifname)
}

func wlanGetInfo(ifname string) (*InterfaceInfo, error) {
	c, err := openWlanClient()
	if err != nil {
		return nil, err
	}
	defer c.close()
	iface, ok := c.findWlanInterface(ifname)
	if !ok {
		return nil, errors.New("no WLAN interface " + ifname)
	}
	info := &InterfaceInfo{Name: ifname, PHYName: iface.description}
	if rssi, err := c.query(&iface.guid, wlanOpcodeRSSI); err == nil && len(rssi) >= 4 {
		info.Signal = int(int32(*(*uint32)(unsafe.Pointer(&rssi[0]))))
	}
	if attrs, err := c.query(&iface.guid, wlanOpcodeCurrentConnection); err == nil {
		applyWlanConnection(attrs, info)
	}
	if channel, err := c.query(&iface.guid, wlanOpcodeChannelNumber); err == nil && len(channel) >= 4 {
		info.Channel = int(*(*uint32)(unsafe.Pointer(&channel[0])))
		info.Frequency = channelFrequency(info.Channel)
	}
	return info, nil
}

func wlanGetHWModes(ifname string) (*HWModes, error) {
	c, err := openWlanClient()
	if err != nil {
		return nil, err
	}
	defer c.close()
	iface, ok := c.findWlanInterface(ifname)
	if !ok {
		return nil, errors.New("no WLAN interface " + ifname)
	}
	var data *byte
	r, _, _ := procWlanGetInterfaceCapability.Call(uintptr(c.handle), uintptr(unsafe.Pointer(&iface.guid)), 0, uintptr(unsafe.Pointer(&data)))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	// WLAN_INTERFACE_CAPABILITY: 5 DWORD-sized fields then dot11PhyTypes[64].
	modes := decodeWlanPhyTypes(copyAndFree(data, 20+64*4))
	if modes == nil {
		return nil, errors.New("no WLAN capability data")
	}
	return modes, nil
}
