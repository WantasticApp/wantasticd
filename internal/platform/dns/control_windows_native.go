//go:build windows

package dns

import (
	"errors"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Native Windows DNS control: GetAdaptersAddresses for the default adapter
// and its effective resolvers, the Tcpip registry keys for static ones, and
// SetInterfaceDnsSettings (Windows 10 2004+) to apply. PowerShell's
// DnsClient module remains the fallback on older systems.

var (
	modIphlpapi                 = windows.NewLazySystemDLL("iphlpapi.dll")
	procSetInterfaceDnsSettings = modIphlpapi.NewProc("SetInterfaceDnsSettings")
	modDnsapi                   = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache   = modDnsapi.NewProc("DnsFlushResolverCache")
)

const (
	dnsSettingIPv6       = 0x0001
	dnsSettingNameserver = 0x0002
)

// dnsInterfaceSettings is DNS_INTERFACE_SETTINGS (version 1). MSVC aligns
// the ULONG64 Flags to 8 bytes on every architecture while Go's 386 port
// aligns uint64 to 4, so the padding and the two halves are explicit.
type dnsInterfaceSettings struct {
	Version             uint32
	_                   uint32
	FlagsLow            uint32
	FlagsHigh           uint32
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

type windowsAdapter struct {
	index     uint32
	guid      string // "{…}"
	effective []string
}

// defaultAdapter returns the up adapter with a gateway and the lowest IPv4
// metric, i.e. the one carrying the default route.
func defaultAdapter() (windowsAdapter, error) {
	size := uint32(15000)
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return windowsAdapter{}, err
		}
		var best *windows.IpAdapterAddresses
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp || a.FirstGatewayAddress == nil {
				continue
			}
			if best == nil || a.Ipv4Metric < best.Ipv4Metric {
				best = a
			}
		}
		if best == nil {
			return windowsAdapter{}, errors.New("no default route adapter")
		}
		out := windowsAdapter{index: best.IfIndex, guid: windows.BytePtrToString(best.AdapterName)}
		for d := best.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip := d.Address.IP(); ip != nil {
				out.effective = append(out.effective, ip.String())
			}
		}
		return out, nil
	}
	return windowsAdapter{}, errors.New("adapter list kept growing")
}

// staticServers reads the NameServer values Windows stores for manual DNS.
func staticServers(guid string) []string {
	var out []string
	for _, base := range []string{`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`, `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\`} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, base+guid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		value, _, err := key.GetStringValue("NameServer")
		key.Close()
		if err == nil {
			out = append(out, strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' })...)
		}
	}
	return out
}

func nativeReadControl() (ControlState, error) {
	adapter, err := defaultAdapter()
	if err != nil {
		return ControlState{}, err
	}
	st := ControlState{Supported: true, Method: "windows-dnsclient", Effective: adapter.effective}
	if servers := staticServers(adapter.guid); len(servers) > 0 {
		st.Manual, st.Servers = true, servers
	}
	return st, nil
}

// nativeSetServers applies servers (or automatic DNS when empty) per address
// family. It returns errNativeUnavailable before Windows 10 2004.
func nativeSetServers(servers []string) error {
	if err := procSetInterfaceDnsSettings.Find(); err != nil {
		return errNativeUnavailable
	}
	adapter, err := defaultAdapter()
	if err != nil {
		return err
	}
	guid, err := windows.GUIDFromString(adapter.guid)
	if err != nil {
		return err
	}
	var v4, v6 []string
	for _, server := range servers {
		if ip := net.ParseIP(server); ip != nil && ip.To4() == nil {
			v6 = append(v6, server)
		} else {
			v4 = append(v4, server)
		}
	}
	for _, family := range []struct {
		flags   uint64
		servers []string
	}{{dnsSettingNameserver, v4}, {dnsSettingNameserver | dnsSettingIPv6, v6}} {
		list, err := windows.UTF16PtrFromString(strings.Join(family.servers, ","))
		if err != nil {
			return err
		}
		settings := dnsInterfaceSettings{Version: 1, FlagsLow: uint32(family.flags), FlagsHigh: uint32(family.flags >> 32), NameServer: list}
		if r := setInterfaceDNS(&guid, &settings); r != 0 {
			return windows.Errno(r)
		}
	}
	_, _, _ = procDnsFlushResolverCache.Call()
	return nil
}

var errNativeUnavailable = errors.New("native DNS API unavailable")
