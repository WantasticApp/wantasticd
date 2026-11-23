//go:build windows

package platforms

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"wantastic-agent/internal/wusp/neighbors"
)

// osNeighborsSupported: Windows keeps one neighbor table for both address
// families in the IP Helper API, readable without privileges.
const osNeighborsSupported = true

var (
	modIphlpapi        = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable2 = modIphlpapi.NewProc("GetIpNetTable2")
	procFreeMibTable   = modIphlpapi.NewProc("FreeMibTable")
)

// NL_NEIGHBOR_STATE (nldef.h): the kernel's own verdict on each entry.
const (
	nlnsUnreachable = 0
	nlnsIncomplete  = 1
	nlnsProbe       = 2
	nlnsDelay       = 3
	nlnsStale       = 4
	nlnsReachable   = 5
	nlnsPermanent   = 6
)

// mibIPNetRow2 mirrors MIB_IPNET_ROW2 (netioapi.h). The Address field is a
// SOCKADDR_INET union, read by family below.
type mibIPNetRow2 struct {
	Address               [28]byte
	InterfaceIndex        uint32
	InterfaceLuid         uint64
	PhysicalAddress       [32]byte
	PhysicalAddressLength uint32
	State                 uint32
	Flags                 uint8
	_                     [3]byte
	ReachabilityTime      uint32
}

// isRouter is the first bit of the MIB_IPNET_ROW2 flags union.
func (r *mibIPNetRow2) isRouter() bool { return r.Flags&0x01 != 0 }

// isUnreachable is the second bit of the same union.
func (r *mibIPNetRow2) isUnreachable() bool { return r.Flags&0x02 != 0 }

// mibIPNetTable2 mirrors MIB_IPNET_TABLE2; Table is a variable-length array.
type mibIPNetTable2 struct {
	NumEntries uint32
	_          uint32
	Table      [1]mibIPNetRow2
}

// osReadNeighborCache reads the IP Helper neighbor table, the same table
// Get-NetNeighbor shows. It is a read of a kernel table: no probe, no ping,
// no scan, and the state of every entry is the kernel's own.
func osReadNeighborCache(ctx context.Context) (osNeighborReading, error) {
	var table *mibIPNetTable2
	rc, _, _ := procGetIpNetTable2.Call(uintptr(windows.AF_UNSPEC), uintptr(unsafe.Pointer(&table)))
	if rc != 0 {
		return osNeighborReading{}, errors.New("GetIpNetTable2: " + windows.Errno(rc).Error())
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))
	if table == nil {
		return osNeighborReading{}, errors.New("GetIpNetTable2 returned no table")
	}

	hosts := neighbors.LoadHostsFile(windowsHostsPath())
	adapters := windowsNeighborAdapters()
	indexToName := make(map[uint32]string, len(adapters))
	reading := osNeighborReading{
		Gateways: make(map[string]string, len(adapters)),
		Aliases:  make(map[string]string, len(adapters)),
		Types:    make(map[string]string, len(adapters)),
	}
	for _, adapter := range adapters {
		indexToName[adapter.index] = adapter.name
		if adapter.gateway != "" {
			reading.Gateways[adapter.name] = adapter.gateway
		}
		reading.Aliases[adapter.name] = adapter.description
		reading.Types[adapter.name] = adapter.kind
	}

	count := int(table.NumEntries)
	if count > 8*maxNeighborEntries {
		count = 8 * maxNeighborEntries
	}
	rows := unsafe.Slice(&table.Table[0], count)
	reading.Entries = make([]neighbors.Entry, 0, count)
	for i := range rows {
		row := &rows[i]
		ip := parseSockaddrInet(row.Address[:])
		if ip == nil {
			continue
		}
		var mac net.HardwareAddr
		if n := int(row.PhysicalAddressLength); n > 0 && n <= len(row.PhysicalAddress) {
			mac = append(net.HardwareAddr(nil), row.PhysicalAddress[:n]...)
		}
		entry := neighbors.Entry{
			Interface: indexToName[row.InterfaceIndex],
			IP:        ip,
			MAC:       mac,
			State:     windowsNeighborState(row),
			Static:    row.State == nlnsPermanent,
			IsRouter:  row.isRouter(),
		}
		if entry.HostName = neighbors.NameFor(hosts, ip); entry.HostName != "" {
			entry.HostNameSource = "hosts"
		}
		reading.Entries = append(reading.Entries, entry)
	}
	return reading, nil
}

// windowsNeighborState maps NL_NEIGHBOR_STATE onto the model's State enum.
func windowsNeighborState(row *mibIPNetRow2) string {
	switch row.State {
	case nlnsReachable:
		return neighbors.StateReachable
	case nlnsPermanent:
		return neighbors.StatePermanent
	case nlnsStale:
		return neighbors.StateStale
	case nlnsDelay:
		return neighbors.StateDelay
	case nlnsProbe:
		return neighbors.StateProbe
	case nlnsIncomplete:
		return neighbors.StateIncomplete
	case nlnsUnreachable:
		return neighbors.StateFailed
	default:
		if row.isUnreachable() {
			return neighbors.StateFailed
		}
		return ""
	}
}

// parseSockaddrInet reads the address out of a SOCKADDR_INET union.
func parseSockaddrInet(buf []byte) net.IP {
	if len(buf) < 4 {
		return nil
	}
	family := uint16(buf[0]) | uint16(buf[1])<<8
	switch family {
	case windows.AF_INET:
		if len(buf) < 8 {
			return nil
		}
		return net.IPv4(buf[4], buf[5], buf[6], buf[7])
	case windows.AF_INET6:
		if len(buf) < 24 {
			return nil
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, buf[8:24])
		return ip
	default:
		return nil
	}
}

// windowsNeighborAdapter is the interface metadata the neighbor table does
// not carry: the connection name neighbors are reported against, the
// friendlier description, the medium and the default gateway.
type windowsNeighborAdapter struct {
	index       uint32
	name        string
	description string
	kind        string
	gateway     string
}

func windowsNeighborAdapters() []windowsNeighborAdapter {
	size := uint32(32 << 10)
	var buf []byte
	for attempt := 0; attempt < 3; attempt++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil
		}
		buf = nil
	}
	if buf == nil {
		return nil
	}
	var out []windowsNeighborAdapter
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		adapter := windowsNeighborAdapter{
			index:       a.IfIndex,
			name:        windows.UTF16PtrToString(a.FriendlyName),
			description: windows.UTF16PtrToString(a.Description),
			kind:        windowsInterfaceKind(a.IfType),
		}
		if a.IfIndex == 0 {
			adapter.index = a.Ipv6IfIndex
		}
		for gateway := a.FirstGatewayAddress; gateway != nil; gateway = gateway.Next {
			if ip := gateway.Address.IP(); ip != nil {
				adapter.gateway = ip.String()
				break
			}
		}
		out = append(out, adapter)
	}
	return out
}

// windowsInterfaceKind maps an IANA ifType onto the model's Interface.{i}.Type
// enum.
func windowsInterfaceKind(ifType uint32) string {
	switch ifType {
	case windows.IF_TYPE_ETHERNET_CSMACD:
		return "ethernet"
	case windows.IF_TYPE_IEEE80211:
		return "wifi"
	case windows.IF_TYPE_TUNNEL:
		return "vpn"
	case windows.IF_TYPE_SOFTWARE_LOOPBACK, 53: // 53: IF_TYPE_PROP_VIRTUAL
		return "virtual"
	case 243, 244: // IF_TYPE_WWANPP, IF_TYPE_WWANPP2
		return "cellular"
	case 209: // IF_TYPE_BRIDGE
		return "bridge"
	default:
		return "other"
	}
}

// windowsHostsPath is where a Windows resolver reads static names.
func windowsHostsPath() string {
	root := os.Getenv("SystemRoot")
	if strings.TrimSpace(root) == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}
