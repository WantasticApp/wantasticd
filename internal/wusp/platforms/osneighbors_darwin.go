//go:build darwin

package platforms

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"wantastic-agent/internal/wusp/neighbors"
)

// osNeighborsSupported: macOS keeps its ARP and NDP caches in the routing
// table, which any process can read over the routing-socket sysctl.
const osNeighborsSupported = true

// macHostsPath is the hosts file a macOS resolver reads. It is the only
// already-cached name source the routing table can be joined against; the
// agent resolves nothing itself.
const macHostsPath = "/etc/hosts"

// osReadNeighborCache reads the macOS neighbor caches the way arp -an and
// ndp -an do: one sysctl per address family over the routing socket, asking
// for the routes that carry link-layer information (RTF_LLINFO).
//
// This is a read of a kernel table. No packet is sent, nothing is probed and
// nothing is resolved: the state of every entry is the kernel's own.
func osReadNeighborCache(ctx context.Context) (osNeighborReading, error) {
	hosts := neighbors.LoadHostsFile(macHostsPath)
	indexToName := interfaceNamesByIndex()
	now := time.Now()

	reading := osNeighborReading{
		Gateways: macDefaultGateways(indexToName),
		Aliases:  map[string]string{},
	}

	var firstErr error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		raw, err := unix.SysctlRaw("net", unix.AF_ROUTE, 0, family, unix.NET_RT_FLAGS, unix.RTF_LLINFO)
		if err != nil {
			// An empty cache for one family is reported by some kernel
			// versions as ENOENT; that is not a failure.
			if err != unix.ENOENT && firstErr == nil {
				firstErr = fmt.Errorf("read neighbor cache (family %d): %w", family, err)
			}
			continue
		}
		reading.Entries = append(reading.Entries, parseBSDNeighborTable(raw, indexToName, hosts, now)...)
	}
	if len(reading.Entries) == 0 && firstErr != nil {
		return osNeighborReading{}, firstErr
	}
	if firstErr != nil {
		reading.Status = neighbors.StatusOK
		reading.StatusDetail = firstErr.Error()
	}
	return reading, nil
}

// parseBSDNeighborTable decodes a NET_RT_FLAGS sysctl answer: a run of
// rt_msghdr records, each followed by the sockaddrs its rtm_addrs bitmask
// names. RTA_DST carries the neighbor's address, RTA_GATEWAY a sockaddr_dl
// with its link-layer address and interface index.
func parseBSDNeighborTable(raw []byte, indexToName map[int]string, hosts map[string]string, now time.Time) []neighbors.Entry {
	out := make([]neighbors.Entry, 0, 64)
	unixNow := now.Unix()
	for len(raw) >= unix.SizeofRtMsghdr {
		header := (*unix.RtMsghdr)(unsafe.Pointer(&raw[0]))
		length := int(header.Msglen)
		if length < unix.SizeofRtMsghdr || length > len(raw) {
			break
		}
		record := raw[:length]
		raw = raw[length:]
		if header.Version != unix.RTM_VERSION {
			continue
		}

		dst, link, ok := parseBSDNeighborAddrs(record[unix.SizeofRtMsghdr:], int(header.Addrs))
		if !ok || dst == nil {
			continue
		}
		name := indexToName[int(header.Index)]
		if link.index > 0 {
			if linkName := indexToName[link.index]; linkName != "" {
				name = linkName
			}
		}
		entry := neighbors.Entry{
			Interface: name,
			IP:        dst,
			MAC:       link.mac,
			State:     bsdNeighborState(header, len(link.mac) > 0, unixNow),
			Static:    header.Rmx.Expire == 0,
		}
		entry.HostName = neighbors.NameFor(hosts, dst)
		if entry.HostName != "" {
			entry.HostNameSource = "hosts"
		}
		// rmx_expire is when the kernel will drop the entry, which is also
		// the last time it confirmed it plus the cache lifetime. Only a
		// permanent entry has no expiry, and for the rest the collection
		// time is the honest answer, so LastSeen stays unset.
		out = append(out, entry)

		if len(out) >= 8*maxNeighborEntries {
			break
		}
	}
	return out
}

// bsdNeighborState turns a routing entry into the model's State enum, using
// exactly what arp(8) and ndp(8) read: an entry with no expiry is a static
// (permanent) one, an unexpired entry is the kernel's current answer, and an
// expired one is stale until the kernel re-confirms it.
func bsdNeighborState(header *unix.RtMsghdr, hasMAC bool, now int64) string {
	switch {
	case !hasMAC:
		return neighbors.StateIncomplete
	case header.Flags&unix.RTF_REJECT != 0:
		return neighbors.StateFailed
	case header.Rmx.Expire == 0:
		return neighbors.StatePermanent
	case int64(header.Rmx.Expire) > now:
		return neighbors.StateReachable
	default:
		return neighbors.StateStale
	}
}

// bsdLinkAddr is the useful part of a sockaddr_dl.
type bsdLinkAddr struct {
	index int
	mac   net.HardwareAddr
}

// parseBSDNeighborAddrs walks the sockaddrs that follow one rt_msghdr,
// returning the RTA_DST address and the RTA_GATEWAY link-layer address.
func parseBSDNeighborAddrs(buf []byte, addrs int) (net.IP, bsdLinkAddr, bool) {
	var dst net.IP
	var link bsdLinkAddr
	for bit := 0; bit < unix.RTAX_MAX; bit++ {
		mask := 1 << bit
		if addrs&mask == 0 {
			continue
		}
		if len(buf) < 2 {
			return nil, link, false
		}
		// sa_len of 0 means the minimum slot, and every slot is padded to a
		// multiple of 4 bytes.
		size := int(buf[0])
		step := bsdSockaddrStep(size)
		if step > len(buf) {
			return nil, link, false
		}
		slot := buf[:step]
		buf = buf[step:]
		switch mask {
		case unix.RTA_DST:
			dst = parseBSDSockaddrIP(slot)
		case unix.RTA_GATEWAY:
			link = parseBSDSockaddrLink(slot)
		}
	}
	return dst, link, true
}

// bsdSockaddrStep rounds a sockaddr length up the way the kernel lays the
// slots out: ROUNDUP(a) in the BSD routing code.
func bsdSockaddrStep(size int) int {
	if size <= 0 {
		return 4
	}
	return 1 + ((size - 1) | 3)
}

func parseBSDSockaddrIP(slot []byte) net.IP {
	if len(slot) < 2 {
		return nil
	}
	switch slot[1] {
	case unix.AF_INET:
		if len(slot) < 8 {
			return nil
		}
		return net.IPv4(slot[4], slot[5], slot[6], slot[7])
	case unix.AF_INET6:
		if len(slot) < 24 {
			return nil
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, slot[8:24])
		// A link-local address carries its scope in bytes 2-3 of the
		// address itself on BSD; clear it so the address reads normally.
		if ip[0] == 0xfe && ip[1]&0xc0 == 0x80 {
			ip[2], ip[3] = 0, 0
		}
		return ip
	default:
		return nil
	}
}

// parseBSDSockaddrLink decodes a sockaddr_dl. The link-layer address lives
// after the interface name inside the variable-length data area, so it is read
// by nlen/alen rather than by a fixed offset.
func parseBSDSockaddrLink(slot []byte) bsdLinkAddr {
	const dataOffset = 8 // sdl_len, sdl_family, sdl_index, sdl_type, sdl_nlen, sdl_alen, sdl_slen
	if len(slot) < dataOffset || slot[1] != unix.AF_LINK {
		return bsdLinkAddr{}
	}
	out := bsdLinkAddr{index: int(binary.NativeEndian.Uint16(slot[2:4]))}
	nlen, alen := int(slot[5]), int(slot[6])
	if alen <= 0 || alen > 16 {
		return out
	}
	start := dataOffset + nlen
	if start+alen > len(slot) {
		return out
	}
	out.mac = append(net.HardwareAddr(nil), slot[start:start+alen]...)
	return out
}

// macDefaultGateways reads the default route of each interface out of the
// routing table, so a neighbor that is one can report IsGateway.
func macDefaultGateways(indexToName map[int]string) map[string]string {
	out := map[string]string{}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		raw, err := unix.SysctlRaw("net", unix.AF_ROUTE, 0, family, unix.NET_RT_DUMP, 0)
		if err != nil {
			continue
		}
		for len(raw) >= unix.SizeofRtMsghdr {
			header := (*unix.RtMsghdr)(unsafe.Pointer(&raw[0]))
			length := int(header.Msglen)
			if length < unix.SizeofRtMsghdr || length > len(raw) {
				break
			}
			record := raw[:length]
			raw = raw[length:]
			if header.Version != unix.RTM_VERSION || header.Flags&unix.RTF_GATEWAY == 0 {
				continue
			}
			dst, gateway, ok := parseBSDRouteAddrs(record[unix.SizeofRtMsghdr:], int(header.Addrs))
			if !ok || dst == nil || gateway == nil || !dst.IsUnspecified() {
				continue
			}
			if name := indexToName[int(header.Index)]; name != "" && out[name] == "" {
				out[name] = gateway.String()
			}
		}
	}
	return out
}

// parseBSDRouteAddrs is parseBSDNeighborAddrs for a route whose gateway is an
// IP address rather than a link-layer one.
func parseBSDRouteAddrs(buf []byte, addrs int) (net.IP, net.IP, bool) {
	var dst, gateway net.IP
	for bit := 0; bit < unix.RTAX_MAX; bit++ {
		mask := 1 << bit
		if addrs&mask == 0 {
			continue
		}
		if len(buf) < 2 {
			return nil, nil, false
		}
		step := bsdSockaddrStep(int(buf[0]))
		if step > len(buf) {
			return nil, nil, false
		}
		slot := buf[:step]
		buf = buf[step:]
		switch mask {
		case unix.RTA_DST:
			dst = parseBSDSockaddrIP(slot)
		case unix.RTA_GATEWAY:
			gateway = parseBSDSockaddrIP(slot)
		}
	}
	return dst, gateway, true
}

// interfaceNamesByIndex maps a kernel interface index onto its BSD name.
func interfaceNamesByIndex() map[int]string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return map[int]string{}
	}
	out := make(map[int]string, len(ifaces))
	for _, iface := range ifaces {
		out[iface.Index] = iface.Name
	}
	return out
}
