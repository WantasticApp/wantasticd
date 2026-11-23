//go:build darwin

package platforms

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"wantastic-agent/internal/wusp/neighbors"
)

// sockaddrIn builds the 16-byte sockaddr_in the routing socket puts in the
// RTA_DST slot of an ARP entry.
func sockaddrIn(ip net.IP) []byte {
	slot := make([]byte, 16)
	slot[0] = 16
	slot[1] = unix.AF_INET
	copy(slot[4:8], ip.To4())
	return slot
}

// sockaddrIn6 builds the 28-byte sockaddr_in6 of an NDP entry.
func sockaddrIn6(ip net.IP) []byte {
	slot := make([]byte, 28)
	slot[0] = 28
	slot[1] = unix.AF_INET6
	copy(slot[8:24], ip.To16())
	return slot
}

// sockaddrDl builds the sockaddr_dl the RTA_GATEWAY slot carries: the
// interface index, the interface name and then the link-layer address, which
// is why the MAC is read by nlen/alen rather than at a fixed offset.
func sockaddrDl(index uint16, name string, mac net.HardwareAddr) []byte {
	body := make([]byte, 8+len(name)+len(mac))
	body[0] = byte(len(body))
	body[1] = unix.AF_LINK
	binary.NativeEndian.PutUint16(body[2:4], index)
	body[4] = 6 // IFT_ETHER
	body[5] = byte(len(name))
	body[6] = byte(len(mac))
	copy(body[8:], name)
	copy(body[8+len(name):], mac)
	// The kernel pads every slot up to a multiple of four bytes.
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	return body
}

// routingRecord assembles one rt_msghdr followed by its sockaddr slots, the
// shape a NET_RT_FLAGS sysctl answer is a run of.
func routingRecord(index uint16, flags, expire int32, dst, gateway []byte) []byte {
	header := unix.RtMsghdr{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Index:   index,
		Flags:   flags,
		Addrs:   unix.RTA_DST | unix.RTA_GATEWAY,
	}
	header.Rmx.Expire = expire
	header.Msglen = uint16(unix.SizeofRtMsghdr + len(dst) + len(gateway))

	out := make([]byte, 0, int(header.Msglen))
	out = append(out, unsafe.Slice((*byte)(unsafe.Pointer(&header)), unix.SizeofRtMsghdr)...)
	out = append(out, dst...)
	out = append(out, gateway...)
	return out
}

func TestParseBSDNeighborTable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	names := map[int]string{4: "en0", 7: "en7"}
	hosts := map[string]string{"192.168.1.1": "gateway.lan"}
	mac := net.HardwareAddr{0xe0, 0x5d, 0x54, 0x11, 0x22, 0x33}

	var raw []byte
	// A static entry: no expiry at all.
	raw = append(raw, routingRecord(4, 0, 0,
		sockaddrIn(net.ParseIP("192.168.1.1")), sockaddrDl(4, "en0", mac))...)
	// An entry the kernel confirmed recently: its expiry is in the future.
	raw = append(raw, routingRecord(4, 0, int32(now.Unix()+600),
		sockaddrIn(net.ParseIP("192.168.1.24")), sockaddrDl(4, "en0", net.HardwareAddr{0x02, 1, 2, 3, 4, 5}))...)
	// An entry past its expiry: usable but not confirmed lately.
	raw = append(raw, routingRecord(7, 0, int32(now.Unix()-60),
		sockaddrIn(net.ParseIP("10.1.1.9")), sockaddrDl(7, "en7", net.HardwareAddr{0x02, 9, 9, 9, 9, 9}))...)
	// An IPv6 entry the kernel has no answer for yet: no link-layer address.
	raw = append(raw, routingRecord(4, 0, int32(now.Unix()+60),
		sockaddrIn6(net.ParseIP("fe80::abcd")), sockaddrDl(4, "en0", nil))...)
	// An entry the kernel gave up on.
	raw = append(raw, routingRecord(4, unix.RTF_REJECT, int32(now.Unix()+60),
		sockaddrIn(net.ParseIP("192.168.1.77")), sockaddrDl(4, "en0", net.HardwareAddr{0x02, 7, 7, 7, 7, 7}))...)

	entries := parseBSDNeighborTable(raw, names, hosts, now)
	if len(entries) != 5 {
		t.Fatalf("expected five entries, got %d: %+v", len(entries), entries)
	}

	static := entries[0]
	if static.Interface != "en0" {
		t.Fatalf("Interface = %q, want en0", static.Interface)
	}
	if static.IP.String() != "192.168.1.1" {
		t.Fatalf("IP = %s", static.IP)
	}
	if static.MAC.String() != mac.String() {
		t.Fatalf("MAC = %s, want %s", static.MAC, mac)
	}
	if static.State != neighbors.StatePermanent || !static.Static {
		t.Fatalf("an entry with no expiry is a static one: %+v", static)
	}
	// The hosts file is the only already-cached name source; the agent
	// resolves nothing itself.
	if static.HostName != "gateway.lan" || static.HostNameSource != "hosts" {
		t.Fatalf("hosts-file name was not joined: %+v", static)
	}

	if entries[1].State != neighbors.StateReachable {
		t.Fatalf("an unexpired entry is the kernel's current answer, got %q", entries[1].State)
	}
	if entries[2].State != neighbors.StateStale || entries[2].Interface != "en7" {
		t.Fatalf("an expired entry is stale on its own interface: %+v", entries[2])
	}
	if entries[3].State != neighbors.StateIncomplete || len(entries[3].MAC) != 0 {
		t.Fatalf("an entry with no link-layer address is incomplete: %+v", entries[3])
	}
	if entries[3].IP.String() != "fe80::abcd" {
		t.Fatalf("IPv6 address = %s", entries[3].IP)
	}
	if entries[4].State != neighbors.StateFailed {
		t.Fatalf("a rejected entry has failed, got %q", entries[4].State)
	}
	// Nothing here reports a timestamp of its own: LastSeen is left for the
	// collection time, because an expiry is not a confirmation time.
	for _, entry := range entries {
		if entry.LastSeen != 0 {
			t.Fatalf("entry claims a confirmation time it does not have: %+v", entry)
		}
	}
}

// A truncated or foreign record stops the walk instead of reading past it.
func TestParseBSDNeighborTableRejectsBadInput(t *testing.T) {
	now := time.Unix(10, 0)
	if got := parseBSDNeighborTable(nil, nil, nil, now); len(got) != 0 {
		t.Fatalf("an empty buffer produced %d entries", len(got))
	}
	if got := parseBSDNeighborTable(make([]byte, 7), nil, nil, now); len(got) != 0 {
		t.Fatalf("a short buffer produced %d entries", len(got))
	}
	// A record claiming to be longer than the buffer is dropped.
	record := routingRecord(4, 0, 0, sockaddrIn(net.ParseIP("10.0.0.1")), sockaddrDl(4, "en0", net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	binary.NativeEndian.PutUint16(record[0:2], uint16(len(record)+40))
	if got := parseBSDNeighborTable(record, nil, nil, now); len(got) != 0 {
		t.Fatalf("an over-long record produced %d entries", len(got))
	}
	// A record from a protocol version this agent does not speak is skipped.
	record = routingRecord(4, 0, 0, sockaddrIn(net.ParseIP("10.0.0.1")), sockaddrDl(4, "en0", net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	record[2] = unix.RTM_VERSION + 99
	if got := parseBSDNeighborTable(record, nil, nil, now); len(got) != 0 {
		t.Fatalf("a foreign routing version produced %d entries", len(got))
	}
}

func TestBSDSockaddrStep(t *testing.T) {
	for size, want := range map[int]int{0: 4, 1: 4, 4: 4, 5: 8, 16: 16, 17: 20, 20: 20, 28: 28} {
		if got := bsdSockaddrStep(size); got != want {
			t.Fatalf("bsdSockaddrStep(%d) = %d, want %d", size, got, want)
		}
	}
}

// The interface table only reports interfaces the model's Type enum knows.
func TestNeighborInterfaceTypeStaysInTheEnum(t *testing.T) {
	allowed := map[string]bool{"": true, "ethernet": true, "wifi": true, "bridge": true,
		"vpn": true, "virtual": true, "cellular": true, "other": true}
	iface := net.Interface{Name: "en0", HardwareAddr: net.HardwareAddr{1, 2, 3, 4, 5, 6}}
	for _, osKind := range []string{"", "ethernet", "wifi", "something-else"} {
		if got := neighborInterfaceType(iface, nil, osKind); !allowed[got] {
			t.Fatalf("neighborInterfaceType(%q) = %q, outside the enum", osKind, got)
		}
	}
	for _, name := range []string{"en0", "bridge100", "utun4", "pdp_ip0", "awdl0", "llw0", "wg0"} {
		got := neighborInterfaceType(net.Interface{Name: name}, nil, "")
		if !allowed[got] {
			t.Fatalf("interface %s classified as %q, outside the enum", name, got)
		}
	}
}
