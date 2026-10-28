package portmap

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

// defaultGateway returns the IPv4 default gateway. Linux (including OpenWrt)
// reads the kernel routing table; elsewhere NAT-PMP is skipped and UPnP
// (which discovers the gateway itself) is used.
func defaultGateway() (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	defer f.Close()
	return parseProcNetRoute(f)
}

// parseProcNetRoute finds the default route's gateway in /proc/net/route
// format: the address printed as a host-order integer, so its bytes are read
// back in the CPU's own order (big-endian MIPS routers included).
func parseProcNetRoute(r io.Reader) (netip.Addr, error) {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		var ip [4]byte
		binary.NativeEndian.PutUint32(ip[:], binary.BigEndian.Uint32(raw))
		addr := netip.AddrFrom4(ip)
		if addr.IsUnspecified() {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, errors.New("no default IPv4 gateway")
}

// localIPFor returns the local address the system uses to reach dst.
func localIPFor(dst netip.Addr) (netip.Addr, error) {
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	return local, nil
}
