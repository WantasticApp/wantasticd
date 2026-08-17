//go:build linux

package platforms

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestParseRouteNeighborMessageIPv4AndIPv6(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	for _, test := range []struct {
		name   string
		family byte
		ip     net.IP
	}{
		{name: "arp", family: unix.AF_INET, ip: net.ParseIP("192.0.2.10").To4()},
		{name: "ndp", family: unix.AF_INET6, ip: net.ParseIP("2001:db8::10").To16()},
	} {
		t.Run(test.name, func(t *testing.T) {
			attributes, err := netlink.MarshalAttributes([]netlink.Attribute{
				{Type: unix.NDA_DST, Data: test.ip},
				{Type: unix.NDA_LLADDR, Data: mac},
			})
			if err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 12, 12+len(attributes))
			data[0] = test.family
			binary.NativeEndian.PutUint32(data[4:8], 7)
			binary.NativeEndian.PutUint16(data[8:10], unix.NUD_REACHABLE)
			data = append(data, attributes...)
			observation, ok, err := parseRouteNeighborMessage(data, map[int]string{7: "br-lan"})
			if err != nil || !ok {
				t.Fatalf("parse ok=%t err=%v", ok, err)
			}
			if !observation.IP.Equal(test.ip) || observation.MAC.String() != mac.String() || observation.InterfaceName != "br-lan" || !observation.Active {
				t.Fatalf("observation=%+v", observation)
			}
		})
	}
}
