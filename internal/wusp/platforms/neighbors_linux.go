//go:build linux

package platforms

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type linuxNeighborObservation struct {
	IP            net.IP
	MAC           net.HardwareAddr
	InterfaceName string
	State         uint16
	Active        bool
}

// readRouteNeighbors performs one RTM_GETNEIGH dump. It covers both the IPv4
// ARP and IPv6 NDP tables without depending on iproute2 being installed.
func readRouteNeighbors() ([]linuxNeighborObservation, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, fmt.Errorf("open route netlink: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// struct ndmsg is 12 bytes and contains AF_UNSPEC followed by zeroes for a
	// complete neighbor-table dump.
	data := make([]byte, 12)
	data[0] = unix.AF_UNSPEC
	messages, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.RTM_GETNEIGH),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	})
	if err != nil {
		return nil, fmt.Errorf("RTM_GETNEIGH: %w", err)
	}
	ifaces, _ := net.Interfaces()
	ifNameByIndex := make(map[int]string, len(ifaces))
	for _, iface := range ifaces {
		ifNameByIndex[iface.Index] = iface.Name
	}

	out := make([]linuxNeighborObservation, 0, len(messages))
	for _, message := range messages {
		observation, ok, parseErr := parseRouteNeighborMessage(message.Data, ifNameByIndex)
		if parseErr != nil {
			return nil, parseErr
		}
		if ok {
			out = append(out, observation)
		}
	}
	return out, nil
}

func parseRouteNeighborMessage(data []byte, ifNameByIndex map[int]string) (linuxNeighborObservation, bool, error) {
	if len(data) < 12 {
		return linuxNeighborObservation{}, false, fmt.Errorf("short RTM_NEWNEIGH payload: %d", len(data))
	}
	family := data[0]
	if family != unix.AF_INET && family != unix.AF_INET6 {
		return linuxNeighborObservation{}, false, nil
	}
	ifIndex := int(int32(binary.NativeEndian.Uint32(data[4:8])))
	state := binary.NativeEndian.Uint16(data[8:10])
	decoder, err := netlink.NewAttributeDecoder(data[12:])
	if err != nil {
		return linuxNeighborObservation{}, false, fmt.Errorf("decode RTM_NEWNEIGH attributes: %w", err)
	}
	var ip net.IP
	var mac net.HardwareAddr
	for decoder.Next() {
		switch decoder.Type() {
		case unix.NDA_DST:
			raw := append([]byte(nil), decoder.Bytes()...)
			if family == unix.AF_INET && len(raw) >= net.IPv4len {
				ip = net.IP(raw[:net.IPv4len])
			} else if family == unix.AF_INET6 && len(raw) >= net.IPv6len {
				ip = net.IP(raw[:net.IPv6len])
			}
		case unix.NDA_LLADDR:
			raw := decoder.Bytes()
			if len(raw) == 6 {
				mac = append(net.HardwareAddr(nil), raw...)
			}
		}
	}
	if err := decoder.Err(); err != nil {
		return linuxNeighborObservation{}, false, fmt.Errorf("decode RTM_NEWNEIGH attribute: %w", err)
	}
	if ip == nil || validClientMAC(mac.String()) == nil {
		return linuxNeighborObservation{}, false, nil
	}
	return linuxNeighborObservation{
		IP:            ip,
		MAC:           mac,
		InterfaceName: ifNameByIndex[ifIndex],
		State:         state,
		Active:        state&(unix.NUD_FAILED|unix.NUD_INCOMPLETE) == 0 && state != unix.NUD_NONE,
	}, true, nil
}
