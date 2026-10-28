package portmap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// NAT-PMP (RFC 6886): ask the gateway on UDP 5351 to forward an external UDP
// port to ours. Two tiny request/response exchanges; no discovery needed
// beyond the default gateway.

var natpmpPort uint16 = 5351 // variable for tests

var errNATPMPUnsupported = errors.New("gateway does not answer NAT-PMP")

// natpmpExchange sends req to the gateway and returns the response, retrying
// with the RFC's doubling timeout (250ms, 500ms).
func natpmpExchange(gateway netip.Addr, req []byte, wantOp byte) ([]byte, error) {
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(gateway, natpmpPort)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	buf := make([]byte, 16)
	for timeout := 250 * time.Millisecond; timeout <= 500*time.Millisecond; timeout *= 2 {
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		resp := buf[:n]
		if len(resp) < 8 || resp[0] != 0 || resp[1] != wantOp {
			continue
		}
		if code := binary.BigEndian.Uint16(resp[2:4]); code != 0 {
			return nil, fmt.Errorf("NAT-PMP result code %d", code)
		}
		return append([]byte(nil), resp...), nil
	}
	return nil, errNATPMPUnsupported
}

// natpmpMap maps internalPort and returns the external address and lease.
// lifetime 0 deletes the mapping.
func natpmpMap(gateway netip.Addr, internalPort uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	resp, err := natpmpExchange(gateway, []byte{0, 0}, 128)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	if len(resp) < 12 {
		return netip.AddrPort{}, 0, errors.New("short NAT-PMP address response")
	}
	external := netip.AddrFrom4([4]byte(resp[8:12]))

	req := make([]byte, 12)
	req[1] = 1 // map UDP
	binary.BigEndian.PutUint16(req[4:6], internalPort)
	binary.BigEndian.PutUint16(req[6:8], internalPort) // suggested external port
	binary.BigEndian.PutUint32(req[8:12], uint32(lifetime/time.Second))
	resp, err = natpmpExchange(gateway, req, 129)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	if len(resp) < 16 {
		return netip.AddrPort{}, 0, errors.New("short NAT-PMP mapping response")
	}
	port := binary.BigEndian.Uint16(resp[10:12])
	lease := time.Duration(binary.BigEndian.Uint32(resp[12:16])) * time.Second
	return netip.AddrPortFrom(external, port), lease, nil
}

var errNotPublic = errors.New("router's external address is not public (CGNAT)")
