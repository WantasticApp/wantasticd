//go:build linux

package linkdiscovery

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	etherTypeLLDP = 0x88cc
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88a8
	mndpPort      = 5678
)

func startPlatformListeners(m *Monitor) {
	if fd, err := openLLDPSocket(); err == nil {
		m.markLLDPStarted(time.Now())
		go safelyRunListener("LLDP", m.markLLDPStopped, func() { receiveLLDP(m, fd) })
	}
	if conn, packetConn, err := openMNDPSocket(); err == nil {
		m.markMNDPStarted(time.Now())
		go safelyRunListener("MNDP", m.markMNDPStopped, func() { receiveMNDP(m, conn, packetConn) })
	}
}

func openLLDPSocket() (int, error) {
	protocol := htons(etherTypeLLDP)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(protocol))
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol}); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	timeout := unix.NsecToTimeval(time.Second.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func receiveLLDP(m *Monitor, fd int) {
	defer unix.Close(fd)
	buffer := make([]byte, 9216)
	for {
		length, address, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		linkAddress, ok := address.(*unix.SockaddrLinklayer)
		if !ok || length < 16 {
			continue
		}
		payload, sourceMAC, ok := ethernetLLDPPayload(buffer[:length])
		if !ok {
			continue
		}
		iface, err := net.InterfaceByIndex(linkAddress.Ifindex)
		if err != nil {
			continue
		}
		neighbor, err := ParseLLDPPayload(iface.Name, sourceMAC, payload, time.Now())
		if err == nil {
			m.observeLLDP(neighbor)
		}
	}
}

func ethernetLLDPPayload(frame []byte) ([]byte, net.HardwareAddr, bool) {
	if len(frame) < 14 {
		return nil, nil, false
	}
	sourceMAC := append(net.HardwareAddr(nil), frame[6:12]...)
	etherType := binary.BigEndian.Uint16(frame[12:14])
	offset := 14
	for etherType == etherTypeVLAN || etherType == etherTypeQinQ {
		if len(frame) < offset+4 {
			return nil, nil, false
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	if etherType != etherTypeLLDP || len(frame) <= offset {
		return nil, nil, false
	}
	return frame[offset:], sourceMAC, true
}

func openMNDPSocket() (*net.UDPConn, *ipv4.PacketConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: mndpPort})
	if err != nil {
		return nil, nil, err
	}
	packetConn := ipv4.NewPacketConn(conn)
	if err := packetConn.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, packetConn, nil
}

func receiveMNDP(m *Monitor, conn *net.UDPConn, packetConn *ipv4.PacketConn) {
	defer conn.Close()
	buffer := make([]byte, 65535)
	for {
		length, control, source, err := packetConn.ReadFrom(buffer)
		if err != nil {
			return
		}
		localInterface := ""
		if control != nil && control.IfIndex > 0 {
			if iface, lookupErr := net.InterfaceByIndex(control.IfIndex); lookupErr == nil {
				localInterface = iface.Name
			}
		}
		var sourceIP net.IP
		switch typed := source.(type) {
		case *net.UDPAddr:
			sourceIP = typed.IP
		case *net.IPAddr:
			sourceIP = typed.IP
		}
		neighbor, err := ParseMNDPPayload(localInterface, sourceIP, buffer[:length], time.Now())
		if err == nil {
			m.observeMNDP(neighbor)
		}
	}
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }
