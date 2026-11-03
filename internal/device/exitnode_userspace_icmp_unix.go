//go:build darwin || linux

package device

import (
	"bytes"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// unixEchoer pings with an unprivileged ICMP datagram socket (macOS, and
// Linux/Android where ping_group_range allows it), or a raw socket as root.
type unixEchoer struct{ network string }

func newICMPEchoer() icmpEchoer {
	for _, network := range []string{"udp4", "ip4:icmp"} {
		if c, err := icmp.ListenPacket(network, "0.0.0.0"); err == nil {
			c.Close()
			return unixEchoer{network: network}
		}
	}
	return nil
}

func (e unixEchoer) echo(dst netip.Addr, payload []byte, timeout time.Duration) bool {
	if !dst.Is4() || len(payload) > 1472 {
		return false
	}
	c, err := icmp.ListenPacket(e.network, "0.0.0.0")
	if err != nil {
		return false
	}
	defer c.Close()
	// Linux rewrites the ID of datagram pings to the socket's port, so the
	// reply is matched on sequence and data, and on ID only with raw sockets.
	id, seq := rand.IntN(0xffff), rand.IntN(0xffff)
	req, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}).Marshal(nil)
	if err != nil {
		return false
	}
	var to net.Addr = &net.UDPAddr{IP: dst.AsSlice()}
	if e.network != "udp4" {
		to = &net.IPAddr{IP: dst.AsSlice()}
	}
	if _, err := c.WriteTo(req, to); err != nil {
		return false
	}
	deadline := time.Now().Add(timeout)
	_ = c.SetReadDeadline(deadline)
	buf := make([]byte, 1500+64)
	for time.Now().Before(deadline) {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return false
		}
		if !sameIP(from, dst) {
			continue
		}
		msg := buf[:n]
		// macOS hands datagram pings back with their IP header.
		if len(msg) >= 20 && msg[0]>>4 == 4 {
			if ihl := int(msg[0]&0x0f) * 4; ihl >= 20 && len(msg) >= ihl {
				msg = msg[ihl:]
			}
		}
		m, err := icmp.ParseMessage(1, msg)
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		body, ok := m.Body.(*icmp.Echo)
		if !ok || body.Seq != seq || !bytes.Equal(body.Data, payload) || (e.network != "udp4" && body.ID != id) {
			continue
		}
		return true
	}
	return false
}

func sameIP(a net.Addr, want netip.Addr) bool {
	var ip net.IP
	switch v := a.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return false
	}
	got, ok := netip.AddrFromSlice(ip)
	return ok && got.Unmap() == want
}

func (unixEchoer) close() {}
