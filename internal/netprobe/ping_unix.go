//go:build !windows

package netprobe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func ping(ctx context.Context, addr netip.Addr) (time.Duration, string, error) {
	network := "udp4"
	listenAddress := "0.0.0.0"
	protocol := 1
	echoType := icmp.Type(ipv4.ICMPTypeEcho)
	replyType := icmp.Type(ipv4.ICMPTypeEchoReply)
	if addr.Is6() {
		network = "udp6"
		listenAddress = "::"
		protocol = 58
		echoType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
	}

	conn, err := icmp.ListenPacket(network, listenAddress)
	if err != nil {
		return 0, "", fmt.Errorf("open native ICMP socket: %w", err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(4 * time.Second)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, "", err
	}

	id := os.Getpid() & 0xffff
	sequence := int(time.Now().UnixNano() & 0xffff)
	message := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: sequence, Data: []byte("wantastic")},
	}
	wire, err := message.Marshal(nil)
	if err != nil {
		return 0, "", err
	}
	destination := &net.UDPAddr{IP: net.IP(addr.AsSlice())}
	started := time.Now()
	if _, err := conn.WriteTo(wire, destination); err != nil {
		return 0, "", err
	}

	buffer := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			return 0, "", err
		}
		parsed, err := icmp.ParseMessage(protocol, buffer[:n])
		if err != nil || parsed.Type != replyType {
			continue
		}
		echo, ok := parsed.Body.(*icmp.Echo)
		if !ok || echo.ID != id || echo.Seq != sequence {
			continue
		}
		latency := time.Since(started)
		return latency, fmt.Sprintf("native ICMP reply from %s in %s", addr, latency.Round(time.Millisecond)), nil
	}
}
