package device

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"wantastic-agent/internal/device/wireguard-go/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// peerStack is a stand-in for a peer using this host as its exit node: its
// packets go into the exit stack and the exit's replies come back to it.
func peerStack(t *testing.T, ux *userspaceExit, addr netip.Addr) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(256, 1420, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(addr.As4()).WithPrefix()}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); ep.Close(); s.Close() })
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			pkt.DecRef()
			ux.inject(view.AsSlice())
			view.Release()
		}
	}()
	ux.send = func(b []byte) bool {
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b...))})
		ep.InjectInbound(header.IPv4ProtocolNumber, pb)
		pb.DecRef()
		return true
	}
	return s
}

// TestUserspaceExitForwardsTCPAndUDP sends a peer's TCP and UDP to an
// internet address through the exit, which re-opens them from host sockets
// (pointed at local echo servers here) and carries the replies back.
func TestUserspaceExitForwardsTCPAndUDP(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	udpLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpLn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udpLn.ReadFrom(buf)
			if err != nil {
				return
			}
			udpLn.WriteTo(buf[:n], from)
		}
	}()

	ux, err := newUserspaceExit(1420, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ux.close()
	var dialed []string
	ux.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, network+" "+address)
		target := tcpLn.Addr().String()
		if network == "udp" {
			target = udpLn.LocalAddr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	peer := peerStack(t, ux, netip.MustParseAddr("10.255.255.9"))
	internet := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{93, 184, 216, 34}), Port: 443}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, peer, internet, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("TCP through the exit: %v", err)
	}
	msg := bytes.Repeat([]byte("wantastic exit "), 4000) // spans many segments
	go conn.Write(msg)
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("TCP echo: %v", err)
	}
	conn.Close()

	internet.Port = 53
	uc, err := gonet.DialUDP(peer, nil, &internet, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("UDP through the exit: %v", err)
	}
	defer uc.Close()
	uc.Write([]byte("query"))
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := uc.Read(buf)
	if err != nil || string(buf[:n]) != "query" {
		t.Fatalf("UDP echo: %q %v", buf[:n], err)
	}
	if len(dialed) < 2 || dialed[0] != "tcp 93.184.216.34:443" || dialed[len(dialed)-1] != "udp 93.184.216.34:53" {
		t.Fatalf("the exit dialed %v, want the peer's real destinations", dialed)
	}
}

func TestUserspaceExitRefusedTCPGetsReset(t *testing.T) {
	ux, err := newUserspaceExit(1420, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ux.close()
	ux.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: io.EOF}
	}
	peer := peerStack(t, ux, netip.MustParseAddr("10.255.255.9"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := gonet.DialContextTCP(ctx, peer, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 81}, ipv4.ProtocolNumber); err == nil {
		t.Fatal("connection to a refused destination succeeded")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("refused destination was not reset promptly")
	}
}

func TestICMPv4EchoReply(t *testing.T) {
	req := make([]byte, 20+8+4)
	ip := header.IPv4(req)
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(req)), TTL: 64, Protocol: uint8(header.ICMPv4ProtocolNumber),
		SrcAddr: tcpip.AddrFrom4([4]byte{10, 255, 255, 9}), DstAddr: tcpip.AddrFrom4([4]byte{8, 8, 8, 8})})
	ip.SetChecksum(^ip.CalculateChecksum())
	icmp := header.ICMPv4(req[20:])
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetIdent(77)
	icmp.SetSequence(5)
	copy(req[28:], "ping")
	icmp.SetChecksum(^checksum(icmp))

	dst, payload, ok := icmpv4EchoTarget(req)
	if !ok || dst != netip.MustParseAddr("8.8.8.8") || string(payload) != "ping" {
		t.Fatalf("target = %v %q %v", dst, payload, ok)
	}
	reply, ok := icmpv4EchoReply(req)
	if !ok {
		t.Fatal("no reply")
	}
	rip := header.IPv4(reply)
	ricmp := header.ICMPv4(reply[20:])
	if rip.SourceAddress() != tcpip.AddrFrom4([4]byte{8, 8, 8, 8}) || rip.DestinationAddress() != tcpip.AddrFrom4([4]byte{10, 255, 255, 9}) {
		t.Errorf("addresses not swapped: %v -> %v", rip.SourceAddress(), rip.DestinationAddress())
	}
	if ricmp.Type() != header.ICMPv4EchoReply || ricmp.Ident() != 77 || ricmp.Sequence() != 5 || string(reply[28:]) != "ping" {
		t.Errorf("reply = %x", reply)
	}
	if !rip.IsChecksumValid() || checksum(ricmp) != 0xffff {
		t.Error("bad checksum")
	}
}

type recordingTUN struct {
	tun.Device
	written [][]byte
}

func (r *recordingTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		r.written = append(r.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func exitTestPacket(src, dst [4]byte) []byte {
	p := make([]byte, 20)
	header.IPv4(p).Encode(&header.IPv4Fields{TotalLength: 20, TTL: 64, Protocol: uint8(header.UDPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4(src), DstAddr: tcpip.AddrFrom4(dst)})
	return p
}

// TestExitGuardDivertsOnlyExitTraffic: with the userspace exit on, peer
// traffic to the internet goes to it, while tenant and LAN traffic still
// reaches the OS untouched (device<->peer must never depend on the exit).
func TestExitGuardDivertsOnlyExitTraffic(t *testing.T) {
	g := newExitGuard()
	g.setTenant([]netip.Prefix{netip.MustParsePrefix("10.255.255.9/32")}, []string{"10.255.255.0/24"})
	g.allow.Store(true)
	ux, err := newUserspaceExit(1420, func([]byte) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer ux.close()
	g.ux.Store(ux)
	rec := &recordingTUN{}
	w := &exitGuardTUN{Device: rec, guard: g}
	peer := [4]byte{10, 255, 255, 7}
	tenant := exitTestPacket(peer, [4]byte{10, 255, 255, 9})
	lan := exitTestPacket(peer, [4]byte{192, 168, 1, 10})
	internet := exitTestPacket(peer, [4]byte{1, 1, 1, 1})
	if _, err := w.Write([][]byte{tenant, internet, lan}, 0); err != nil {
		t.Fatal(err)
	}
	if len(rec.written) != 2 || !bytes.Equal(rec.written[0], tenant) || !bytes.Equal(rec.written[1], lan) {
		t.Fatalf("OS got %d packets, want only tenant and LAN", len(rec.written))
	}
	if users := g.recentUsers(time.Minute); len(users) != 1 {
		t.Fatalf("exit users = %v", users)
	}

	// Exit-node sharing off: internet traffic is refused, not diverted.
	g.allow.Store(false)
	rec.written = nil
	w.Write([][]byte{internet, tenant}, 0)
	if len(rec.written) != 1 || !bytes.Equal(rec.written[0], tenant) {
		t.Fatalf("with sharing off the OS got %d packets", len(rec.written))
	}
}
