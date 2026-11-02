package device

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	uxNIC            tcpip.NICID = 1
	uxTCPMaxInFlight             = 1024
	uxDialTimeout                = 10 * time.Second
	uxUDPIdle                    = 2 * time.Minute
	uxDNSIdle                    = 15 * time.Second
	uxQueue                      = 1024
)

// userspaceExit is exit-node NAT for hosts without a kernel NAT the agent can
// drive (Windows Home/Pro have none outside Hyper-V or Internet Connection
// Sharing). Internet-bound packets of peers allowed to use this exit land in
// a dedicated gVisor stack; its TCP and UDP forwarders re-open each flow from
// this host's own sockets, so Windows routes them out of its normal uplink,
// and replies return to the peer through WireGuard. ICMP echo uses the OS
// ping API where there is one.
//
// It only ever receives packets the exit guard already classified as
// internet traffic of an allowed peer: tenant, LAN and own-address traffic
// never reaches it. The stack is separate from every other netstack in the
// agent, so its promiscuous mode (needed to accept any destination) has no
// effect on device<->peer reachability.
type userspaceExit struct {
	stack  *stack.Stack
	ep     *channel.Endpoint
	send   func([]byte) bool
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	echo   icmpEchoer
	pings  chan struct{} // bounds concurrent ICMP echoes
	// dial opens the host side of a flow; tests point it at a local server.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// icmpEchoer sends one ICMP echo and reports whether a reply came back.
type icmpEchoer interface {
	echo(dst netip.Addr, payload []byte, timeout time.Duration) bool
	close()
}

func newUserspaceExit(mtu int, send func([]byte) bool) (*userspaceExit, error) {
	if mtu <= 0 {
		mtu = 1420
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	ep := channel.New(uxQueue, uint32(mtu), "")
	if err := s.CreateNIC(uxNIC, ep); err != nil {
		s.Close()
		return nil, fmt.Errorf("exit stack NIC: %v", err)
	}
	// Accept packets for any destination and answer from it.
	if err := s.SetPromiscuousMode(uxNIC, true); err != nil {
		s.Close()
		return nil, fmt.Errorf("exit stack promiscuous: %v", err)
	}
	if err := s.SetSpoofing(uxNIC, true); err != nil {
		s.Close()
		return nil, fmt.Errorf("exit stack spoofing: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: uxNIC},
		{Destination: header.IPv6EmptySubnet, NIC: uxNIC},
	})
	ctx, cancel := context.WithCancel(context.Background())
	dialer := &net.Dialer{Timeout: uxDialTimeout, KeepAlive: 30 * time.Second}
	u := &userspaceExit{stack: s, ep: ep, send: send, ctx: ctx, cancel: cancel, echo: newICMPEchoer(), pings: make(chan struct{}, 64), dial: dialer.DialContext}
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, uxTCPMaxInFlight, u.handleTCP).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(s, u.handleUDP).HandlePacket)
	u.wg.Add(1)
	go u.writeLoop()
	return u, nil
}

// inject hands one peer packet (already accepted by the exit guard) to the
// stack. The packet is copied; the caller keeps its buffer.
func (u *userspaceExit) inject(pkt []byte) {
	if len(pkt) == 0 || u.ctx.Err() != nil {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch pkt[0] >> 4 {
	case 4:
		if u.echo != nil && isICMPv4EchoRequest(pkt) {
			u.ping(append([]byte(nil), pkt...))
			return
		}
		proto = header.IPv4ProtocolNumber
	case 6:
		proto = header.IPv6ProtocolNumber
	default:
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), pkt...))})
	u.ep.InjectInbound(proto, pb)
	pb.DecRef()
}

// writeLoop returns the stack's replies to peers.
func (u *userspaceExit) writeLoop() {
	defer u.wg.Done()
	for {
		pkt := u.ep.ReadContext(u.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		u.send(view.AsSlice())
		view.Release()
	}
}

func (u *userspaceExit) close() {
	u.cancel()
	u.ep.Close()
	u.wg.Wait()
	u.stack.Close()
	if u.echo != nil {
		u.echo.close()
	}
}

func uxHostPort(addr tcpip.Address, port uint16) string {
	ip, _ := netip.AddrFromSlice(addr.AsSlice())
	return net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(int(port)))
}

// handleTCP connects to the destination first, so a refused or unreachable
// destination is answered with a reset rather than a hanging handshake.
func (u *userspaceExit) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	conn, err := u.dial(u.ctx, "tcp", uxHostPort(id.LocalAddress, id.LocalPort))
	if err != nil {
		r.Complete(true)
		return
	}
	out, ok := conn.(halfCloser)
	if !ok {
		conn.Close()
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		out.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	in := gonet.NewTCPConn(&wq, ep)
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		uxPipeTCP(u.ctx, in, out)
	}()
}

type halfCloser interface {
	net.Conn
	CloseWrite() error
}

// uxPipeTCP copies both ways, passing half-closes through, until both sides
// are done or the exit stops.
func uxPipeTCP(ctx context.Context, in *gonet.TCPConn, out halfCloser) {
	stop := context.AfterFunc(ctx, func() { in.Close(); out.Close() })
	defer stop()
	defer in.Close()
	defer out.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(out, in); out.CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(in, out); in.CloseWrite(); done <- struct{}{} }()
	<-done
	<-done
}

// handleUDP relays one peer flow (5-tuple) through a host UDP socket until
// it has been idle for a while; DNS flows close sooner.
func (u *userspaceExit) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, udpErr := r.CreateEndpoint(&wq)
	if udpErr != nil {
		return
	}
	in := gonet.NewUDPConn(&wq, ep)
	out, err := u.dial(u.ctx, "udp", uxHostPort(id.LocalAddress, id.LocalPort))
	if err != nil {
		in.Close()
		return
	}
	idle := uxUDPIdle
	if id.LocalPort == 53 {
		idle = uxDNSIdle
	}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		uxPipeUDP(u.ctx, in, out, idle)
	}()
}

func uxPipeUDP(ctx context.Context, in, out net.Conn, idle time.Duration) {
	stop := context.AfterFunc(ctx, func() { in.Close(); out.Close() })
	defer stop()
	defer in.Close()
	defer out.Close()
	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn) {
		buf := make([]byte, 64<<10)
		for {
			src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if err != nil {
				break
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				break
			}
		}
		// Unblock the other direction.
		in.SetReadDeadline(time.Now())
		out.SetReadDeadline(time.Now())
		done <- struct{}{}
	}
	go relay(out, in)
	go relay(in, out)
	<-done
	<-done
}

// ping answers a peer's echo request with the host's own ping, preserving the
// peer's identifier, sequence and payload in the reply.
func (u *userspaceExit) ping(pkt []byte) {
	select {
	case u.pings <- struct{}{}:
	default:
		return // too many outstanding pings: drop like a busy router
	}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		defer func() { <-u.pings }()
		dst, payload, ok := icmpv4EchoTarget(pkt)
		if !ok || !u.echo.echo(dst, payload, 3*time.Second) || u.ctx.Err() != nil {
			return
		}
		if reply, ok := icmpv4EchoReply(pkt); ok {
			u.send(reply)
		}
	}()
}

func isICMPv4EchoRequest(pkt []byte) bool {
	if len(pkt) < header.IPv4MinimumSize {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	return ihl >= header.IPv4MinimumSize && len(pkt) >= ihl+header.ICMPv4MinimumSize &&
		pkt[9] == uint8(header.ICMPv4ProtocolNumber) && pkt[ihl] == uint8(header.ICMPv4Echo) &&
		// not a fragment
		pkt[6]&0x3f == 0 && pkt[7] == 0
}

// icmpv4EchoTarget returns the destination and the echo payload (after the
// 8-byte ICMP header).
func icmpv4EchoTarget(pkt []byte) (netip.Addr, []byte, bool) {
	if !isICMPv4EchoRequest(pkt) {
		return netip.Addr{}, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(pkt[2])<<8 | int(pkt[3])
	if total < ihl+header.ICMPv4MinimumSize || total > len(pkt) {
		return netip.Addr{}, nil, false
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	return dst, pkt[ihl+header.ICMPv4MinimumSize : total], true
}

// icmpv4EchoReply builds the echo reply to request: addresses swapped,
// type 0, checksums recomputed.
func icmpv4EchoReply(request []byte) ([]byte, bool) {
	if !isICMPv4EchoRequest(request) {
		return nil, false
	}
	ihl := int(request[0]&0x0f) * 4
	total := int(request[2])<<8 | int(request[3])
	if total < ihl+header.ICMPv4MinimumSize || total > len(request) {
		return nil, false
	}
	// A plain 20-byte header: no options in the reply.
	icmpLen := total - ihl
	reply := make([]byte, header.IPv4MinimumSize+icmpLen)
	ip := header.IPv4(reply)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(reply)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4([4]byte(request[16:20])),
		DstAddr:     tcpip.AddrFrom4([4]byte(request[12:16])),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	icmp := header.ICMPv4(reply[header.IPv4MinimumSize:])
	copy(icmp, request[ihl:total])
	icmp.SetType(header.ICMPv4EchoReply)
	icmp.SetCode(0)
	icmp.SetChecksum(0)
	icmp.SetChecksum(^checksum(icmp))
	return reply, true
}

// checksum is the Internet checksum (RFC 1071) of b, not inverted.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}
