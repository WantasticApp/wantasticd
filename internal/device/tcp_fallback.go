package device

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"wantastic-agent/internal/device/wireguard-go/conn"
)

// WireGuard over TLS to the hub's load balancer, for networks that drop
// WireGuard UDP (China's firewall recognises its handshake). UDP stays the
// only path while it works: the link to the hub moves to TCP only after
// handshakes go unanswered, and moves back when a UDP handshake is answered
// again. Peer-to-peer traffic never uses it.
//
// Wire format, after a TLS handshake on the load balancer's Winbox port
// (8291, open everywhere; the balancer tells TLS from Winbox by the first
// bytes): the 4-byte magic, then each WireGuard packet as a 2-byte
// big-endian length and the packet. TLS only hides the traffic's shape;
// WireGuard authenticates and encrypts the packets itself, so the balancer's
// certificate is not checked.
const tcpFallbackMagic = "WGT1"

// Variables so tests can shorten them.
var (
	tcpFallbackPort = 8291
	// tcpFallbackAfter is how long handshake initiations may go unanswered
	// over UDP before the hub link moves to TCP (WireGuard retries every 5s).
	tcpFallbackAfter = 16 * time.Second
	// tcpUDPProbeEvery is how often, while on TCP, one initiation goes over
	// UDP instead to see whether UDP works again.
	tcpUDPProbeEvery = 5 * time.Minute
	tcpRedialBackoff = 5 * time.Second
	tcpIdleTimeout   = 3 * time.Minute
)

const (
	wgMessageInitiation = 1
	wgMessageResponse   = 2
)

func wgMessageType(p []byte) uint32 {
	if len(p) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(p[:4])
}

// fallbackBind wraps the UDP bind; only packets to and from the hub are
// looked at.
type fallbackBind struct {
	conn.Bind

	mu    sync.Mutex
	hub   netip.AddrPort
	hubEP conn.Endpoint
	// pendingInit is when an initiation to the hub over UDP went out with
	// no response since; zero when answered.
	pendingInit time.Time
	useTCP      bool
	link        *tcpLink
	dialing     bool
	lastDial    time.Time
	lastProbe   time.Time
	rx          chan []byte
	closed      chan struct{}
}

func newFallbackBind(inner conn.Bind) *fallbackBind {
	return &fallbackBind{Bind: inner, rx: make(chan []byte, 256), closed: make(chan struct{})}
}

// Unwrap returns the UDP bind (Linux route-change handling checks its type).
func (b *fallbackBind) Unwrap() conn.Bind { return b.Bind }

// setHub names the hub endpoint (its resolved IP and WireGuard port).
func (b *fallbackBind) setHub(hub netip.AddrPort) {
	ep, err := b.Bind.ParseEndpoint(hub.String())
	if err != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.hub == hub {
		return
	}
	b.hub, b.hubEP = hub, ep
	b.pendingInit, b.useTCP = time.Time{}, false
	b.closeLinkLocked()
}

// usingTCP reports whether the hub link currently runs over TCP.
func (b *fallbackBind) usingTCP() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.useTCP
}

func (b *fallbackBind) isHub(ep conn.Endpoint) bool {
	if ep == nil {
		return false
	}
	b.mu.Lock()
	hub := b.hub
	b.mu.Unlock()
	if !hub.IsValid() {
		return false
	}
	ap, err := netip.ParseAddrPort(ep.DstToString())
	return err == nil && ap.Addr().Unmap() == hub.Addr().Unmap() && ap.Port() == hub.Port()
}

func (b *fallbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	b.mu.Lock()
	closed := make(chan struct{})
	b.closed = closed
	b.mu.Unlock()

	wrapped := make([]conn.ReceiveFunc, 0, len(fns)+1)
	for _, fn := range fns {
		wrapped = append(wrapped, b.watchUDP(fn))
	}
	wrapped = append(wrapped, func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case p := <-b.rx:
			b.mu.Lock()
			ep := b.hubEP
			b.mu.Unlock()
			sizes[0] = copy(packets[0], p)
			eps[0] = ep
			return 1, nil
		case <-closed:
			return 0, net.ErrClosed
		}
	})
	return wrapped, actual, nil
}

// watchUDP notes handshake responses from the hub arriving over UDP: UDP
// works, so the hub link stays on (or returns to) UDP.
func (b *fallbackBind) watchUDP(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		for i := 0; i < n; i++ {
			if wgMessageType(packets[i][:sizes[i]]) == wgMessageResponse && b.isHub(eps[i]) {
				b.mu.Lock()
				b.pendingInit = time.Time{}
				if b.useTCP {
					log.Printf("[WG] UDP to the hub answers again; leaving the TCP fallback")
					b.useTCP = false
					b.closeLinkLocked()
				}
				b.mu.Unlock()
			}
		}
		return n, err
	}
}

func (b *fallbackBind) Close() error {
	b.mu.Lock()
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	b.closeLinkLocked()
	b.mu.Unlock()
	return b.Bind.Close()
}

func (b *fallbackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if !b.isHub(ep) {
		return b.Bind.Send(bufs, ep)
	}
	now := time.Now()
	b.mu.Lock()
	if !b.useTCP && !b.pendingInit.IsZero() && now.Sub(b.pendingInit) > tcpFallbackAfter {
		log.Printf("[WG] No handshake answer from the hub over UDP for %s; switching the hub link to TCP %d", now.Sub(b.pendingInit).Round(time.Second), tcpFallbackPort)
		b.useTCP = true
		b.lastProbe = now
	}
	if !b.useTCP {
		for _, p := range bufs {
			if wgMessageType(p) == wgMessageInitiation && b.pendingInit.IsZero() {
				b.pendingInit = now
			}
		}
		b.mu.Unlock()
		return b.Bind.Send(bufs, ep)
	}

	// On TCP. Every few minutes one initiation goes over UDP instead, to
	// see whether UDP works again (sending it over both would be rejected as
	// a replay by the hub). If unanswered, WireGuard retries it in 5s over TCP.
	var probe, rest [][]byte
	for _, p := range bufs {
		if wgMessageType(p) == wgMessageInitiation && now.Sub(b.lastProbe) > tcpUDPProbeEvery {
			b.lastProbe = now
			probe = append(probe, p)
			continue
		}
		rest = append(rest, p)
	}
	link := b.link
	if link == nil {
		b.dialLocked()
	}
	b.mu.Unlock()

	if len(probe) > 0 {
		_ = b.Bind.Send(probe, ep)
	}
	if link == nil {
		return nil // dialing; WireGuard resends
	}
	for _, p := range rest {
		if err := link.write(p); err != nil {
			b.mu.Lock()
			if b.link == link {
				b.closeLinkLocked()
			}
			b.mu.Unlock()
			return nil
		}
	}
	return nil
}

// dialLocked starts one TLS dial to the hub's load balancer. mu held.
func (b *fallbackBind) dialLocked() {
	if b.dialing || time.Since(b.lastDial) < tcpRedialBackoff || !b.hub.IsValid() {
		return
	}
	b.dialing, b.lastDial = true, time.Now()
	hub, closed := b.hub, b.closed
	go func() {
		link, err := dialTCPLink(hub.Addr())
		b.mu.Lock()
		defer b.mu.Unlock()
		b.dialing = false
		if err != nil {
			log.Printf("[WG] TCP fallback to %s: %v", hub.Addr(), err)
			return
		}
		select {
		case <-closed:
			link.close()
			return
		default:
		}
		if !b.useTCP || b.hub != hub {
			link.close()
			return
		}
		b.link = link
		log.Printf("[WG] Hub link now runs over TCP %s", link.addr)
		go b.readLink(link, closed)
	}()
}

func (b *fallbackBind) readLink(link *tcpLink, closed chan struct{}) {
	defer func() {
		b.mu.Lock()
		if b.link == link {
			b.closeLinkLocked()
		}
		b.mu.Unlock()
	}()
	for {
		p, err := link.read()
		if err != nil {
			return
		}
		select {
		case b.rx <- p:
		case <-closed:
			return
		}
	}
}

func (b *fallbackBind) closeLinkLocked() {
	if b.link != nil {
		b.link.close()
		b.link = nil
	}
}

// tcpLink is one TLS connection carrying framed WireGuard packets.
type tcpLink struct {
	addr string
	c    *tls.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
	once sync.Once
}

func dialTCPLink(addr netip.Addr) (*tcpLink, error) {
	target := net.JoinHostPort(addr.String(), strconv.Itoa(tcpFallbackPort))
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 20 * time.Second}
	c, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		InsecureSkipVerify: true, // WireGuard authenticates the hub; TLS only hides the traffic
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(tcpFallbackMagic)); err != nil {
		c.Close()
		return nil, err
	}
	return &tcpLink{addr: target, c: c, r: bufio.NewReaderSize(c, 64<<10)}, nil
}

func (l *tcpLink) write(p []byte) error {
	if len(p) > 0xffff {
		return errors.New("packet too large")
	}
	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame, uint16(len(p)))
	copy(frame[2:], p)
	l.wmu.Lock()
	defer l.wmu.Unlock()
	_ = l.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := l.c.Write(frame)
	return err
}

func (l *tcpLink) read() ([]byte, error) {
	_ = l.c.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
	var hdr [2]byte
	if _, err := io.ReadFull(l.r, hdr[:]); err != nil {
		return nil, err
	}
	p := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(l.r, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (l *tcpLink) close() { l.once.Do(func() { l.c.Close() }) }
