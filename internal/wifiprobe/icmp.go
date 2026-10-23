// Package wifiprobe measures round-trip latency to WiFi stations with ICMP
// echo, natively (golang.org/x/net/icmp) and without spawning ping(8).
//
// One socket serves every target: each round sends one echo to all targets,
// so N stations cost Count rounds of wall time rather than N×Count. Replies
// are matched by (source address, sequence) and, on raw sockets, by the echo
// identifier, so stray traffic never pollutes the statistics.
package wifiprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	MethodICMP = "icmp"
	MethodNone = "none"

	// MaxTargets bounds one probe run.
	MaxTargets = 256
	payloadLen = 16
)

// Options controls one probe run.
type Options struct {
	Count    int           // echo requests per target
	Interval time.Duration // gap between rounds
	Timeout  time.Duration // wait for late replies after the last round
}

// Result summarises the replies from one target.
type Result struct {
	Sent     int
	Received int
	Min      time.Duration
	Max      time.Duration
	Avg      time.Duration
	// Jitter is the mean absolute difference between consecutive RTTs
	// (RFC 3550 style, without smoothing).
	Jitter time.Duration
}

// Lost returns the number of echo requests that got no reply.
func (r Result) Lost() int {
	if r.Received > r.Sent {
		return 0
	}
	return r.Sent - r.Received
}

// ErrUnavailable means neither a raw nor an unprivileged ICMP socket could be
// opened (no CAP_NET_RAW and ping_group_range excludes the agent).
var ErrUnavailable = errors.New("wifiprobe: no ICMP socket available")

type sentProbe struct {
	target netip.Addr
	at     time.Time
}

// Probe pings every IPv4 target Count times and returns per-target results.
func Probe(ctx context.Context, targets []netip.Addr, opts Options) (map[netip.Addr]Result, error) {
	if opts.Count <= 0 {
		opts.Count = 4
	}
	if opts.Interval <= 0 {
		opts.Interval = 250 * time.Millisecond
	}
	if opts.Timeout <= 0 {
		opts.Timeout = time.Second
	}
	unique := make([]netip.Addr, 0, len(targets))
	seen := make(map[netip.Addr]bool, len(targets))
	for _, target := range targets {
		target = target.Unmap()
		if !target.Is4() || target.IsUnspecified() || target.IsMulticast() || seen[target] {
			continue
		}
		seen[target] = true
		unique = append(unique, target)
		if len(unique) == MaxTargets {
			break
		}
	}
	results := make(map[netip.Addr]Result, len(unique))
	if len(unique) == 0 {
		return results, nil
	}

	conn, raw, err := listen()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	id := rand.Intn(0xffff) + 1
	nonce := rand.Uint64()
	var mu sync.Mutex
	pending := make(map[uint16]sentProbe, len(unique)*opts.Count)
	rtts := make(map[netip.Addr][]time.Duration, len(unique))

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					return
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			received := time.Now()
			packet := buf[:n]
			// Darwin delivers the IPv4 header on datagram ICMP sockets.
			if !raw && len(packet) >= ipv4.HeaderLen && packet[0]>>4 == 4 {
				if ihl := int(packet[0]&0x0f) * 4; ihl >= ipv4.HeaderLen && ihl < len(packet) {
					packet = packet[ihl:]
				}
			}
			msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), packet)
			if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			echo, ok := msg.Body.(*icmp.Echo)
			if !ok || len(echo.Data) < payloadLen || binary.BigEndian.Uint64(echo.Data[8:]) != nonce {
				continue
			}
			// Unprivileged sockets rewrite the identifier; raw ones keep ours.
			if raw && echo.ID != id {
				continue
			}
			from, ok := peerAddr(peer)
			if !ok {
				continue
			}
			mu.Lock()
			probe, found := pending[uint16(echo.Seq)]
			if found && probe.target == from {
				delete(pending, uint16(echo.Seq))
				rtts[from] = append(rtts[from], received.Sub(probe.at))
			}
			mu.Unlock()
		}
	}()

	seq := uint16(rand.Intn(0xffff))
	sent := make(map[netip.Addr]int, len(unique))
	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint64(payload[8:], nonce)
send:
	for round := 0; round < opts.Count; round++ {
		if round > 0 {
			select {
			case <-ctx.Done():
				break send
			case <-time.After(opts.Interval):
			}
		}
		for _, target := range unique {
			seq++
			binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))
			wire, err := (&icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Body: &icmp.Echo{ID: id, Seq: int(seq), Data: payload},
			}).Marshal(nil)
			if err != nil {
				continue
			}
			mu.Lock()
			pending[seq] = sentProbe{target: target, at: time.Now()}
			mu.Unlock()
			if _, err := conn.WriteTo(wire, socketAddr(target, raw)); err != nil {
				mu.Lock()
				delete(pending, seq)
				mu.Unlock()
				continue
			}
			sent[target]++
		}
	}
	deadline := time.Now().Add(opts.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	<-readerDone

	mu.Lock()
	defer mu.Unlock()
	for _, target := range unique {
		results[target] = summarise(sent[target], rtts[target])
	}
	return results, nil
}

func summarise(sent int, rtts []time.Duration) Result {
	res := Result{Sent: sent, Received: len(rtts)}
	if len(rtts) == 0 {
		return res
	}
	var total, jitter time.Duration
	res.Min, res.Max = rtts[0], rtts[0]
	for i, rtt := range rtts {
		total += rtt
		if rtt < res.Min {
			res.Min = rtt
		}
		if rtt > res.Max {
			res.Max = rtt
		}
		if i > 0 {
			d := rtt - rtts[i-1]
			if d < 0 {
				d = -d
			}
			jitter += d
		}
	}
	res.Avg = total / time.Duration(len(rtts))
	if len(rtts) > 1 {
		res.Jitter = jitter / time.Duration(len(rtts)-1)
	}
	return res
}

// listen prefers a raw socket (agent runs as root on CPEs) and falls back to
// the kernel's unprivileged ICMP datagram socket.
func listen() (*icmp.PacketConn, bool, error) {
	if conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		return conn, true, nil
	}
	if conn, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		return conn, false, nil
	}
	return nil, false, ErrUnavailable
}

func socketAddr(target netip.Addr, raw bool) net.Addr {
	if raw {
		return &net.IPAddr{IP: target.AsSlice()}
	}
	return &net.UDPAddr{IP: target.AsSlice()}
}

func peerAddr(addr net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch a := addr.(type) {
	case *net.IPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	default:
		return netip.Addr{}, false
	}
	parsed, ok := netip.AddrFromSlice(ip)
	return parsed.Unmap(), ok
}
