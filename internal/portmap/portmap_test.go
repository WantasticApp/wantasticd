package portmap

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseProcNetRouteFindsDefaultGateway(t *testing.T) {
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"eth0\t00000000\t" + gatewayHex(netip.MustParseAddr("192.168.1.1")) + "\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
	gw, err := parseProcNetRoute(strings.NewReader(table))
	if err != nil || gw != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("gateway = %v, %v", gw, err)
	}
	if _, err := parseProcNetRoute(strings.NewReader("Iface\tDestination\tGateway\n")); err == nil {
		t.Fatal("table without a default route must fail")
	}
}

// gatewayHex prints an address the way the kernel does on this CPU.
func gatewayHex(addr netip.Addr) string {
	b := addr.As4()
	v := binary.NativeEndian.Uint32(b[:])
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return strings.ToUpper(hexString(out[:]))
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	s := make([]byte, 0, len(b)*2)
	for _, c := range b {
		s = append(s, digits[c>>4], digits[c&0x0f])
	}
	return string(s)
}

// A fake gateway on loopback answers the two NAT-PMP requests.
func TestNATPMPMapAgainstFakeGateway(t *testing.T) {
	gw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	old := natpmpPort
	natpmpPort = uint16(gw.LocalAddr().(*net.UDPAddr).Port)
	defer func() { natpmpPort = old }()

	go func() {
		buf := make([]byte, 16)
		for {
			n, from, err := gw.ReadFromUDP(buf)
			if err != nil {
				return
			}
			switch {
			case n == 2 && buf[1] == 0:
				resp := make([]byte, 12)
				resp[1] = 128
				copy(resp[8:12], []byte{203, 0, 113, 9})
				gw.WriteToUDP(resp, from)
			case n == 12 && buf[1] == 1:
				resp := make([]byte, 16)
				resp[1] = 129
				copy(resp[8:10], buf[4:6])                     // internal port
				binary.BigEndian.PutUint16(resp[10:12], 61000) // assigned external port
				binary.BigEndian.PutUint32(resp[12:16], 3600)
				gw.WriteToUDP(resp, from)
			}
		}
	}()

	external, lease, err := natpmpMap(netip.MustParseAddr("127.0.0.1"), 51820, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if external != netip.MustParseAddrPort("203.0.113.9:61000") || lease != time.Hour {
		t.Fatalf("mapping = %v lease %v", external, lease)
	}
}

type changes struct {
	mu   sync.Mutex
	seen []netip.AddrPort
}

func (c *changes) add(a netip.AddrPort) { c.mu.Lock(); c.seen = append(c.seen, a); c.mu.Unlock() }
func (c *changes) list() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]netip.AddrPort(nil), c.seen...)
}

func testMapper(onChange func(netip.AddrPort)) (*Mapper, chan time.Time) {
	tick := make(chan time.Time)
	m := New(51820, onChange)
	m.after = func(time.Duration) <-chan time.Time { return tick }
	return m, tick
}

func TestMapperAnnouncesMappingAndRemovesItOnStop(t *testing.T) {
	var got changes
	released := make(chan struct{}, 1)
	m, tick := testMapper(got.add)
	m.gateway = func() (netip.Addr, error) { return netip.MustParseAddr("192.168.1.1"), nil }
	m.natpmp = func(_ netip.Addr, _ uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
		if lifetime == 0 {
			released <- struct{}{}
			return netip.AddrPort{}, 0, nil
		}
		return netip.MustParseAddrPort("203.0.113.9:51820"), time.Hour, nil
	}
	m.upnp = func(context.Context, uint16, time.Duration) (netip.AddrPort, time.Duration, func(), error) {
		t.Error("UPnP must not run when NAT-PMP works")
		return netip.AddrPort{}, 0, nil, errors.New("unused")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	tick <- time.Now() // one renewal: same address, no new announcement
	cancel()
	<-done

	select {
	case <-released:
	default:
		t.Fatal("mapping not removed on stop")
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:51820"), {}}
	if seen := got.list(); len(seen) != 2 || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("announcements = %v, want %v", seen, want)
	}
}

// A router whose own WAN is CGNAT gets no usable mapping; NAT-PMP falls
// through to UPnP, and a CGNAT UPnP result is released and not announced.
func TestMapperIgnoresCarrierGradeNAT(t *testing.T) {
	var got changes
	m, tick := testMapper(got.add)
	m.gateway = func() (netip.Addr, error) { return netip.MustParseAddr("192.168.1.1"), nil }
	m.natpmp = func(netip.Addr, uint16, time.Duration) (netip.AddrPort, time.Duration, error) {
		return netip.MustParseAddrPort("100.72.1.5:51820"), time.Hour, nil
	}
	releasedUPnP := false
	m.upnp = func(context.Context, uint16, time.Duration) (netip.AddrPort, time.Duration, func(), error) {
		return netip.MustParseAddrPort("100.72.1.5:51820"), time.Hour, func() { releasedUPnP = true }, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	tick <- time.Now()
	cancel()
	<-done
	if seen := got.list(); len(seen) != 0 {
		t.Fatalf("CGNAT address announced: %v", seen)
	}
	if !releasedUPnP {
		t.Fatal("unusable UPnP mapping left on the router")
	}
}
