package device

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"wantastic-agent/internal/device/wireguard-go/conn"
)

func testTLSListener(t *testing.T) net.Listener {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func wgPacket(kind uint32, size int) []byte {
	p := make([]byte, size)
	binary.LittleEndian.PutUint32(p, kind)
	return p
}

// Unanswered UDP handshakes move the hub link to TLS; packets then go and
// come back over it, and a UDP handshake answer moves it back to UDP.
func TestHubLinkFallsBackToTCPAndReturns(t *testing.T) {
	oldPort, oldAfter, oldProbe, oldBackoff := tcpFallbackPort, tcpFallbackAfter, tcpUDPProbeEvery, tcpRedialBackoff
	t.Cleanup(func() {
		tcpFallbackPort, tcpFallbackAfter, tcpUDPProbeEvery, tcpRedialBackoff = oldPort, oldAfter, oldProbe, oldBackoff
	})
	tcpFallbackAfter, tcpUDPProbeEvery, tcpRedialBackoff = 50*time.Millisecond, time.Hour, 0

	// The "hub": a UDP socket that does not answer yet, and the balancer's TLS port.
	hubUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer hubUDP.Close()
	ln := testTLSListener(t)
	tcpFallbackPort = ln.Addr().(*net.TCPAddr).Port
	hub := hubUDP.LocalAddr().(*net.UDPAddr).AddrPort()
	hub = netip.AddrPortFrom(hub.Addr().Unmap(), hub.Port())

	b := newFallbackBind(conn.NewStdNetBind())
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.setHub(hub)
	ep, err := b.ParseEndpoint(hub.String())
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 16)
	for _, fn := range fns {
		go func(fn conn.ReceiveFunc) {
			bufs := [][]byte{make([]byte, 2048)}
			sizes := make([]int, 1)
			eps := make([]conn.Endpoint, 1)
			for {
				n, err := fn(bufs, sizes, eps)
				if err != nil {
					return
				}
				if n == 1 && eps[0] != nil && eps[0].DstToString() == hub.String() {
					received <- append([]byte(nil), bufs[0][:sizes[0]]...)
				}
			}
		}(fn)
	}

	// UDP initiations go unanswered.
	if err := b.Send([][]byte{wgPacket(1, 148)}, ep); err != nil {
		t.Fatal(err)
	}
	if b.usingTCP() {
		t.Fatal("moved to TCP before any wait")
	}
	time.Sleep(80 * time.Millisecond)

	// The balancer side: accept, check the magic, echo one response.
	served := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		magic := make([]byte, 4)
		if _, err := io.ReadFull(c, magic); err != nil || string(magic) != tcpFallbackMagic {
			return
		}
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		p := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		io.ReadFull(c, p)
		served <- p
		resp := wgPacket(2, 92)
		frame := append([]byte{0, byte(len(resp))}, resp...)
		c.Write(frame)
		time.Sleep(time.Second)
	}()

	// WireGuard resends; the bind dials and then carries it over TLS.
	deadline := time.Now().Add(5 * time.Second)
	var got []byte
	for got == nil && time.Now().Before(deadline) {
		if err := b.Send([][]byte{wgPacket(1, 148)}, ep); err != nil {
			t.Fatal(err)
		}
		select {
		case got = <-served:
		case <-time.After(100 * time.Millisecond):
		}
	}
	if got == nil || binary.LittleEndian.Uint32(got) != 1 {
		t.Fatalf("balancer got %x; want the initiation over TLS", got)
	}
	if !b.usingTCP() {
		t.Fatal("not on TCP after unanswered handshakes")
	}
	select {
	case p := <-received:
		if binary.LittleEndian.Uint32(p) != 2 {
			t.Fatalf("received type %d over TCP", binary.LittleEndian.Uint32(p))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("response from the balancer never reached WireGuard")
	}

	// A UDP probe that the hub now answers moves the link back to UDP.
	tcpUDPProbeEvery = 0
	if err := b.Send([][]byte{wgPacket(1, 148)}, ep); err != nil {
		t.Fatal(err)
	}
	_ = hubUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	_, from, err := hubUDP.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no UDP probe while on TCP: %v", err)
	}
	if _, err := hubUDP.WriteToUDP(wgPacket(2, 92), from); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for b.usingTCP() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if b.usingTCP() {
		t.Fatal("still on TCP after UDP answered")
	}
}

// Traffic to other peers never leaves UDP.
func TestPeerTrafficStaysOnUDP(t *testing.T) {
	b := newFallbackBind(conn.NewStdNetBind())
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.setHub(netip.MustParseAddrPort("127.0.0.1:9"))
	peer, _ := b.ParseEndpoint("127.0.0.1:10")
	if b.isHub(peer) {
		t.Fatal("peer endpoint taken for the hub")
	}
}
