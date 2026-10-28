package device

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"wantastic-agent/internal/device/wireguard-go/conn"
	"wantastic-agent/internal/device/wireguard-go/tun/tuntest"
)

// Two real devices on loopback punch to each other. The coordinator is
// simulated by handing each side the PunchRelay it would send.

type e2eNode struct {
	dev    *Device
	pub    NoisePublicKey
	client *P2PClient
	ip     net.IP
}

// lossyBind drops outgoing packets for which drop returns true.
type lossyBind struct {
	conn.Bind
	drop func(packet []byte, ep conn.Endpoint) bool
}

func (b *lossyBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	kept := bufs[:0:0]
	for _, buf := range bufs {
		if b.drop == nil || !b.drop(buf, ep) {
			kept = append(kept, buf)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return b.Bind.Send(kept, ep)
}

func isOuterPunchPacket(packet []byte) bool {
	return len(packet) == 45 && binary.LittleEndian.Uint32(packet[:4]) == MessageP2PType &&
		packet[4] == P2PSubtypePunchPacket
}

func newE2ENode(t *testing.T, name string, coordinator NoisePublicKey, ip net.IP, bind conn.Bind) *e2eNode {
	t.Helper()
	var priv NoisePrivateKey
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	n := &e2eNode{ip: ip.To4(), pub: priv.publicKey()}
	level := LogLevelError
	if testing.Verbose() {
		level = LogLevelVerbose
	}
	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	n.dev = NewDevice(tuntest.NewChannelTUN().TUN(), bind, NewLogger(level, name+": "))
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:9\nallowed_ip=10.255.255.0/24\n",
		hex.EncodeToString(priv[:]), hex.EncodeToString(coordinator[:]))
	if err := n.dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := n.dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.dev.Close)
	n.dev.StartP2P(coordinator)
	n.client = n.dev.GetP2PClient()
	return n
}

func (n *e2eNode) addr() net.UDPAddr {
	return net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(n.dev.net.port)}
}

// relayFor is the PunchRelay the coordinator sends about peer.
func relayFor(peer *e2eNode, peerID uint32, nonce [8]byte) *P2PMessage {
	addr := peer.addr()
	m := &P2PMessage{Subtype: P2PSubtypePunchRelay, TargetID: peerID, Nonce: nonce}
	copy(m.PublicKey[:], peer.pub[:])
	m.SetObservedAddr(&addr)
	m.Payload = AppendP2PCandidatePayload(peer.ip, []net.UDPAddr{addr})
	return m
}

// unreachableRelayFor is relayFor with only an address that drops packets,
// as when the peer's NAT mapping was observed wrongly.
func unreachableRelayFor(peer *e2eNode, peerID uint32, nonce [8]byte) *P2PMessage {
	m := relayFor(peer, peerID, nonce)
	bad := net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 9}
	m.SetObservedAddr(&bad)
	m.Payload = AppendP2PCandidatePayload(peer.ip, []net.UDPAddr{bad})
	return m
}

func randomNonce(t *testing.T) (nonce [8]byte) {
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	return nonce
}

func newE2EPair(t *testing.T, bindB conn.Bind) (a, b *e2eNode) {
	var coordinatorPriv NoisePrivateKey
	if _, err := rand.Read(coordinatorPriv[:]); err != nil {
		t.Fatal(err)
	}
	coordinator := coordinatorPriv.publicKey()
	a = newE2ENode(t, "A", coordinator, net.IPv4(10, 255, 255, 2), nil)
	b = newE2ENode(t, "B", coordinator, net.IPv4(10, 255, 255, 3), bindB)
	return a, b
}

const (
	e2eIDA = uint32(2001)
	e2eIDB = uint32(2002)
)

func waitDirect(t *testing.T, a, b *e2eNode, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if a.client.GetEndpoint(e2eIDB) != nil && b.client.GetEndpoint(e2eIDA) != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	for name, n := range map[string]*e2eNode{"A": a, "B": b} {
		for _, p := range n.client.GetDiscoveredPeers() {
			t.Logf("%s: peer %d state=%v", name, p.ID, p.State)
		}
	}
	t.Fatalf("direct path not established within %s", timeout)
}

func runE2E(t *testing.T, delayB time.Duration) {
	a, b := newE2EPair(t, nil)
	nonce := randomNonce(t)
	a.client.HandleMessage(relayFor(b, e2eIDB, nonce))
	time.Sleep(delayB)
	b.client.HandleMessage(relayFor(a, e2eIDA, nonce))
	waitDirect(t, a, b, 15*time.Second)
}

func TestP2PE2ESimultaneous(t *testing.T) { runE2E(t, 0) }
func TestP2PE2EDelayed(t *testing.T)      { runE2E(t, 3*time.Second) }

// B only has a wrong address for A, so only A's punches arrive; B's answers
// are the only way A learns the path works.
func TestP2PE2EOneWay(t *testing.T) {
	a, b := newE2EPair(t, nil)
	nonce := randomNonce(t)
	a.client.HandleMessage(relayFor(b, e2eIDB, nonce))
	b.client.HandleMessage(unreachableRelayFor(a, e2eIDA, nonce))
	waitDirect(t, a, b, 15*time.Second)
}

// As OneWay, and B's first answers to A are lost. B must keep answering
// later punches instead of answering only once.
func TestP2PE2EOneWayLostReply(t *testing.T) {
	var portA atomic.Int64
	var dropped atomic.Int32
	bindB := &lossyBind{Bind: conn.NewDefaultBind()}
	bindB.drop = func(packet []byte, ep conn.Endpoint) bool {
		if !isOuterPunchPacket(packet) || ep.DstToString() != fmt.Sprintf("127.0.0.1:%d", portA.Load()) {
			return false
		}
		return dropped.Add(1) <= 3
	}
	a, b := newE2EPair(t, bindB)
	portA.Store(int64(a.dev.net.port))

	nonce := randomNonce(t)
	a.client.HandleMessage(relayFor(b, e2eIDB, nonce))
	b.client.HandleMessage(unreachableRelayFor(a, e2eIDA, nonce))
	waitDirect(t, a, b, 15*time.Second)
	if got := dropped.Load(); got <= 3 {
		t.Fatalf("B answered A %d times, want more than the 3 dropped", got)
	}
}

// Both sides asked at once: the coordinator relays twice with different
// nonces and each side sees them in the opposite order.
func TestP2PE2ESimultaneousRelaysWithDifferentNonces(t *testing.T) {
	a, b := newE2EPair(t, nil)
	first, second := randomNonce(t), randomNonce(t)
	a.client.HandleMessage(relayFor(b, e2eIDB, first))
	b.client.HandleMessage(relayFor(a, e2eIDA, second))
	a.client.HandleMessage(relayFor(b, e2eIDB, second))
	b.client.HandleMessage(relayFor(a, e2eIDA, first))
	waitDirect(t, a, b, 15*time.Second)
}

// A relay for an established peer means the peer lost the direct path: both
// sides must punch again instead of the established side ignoring it.
func TestP2PE2EEstablishedPeerRejoinsNewRelay(t *testing.T) {
	a, b := newE2EPair(t, nil)
	nonce := randomNonce(t)
	a.client.HandleMessage(relayFor(b, e2eIDB, nonce))
	b.client.HandleMessage(relayFor(a, e2eIDA, nonce))
	waitDirect(t, a, b, 15*time.Second)

	// A relay racing the promotion is ignored.
	a.client.HandleMessage(relayFor(b, e2eIDB, randomNonce(t)))
	if a.client.GetEndpoint(e2eIDB) == nil {
		t.Fatal("relay within the grace period tore down a fresh direct path")
	}

	for _, side := range []struct {
		n  *e2eNode
		id uint32
	}{{a, e2eIDB}, {b, e2eIDA}} {
		side.n.client.mu.Lock()
		side.n.client.peers[side.id].EstablishedAt = time.Now().Add(-time.Minute)
		side.n.client.mu.Unlock()
	}
	before := time.Now()
	again := randomNonce(t)
	a.client.HandleMessage(relayFor(b, e2eIDB, again))
	if a.client.GetEndpoint(e2eIDB) != nil {
		t.Fatal("established peer ignored a new punch relay")
	}
	if a.dev.LookupPeer(b.pub) != nil && a.dev.allowedips.Lookup(b.ip) == a.dev.LookupPeer(b.pub) {
		t.Fatal("direct peer kept the VPN route after the new relay")
	}
	b.client.HandleMessage(relayFor(a, e2eIDA, again))
	waitDirect(t, a, b, 15*time.Second)
	a.client.mu.RLock()
	establishedAt := a.client.peers[e2eIDB].EstablishedAt
	a.client.mu.RUnlock()
	if establishedAt.Before(before) {
		t.Fatalf("direct path was not re-established after the new relay")
	}
}
