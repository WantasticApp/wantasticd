package device

import (
	"net"
	"sync/atomic"
	"testing"
)

// TestReceiverACLDropAndCarveOuts proves the phase-3 receiver backstop: a
// decrypted packet whose crypto-authenticated source overlay IP is in the deny
// set is dropped when it arrives over a DIRECT peer, but is NEVER dropped when it
// arrives via the hub/relay (server) peer, and an empty set drops nothing.
func TestReceiverACLDropAndCarveOuts(t *testing.T) {
	pair := genTestPair(t, false)
	dev := pair[0].dev

	// The configured peer is the client's relay (hub) peer in this topology.
	serverDst := pair[1].ip.AsSlice()
	serverPeer := dev.allowedips.Lookup(serverDst)
	if serverPeer == nil {
		t.Fatal("relay peer missing")
	}
	serverKey := serverPeer.handshake.remoteStatic

	// A separate direct peer with its own /32.
	directKey := testNoisePublicKey(0x51)
	directPeer, err := dev.NewPeer(directKey)
	if err != nil {
		t.Fatalf("new direct peer: %v", err)
	}
	directSrc := net.IPv4(10, 20, 30, 40).To4()

	// Empty set: nothing is dropped (inert, zero behavior change).
	if dev.receiverACLDrop(directPeer, directSrc) {
		t.Fatal("empty set must not drop")
	}

	// Install a deny set naming the direct peer's /32.
	dev.SetReceiverACLDenySet([][]byte{directSrc}, serverKey)

	// Direct peer, src in set ⇒ DROP.
	if !dev.receiverACLDrop(directPeer, directSrc) {
		t.Error("denied src over a direct peer must be dropped")
	}
	// Carve-out: the SAME src arriving via the hub/relay (server) peer is NEVER
	// dropped — the hub already filtered relayed/return/control traffic.
	if dev.receiverACLDrop(serverPeer, directSrc) {
		t.Error("traffic via the server peer must never be dropped (carve-out)")
	}
	// A src NOT in the set is never dropped.
	other := net.IPv4(10, 20, 30, 99).To4()
	if dev.receiverACLDrop(directPeer, other) {
		t.Error("src not in the deny set must not be dropped")
	}

	// Clearing the set (revocation) makes the hot path inert again.
	dev.SetReceiverACLDenySet(nil, serverKey)
	if dev.receiverACLDrop(directPeer, directSrc) {
		t.Error("cleared set must not drop")
	}
}

// TestTearDownDeniedDirectPeers proves a now-denied established direct tunnel is
// removed and its relay route restored, while a non-denied peer is left intact.
func TestTearDownDeniedDirectPeers(t *testing.T) {
	pair := genTestPair(t, false)
	client := NewP2PClient(pair[0].dev)
	defer client.Close()

	destination := pair[1].ip.AsSlice()
	relayPeer := pair[0].dev.allowedips.Lookup(destination)
	if relayPeer == nil {
		t.Fatal("relay route missing")
	}
	client.serverPeerKey = relayPeer.handshake.remoteStatic

	// Promote a direct peer to the destination /32.
	directPriv := testNoisePrivateKey(0x61)
	directKey := directPriv.publicKey()
	assignedIP := net.IP(destination)
	if err := client.prepareDirectPeer(directKey, assignedIP, "127.0.0.1:55557"); err != nil {
		t.Fatalf("prepare direct peer: %v", err)
	}
	if err := client.activateDirectPeer(directKey, assignedIP); err != nil {
		t.Fatalf("activate direct peer: %v", err)
	}
	directPeer := pair[0].dev.LookupPeer(directKey)
	if directPeer == nil || pair[0].dev.allowedips.Lookup(destination) != directPeer {
		t.Fatal("direct peer did not take the route")
	}

	// Register it as an established discovered peer so teardown can find it.
	client.mu.Lock()
	client.peers[9] = &DiscoveredPeer{
		ID:         9,
		PublicKey:  directKey,
		State:      P2PStateEstablished,
		AssignedIP: append(net.IP(nil), assignedIP...),
		RelayPeer:  relayPeer,
	}
	client.rebuildIndexesLocked()
	client.mu.Unlock()

	// A deny set for an UNRELATED IP tears down nothing.
	torn := client.TearDownDeniedDirectPeers(map[string]struct{}{string(net.IPv4(9, 9, 9, 9).To4()): {}})
	if len(torn) != 0 {
		t.Fatalf("unrelated deny set tore down %d peers", len(torn))
	}
	if pair[0].dev.LookupPeer(directKey) == nil {
		t.Fatal("non-denied direct peer was wrongly removed")
	}

	// Deny the direct peer's /32: it is torn down and the relay route restored.
	torn = client.TearDownDeniedDirectPeers(map[string]struct{}{denyKeyForIP(assignedIP): {}})
	if len(torn) != 1 {
		t.Fatalf("denied teardown count = %d, want 1", len(torn))
	}
	if pair[0].dev.LookupPeer(directKey) != nil {
		t.Error("denied direct peer was not removed")
	}
	if got := pair[0].dev.allowedips.Lookup(destination); got != relayPeer {
		t.Error("relay route was not restored after teardown")
	}
}

// TestApplyRelayOnlyPinsAndTearsDown proves a relay-only peer's live direct
// tunnel is torn down, the relay route restored, and the peer pinned so
// tryP2PByID refuses to re-promote it; clearing the pins lets it promote again.
func TestApplyRelayOnlyPinsAndTearsDown(t *testing.T) {
	pair := genTestPair(t, false)
	client := NewP2PClient(pair[0].dev)
	defer client.Close()

	destination := pair[1].ip.AsSlice()
	relayPeer := pair[0].dev.allowedips.Lookup(destination)
	client.serverPeerKey = relayPeer.handshake.remoteStatic

	directPriv := testNoisePrivateKey(0x71)
	directKey := directPriv.publicKey()
	assignedIP := net.IP(destination)
	if err := client.prepareDirectPeer(directKey, assignedIP, "127.0.0.1:55558"); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := client.activateDirectPeer(directKey, assignedIP); err != nil {
		t.Fatalf("activate: %v", err)
	}
	client.mu.Lock()
	client.peers[11] = &DiscoveredPeer{
		ID:         11,
		PublicKey:  directKey,
		P2PCapable: true,
		State:      P2PStateEstablished,
		AssignedIP: append(net.IP(nil), assignedIP...),
		RelayPeer:  relayPeer,
	}
	client.attemptGates[11] = &atomic.Int64{}
	client.rebuildIndexesLocked()
	client.mu.Unlock()

	pins := map[string]struct{}{denyKeyForIP(assignedIP): {}}
	torn := client.ApplyRelayOnly(pins)
	if len(torn) != 1 {
		t.Fatalf("relay-only teardown = %d, want 1", len(torn))
	}
	if pair[0].dev.LookupPeer(directKey) != nil {
		t.Error("relay-only direct peer not removed")
	}
	if got := pair[0].dev.allowedips.Lookup(destination); got != relayPeer {
		t.Error("relay route not restored for relay-only peer")
	}
	// Relay-only must NOT drop the peer's traffic — it flows via the relay. The
	// deny set is independent of the relay-pin set.
	pair[0].dev.SetReceiverACLDenySet(nil, client.serverPeerKey)
	if pair[0].dev.receiverACLDrop(relayPeer, assignedIP.To4()) {
		t.Error("relay-only peer's traffic must NOT be dropped")
	}
	// Pinned: a promotion attempt is refused.
	client.mu.Lock()
	client.peers[11].State = P2PStateDiscovered
	client.mu.Unlock()
	if client.tryP2PByID(11) {
		t.Error("relay-pinned peer was promoted to direct")
	}
	// Clearing the pins lets it promote again.
	client.ApplyRelayOnly(nil)
	if !client.tryP2PByID(11) {
		t.Error("peer should be promotable after pins cleared")
	}
}
