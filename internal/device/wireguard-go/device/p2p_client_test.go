package device

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestFailPunchSessionIgnoresStaleSession(t *testing.T) {
	client := &P2PClient{sessions: make(map[uint32]*P2PSession)}
	peer := &DiscoveredPeer{ID: 10, State: P2PStateTrying}
	oldSession := &P2PSession{TargetID: peer.ID}
	newSession := &P2PSession{TargetID: peer.ID}
	client.sessions[peer.ID] = newSession

	client.mu.Lock()
	failed := client.failPunchSessionIfCurrentLocked(peer, oldSession, time.Now())
	client.mu.Unlock()

	if failed {
		t.Fatalf("stale session should not mark the peer failed")
	}
	if peer.State != P2PStateTrying {
		t.Fatalf("peer state changed for stale session: %v", peer.State)
	}
}

func TestFailPunchSessionMarksCurrentSessionFailed(t *testing.T) {
	client := &P2PClient{
		sessions:       make(map[uint32]*P2PSession),
		sessionByNonce: make(map[[8]byte]*P2PSession),
	}
	peer := &DiscoveredPeer{ID: 10, State: P2PStateTrying}
	session := &P2PSession{TargetID: peer.ID, done: make(chan struct{})}
	now := time.Now()
	client.sessions[peer.ID] = session
	client.sessionByNonce[session.Nonce] = session

	client.mu.Lock()
	failed := client.failPunchSessionIfCurrentLocked(peer, session, now)
	client.mu.Unlock()

	if !failed {
		t.Fatalf("current session should be marked failed")
	}
	if peer.State != P2PStateFailed {
		t.Fatalf("peer state = %v, want failed", peer.State)
	}
	if peer.PunchAttempts != 1 {
		t.Fatalf("punch attempts = %d, want 1", peer.PunchAttempts)
	}
	if !peer.LastUsed.Equal(now) {
		t.Fatalf("last used = %v, want %v", peer.LastUsed, now)
	}
	if len(client.sessions) != 0 || len(client.sessionByNonce) != 0 {
		t.Fatalf("failed session was not removed")
	}
	select {
	case <-session.done:
	default:
		t.Fatalf("failed session worker was not stopped")
	}
}

func TestFailPunchSessionDoesNotDowngradeEstablishedPeer(t *testing.T) {
	client := &P2PClient{sessions: make(map[uint32]*P2PSession)}
	peer := &DiscoveredPeer{ID: 10, State: P2PStateEstablished}
	session := &P2PSession{TargetID: peer.ID}
	client.sessions[peer.ID] = session

	client.mu.Lock()
	failed := client.failPunchSessionIfCurrentLocked(peer, session, time.Now())
	client.mu.Unlock()

	if failed {
		t.Fatalf("established peer should not be marked failed")
	}
	if peer.State != P2PStateEstablished {
		t.Fatalf("peer state changed for established peer: %v", peer.State)
	}
}

func TestHandlePeerListPreservesFailedStateUntilBackoff(t *testing.T) {
	client := &P2PClient{
		device:   &Device{log: NewLogger(LogLevelSilent, "")},
		peers:    make(map[uint32]*DiscoveredPeer),
		sessions: make(map[uint32]*P2PSession),
	}
	peerID := uint32(42)
	lastUsed := time.Now()
	client.peers[peerID] = &DiscoveredPeer{
		ID:             peerID,
		State:          P2PStateFailed,
		LastUsed:       lastUsed,
		PunchAttempts:  2,
		CandidateAddrs: []net.UDPAddr{{IP: net.ParseIP("198.51.100.20"), Port: 51820}},
	}

	client.handlePeerList(&P2PMessage{Payload: testPeerListPayload(peerID)})

	got := client.peers[peerID]
	if got.State != P2PStateFailed {
		t.Fatalf("peer state = %v, want failed", got.State)
	}
	if got.PunchAttempts != 2 {
		t.Fatalf("punch attempts = %d, want preserved value 2", got.PunchAttempts)
	}
	if !got.LastUsed.Equal(lastUsed) {
		t.Fatalf("last used = %v, want %v", got.LastUsed, lastUsed)
	}
	if len(got.CandidateAddrs) != 1 {
		t.Fatalf("candidate addrs were not preserved: %#v", got.CandidateAddrs)
	}
}

func TestHandlePeerListBuildsTrafficDrivenIndexWithoutEagerAttempt(t *testing.T) {
	client := &P2PClient{
		device:   &Device{log: NewLogger(LogLevelSilent, "")},
		peers:    make(map[uint32]*DiscoveredPeer),
		sessions: make(map[uint32]*P2PSession),
	}
	peerID := uint32(42)
	client.handlePeerList(&P2PMessage{Payload: testPeerListPayload(peerID)})

	peer := client.peers[peerID]
	if peer == nil || peer.State != P2PStateDiscovered {
		t.Fatalf("peer state = %#v, want discovered", peer)
	}
	index := client.destinations.Load()
	addr := netip.MustParseAddr("10.255.255.41")
	if index == nil || index.byIP[addr].peerID != peerID {
		t.Fatalf("destination index does not contain %s", addr)
	}
	if client.attemptQueue != nil && len(client.attemptQueue) != 0 {
		t.Fatalf("peer-list refresh eagerly queued a direct attempt")
	}

	client.mu.Lock()
	peer.State = P2PStateTrying
	client.rebuildIndexesLocked()
	client.mu.Unlock()
	if _, ok := client.destinations.Load().byIP[addr]; ok {
		t.Fatalf("trying peer remained on the packet-path discovery index")
	}
}

func TestObserveDestinationCoalescesAttempts(t *testing.T) {
	client := NewP2PClient(&Device{})
	defer client.Close()
	peerID := uint32(7)
	gate := client.attemptGates[peerID]
	if gate == nil {
		gate = newAtomicInt64()
		client.attemptGates[peerID] = gate
	}
	client.destinations.Store(&p2pDestinationIndex{byIP: map[netip.Addr]p2pDestination{
		netip.MustParseAddr("10.0.0.7"): {peerID: peerID, gate: gate},
	}})

	for range 100 {
		client.ObserveDestination(net.IPv4(10, 0, 0, 7).To4())
	}
	if got := len(client.attemptQueue); got != 1 {
		t.Fatalf("queued attempts = %d, want 1", got)
	}
}

func TestPeerListRejectsOversizedAndTruncatedPayloads(t *testing.T) {
	client := &P2PClient{
		device: &Device{log: NewLogger(LogLevelSilent, "")},
		peers:  make(map[uint32]*DiscoveredPeer),
	}
	oversized := make([]byte, 4)
	binary.BigEndian.PutUint32(oversized, p2pMaxPeerListEntries+1)
	client.handlePeerList(&P2PMessage{Payload: oversized})

	truncated := make([]byte, 4)
	binary.BigEndian.PutUint32(truncated, 1)
	client.handlePeerList(&P2PMessage{Payload: truncated})
	if len(client.peers) != 0 {
		t.Fatalf("invalid peer lists mutated discovery state")
	}
}

func TestControlQueueIsBoundedAndCloseIsIdempotent(t *testing.T) {
	client := NewP2PClient(&Device{})
	for i := 0; i < p2pControlQueueSize; i++ {
		if !client.EnqueueMessage(&P2PMessage{}) {
			t.Fatalf("queue rejected message %d before reaching capacity", i)
		}
	}
	if client.EnqueueMessage(&P2PMessage{}) {
		t.Fatalf("queue accepted work beyond its fixed capacity")
	}
	if got := client.droppedControl.Load(); got != 1 {
		t.Fatalf("dropped control count = %d, want 1", got)
	}
	client.Close()
	client.Close()
}

func TestDirectPeerPromotionKeepsAndRestoresRelayRoute(t *testing.T) {
	pair := genTestPair(t, false)
	client := NewP2PClient(pair[0].dev)
	defer client.Close()

	destination := pair[1].ip.AsSlice()
	relayPeer := pair[0].dev.allowedips.Lookup(destination)
	if relayPeer == nil {
		t.Fatalf("test relay route is missing")
	}
	client.serverPeerKey = relayPeer.handshake.remoteStatic

	privateKey := testNoisePrivateKey(0x31)
	directKey := privateKey.publicKey()
	assignedIP := net.IP(destination)
	if err := client.prepareDirectPeer(directKey, assignedIP, "127.0.0.1:55555"); err != nil {
		t.Fatalf("prepare direct peer: %v", err)
	}
	if got := pair[0].dev.allowedips.Lookup(destination); got != relayPeer {
		t.Fatalf("candidate replaced relay route before handshake")
	}
	directPeer := pair[0].dev.LookupPeer(directKey)
	if directPeer == nil {
		t.Fatalf("direct candidate peer was not configured")
	}

	if err := client.activateDirectPeer(directKey, assignedIP); err != nil {
		t.Fatalf("activate direct peer: %v", err)
	}
	if got := pair[0].dev.allowedips.Lookup(destination); got != directPeer {
		t.Fatalf("authenticated direct peer did not receive the route")
	}

	pair[0].dev.RemovePeer(directKey)
	client.restoreRelayRoute(assignedIP, relayPeer)
	if got := pair[0].dev.allowedips.Lookup(destination); got != relayPeer {
		t.Fatalf("relay route was not restored after direct peer removal")
	}
}

func BenchmarkP2PEndpointLookupMiss512(b *testing.B) {
	client := &P2PClient{
		peers:        make(map[uint32]*DiscoveredPeer, 512),
		peerKeyIndex: make(map[NoisePublicKey]uint32, 512),
	}
	for id := uint32(1); id <= 512; id++ {
		var key NoisePublicKey
		binary.BigEndian.PutUint32(key[len(key)-4:], id)
		client.peers[id] = &DiscoveredPeer{
			ID:        id,
			PublicKey: key,
			State:     P2PStateEstablished,
		}
		client.peerKeyIndex[key] = id
	}

	var missing NoisePublicKey
	missing[0] = 0xff
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = client.GetEndpointForPeer(missing)
	}
}

func testNoisePrivateKey(seed byte) NoisePrivateKey {
	var key NoisePrivateKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func newAtomicInt64() *atomic.Int64 {
	return new(atomic.Int64)
}

func testPeerListPayload(peerID uint32) []byte {
	payload := make([]byte, 4+78)
	binary.BigEndian.PutUint32(payload[:4], 1)
	offset := 4
	binary.BigEndian.PutUint32(payload[offset:], peerID)
	copy(payload[offset+36:], net.ParseIP("192.168.88.20").To16())
	binary.BigEndian.PutUint16(payload[offset+52:], 51820)
	copy(payload[offset+54:], net.ParseIP("203.0.113.20").To16())
	binary.BigEndian.PutUint16(payload[offset+70:], 42000)
	payload[offset+72] = uint8(NATRestricted)
	payload[offset+73] = 1
	copy(payload[offset+74:offset+78], net.ParseIP("10.255.255.41").To4())
	return payload
}
