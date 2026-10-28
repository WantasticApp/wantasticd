package device

import (
	"bytes"
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

func testNoisePublicKey(seed byte) NoisePublicKey {
	key := testNoisePrivateKey(seed)
	return key.publicKey()
}

func newAtomicInt64() *atomic.Int64 {
	return new(atomic.Int64)
}

func testPeerListPayload(peerID uint32) []byte {
	return testPeerListPayloadWithKey(peerID, NoisePublicKey{})
}

func testPeerListPayloadWithKey(peerID uint32, publicKey NoisePublicKey) []byte {
	payload := make([]byte, 4+78)
	binary.BigEndian.PutUint32(payload[:4], 1)
	offset := 4
	binary.BigEndian.PutUint32(payload[offset:], peerID)
	copy(payload[offset+4:], publicKey[:])
	copy(payload[offset+36:], net.ParseIP("192.168.88.20").To16())
	binary.BigEndian.PutUint16(payload[offset+52:], 51820)
	copy(payload[offset+54:], net.ParseIP("203.0.113.20").To16())
	binary.BigEndian.PutUint16(payload[offset+70:], 42000)
	payload[offset+72] = uint8(NATRestricted)
	payload[offset+73] = 1
	copy(payload[offset+74:offset+78], net.ParseIP("10.255.255.41").To4())
	return payload
}

func newTestDiscoveryClient() *P2PClient {
	return &P2PClient{
		device:   &Device{log: NewLogger(LogLevelSilent, "")},
		peers:    make(map[uint32]*DiscoveredPeer),
		sessions: make(map[uint32]*P2PSession),
	}
}

// A coordinator restart renumbers peers. The stale ID must go, or the
// destination index picks either entry for the same VPN IP and punch
// requests to the dead ID are silently dropped by the coordinator.
func TestHandlePeerListDropsRenumberedPeerID(t *testing.T) {
	key := testNoisePublicKey(0x41)
	for range 50 {
		client := newTestDiscoveryClient()
		client.handlePeerList(&P2PMessage{Payload: testPeerListPayloadWithKey(1003, key)})
		client.handlePeerList(&P2PMessage{Payload: testPeerListPayloadWithKey(1010, key)})
		if len(client.peers) != 1 || client.peers[1010] == nil {
			t.Fatalf("peers after renumbering = %v, want only ID 1010", client.peers)
		}
		if got := client.destinations.Load().byIP[netip.MustParseAddr("10.255.255.41")].peerID; got != 1010 {
			t.Fatalf("destination index uses ID %d, want 1010", got)
		}
		if got := client.peerKeyIndex[key]; got != 1010 {
			t.Fatalf("key index = %d, want 1010", got)
		}
		if !client.reregister.Load() {
			t.Fatalf("renumbering did not schedule a re-registration")
		}
	}
}

func TestHandlePeerListRenumberKeepsDirectPath(t *testing.T) {
	key := testNoisePublicKey(0x42)
	client := newTestDiscoveryClient()
	client.handlePeerList(&P2PMessage{Payload: testPeerListPayloadWithKey(1003, key)})
	established := time.Now().Add(-time.Minute)
	client.peers[1003].State = P2PStateEstablished
	client.peers[1003].EstablishedAt = established
	session := &P2PSession{TargetID: 1003, Nonce: [8]byte{1}, done: make(chan struct{})}
	client.sessions[1003] = session
	client.sessionByNonce = map[[8]byte]*P2PSession{session.Nonce: session}

	client.handlePeerList(&P2PMessage{Payload: testPeerListPayloadWithKey(1010, key)})
	peer := client.peers[1010]
	if len(client.peers) != 1 || peer == nil || peer.ID != 1010 {
		t.Fatalf("peers after renumbering = %v", client.peers)
	}
	if peer.State != P2PStateEstablished || !peer.EstablishedAt.Equal(established) {
		t.Fatalf("direct path state lost on renumbering: %v", peer.State)
	}
	if len(client.sessions) != 0 || len(client.sessionByNonce) != 0 {
		t.Fatalf("session for the stale ID survived")
	}
	select {
	case <-session.done:
	default:
		t.Fatalf("session for the stale ID was not stopped")
	}
}

func TestHandlePeerListRenumberRestartsTryingAttempt(t *testing.T) {
	key := testNoisePublicKey(0x43)
	client := newTestDiscoveryClient()
	client.handlePeerList(&P2PMessage{Payload: testPeerListPayloadWithKey(1003, key)})
	client.peers[1003].State = P2PStateTrying
	client.handlePeerList(&P2PMessage{Payload: testPeerListPayloadWithKey(1010, key)})
	if peer := client.peers[1010]; peer == nil || peer.State != P2PStateDiscovered {
		t.Fatalf("attempt against the stale ID was not reset: %#v", peer)
	}
	if _, ok := client.destinations.Load().byIP[netip.MustParseAddr("10.255.255.41")]; !ok {
		t.Fatalf("renumbered peer is not eligible for a new attempt")
	}
}

func TestForgetUnlistedPeers(t *testing.T) {
	client := newTestDiscoveryClient()
	client.attemptGates = make(map[uint32]*atomic.Int64)
	now := time.Now()
	old := now.Add(-p2pPeerForgetAfter - time.Minute)
	client.peers[1] = &DiscoveredPeer{ID: 1, State: P2PStateDiscovered, LastSeen: old}
	client.peers[2] = &DiscoveredPeer{ID: 2, State: P2PStateFailed, LastSeen: old}
	client.peers[3] = &DiscoveredPeer{ID: 3, State: P2PStateEstablished, LastSeen: old}
	client.peers[4] = &DiscoveredPeer{ID: 4, State: P2PStateTrying, LastSeen: old}
	client.peers[5] = &DiscoveredPeer{ID: 5, State: P2PStateDiscovered, LastSeen: now}
	client.attemptGates[1] = new(atomic.Int64)

	client.mu.Lock()
	changed := client.forgetUnlistedPeersLocked(now)
	client.mu.Unlock()
	if !changed {
		t.Fatalf("no peers forgotten")
	}
	for _, id := range []uint32{1, 2} {
		if client.peers[id] != nil {
			t.Fatalf("unlisted peer %d was kept", id)
		}
	}
	for _, id := range []uint32{3, 4, 5} {
		if client.peers[id] == nil {
			t.Fatalf("peer %d was forgotten", id)
		}
	}
	if client.attemptGates[1] != nil {
		t.Fatalf("attempt gate of a forgotten peer was kept")
	}
}

func TestRegisterDue(t *testing.T) {
	client := newTestDiscoveryClient()
	now := time.Now()
	if !client.registerDue(now) {
		t.Fatalf("unregistered client is not due")
	}
	client.myID = 7
	client.lastRegister.Store(now.UnixNano())
	if client.registerDue(now) {
		t.Fatalf("fresh registration is due again")
	}
	client.reregister.Store(true)
	if !client.registerDue(now) || client.registerDue(now) {
		t.Fatalf("candidate change must trigger exactly one registration")
	}
	if !client.registerDue(now.Add(p2pReregisterInterval)) {
		t.Fatalf("registration is not refreshed periodically")
	}
}

func TestInitiatesHandshakeBreaksTie(t *testing.T) {
	low, high := testNoisePublicKey(0x10), testNoisePublicKey(0x20)
	if bytes.Compare(low[:], high[:]) > 0 {
		low, high = high, low
	}
	a := &P2PClient{myPublicKey: low}
	b := &P2PClient{myPublicKey: high}
	if !a.initiatesHandshake(high) || b.initiatesHandshake(low) {
		t.Fatalf("exactly the lower key must initiate")
	}
}

func TestPrepareDirectPeerOnlyLowerKeyStartsHandshake(t *testing.T) {
	pair := genTestPair(t, false)
	client := NewP2PClient(pair[0].dev)
	defer client.Close()
	client.serverPeerKey = mustSinglePeer(t, pair[0].dev).handshake.remoteStatic

	for seed := byte(0x50); seed < 0x58; seed++ {
		key := testNoisePublicKey(seed)
		if err := client.prepareDirectPeer(key, net.IPv4(10, 0, 0, seed).To4(), "127.0.0.1:55555"); err != nil {
			t.Fatalf("prepare direct peer: %v", err)
		}
		peer := pair[0].dev.LookupPeer(key)
		if peer == nil {
			t.Fatalf("direct candidate was not configured")
		}
		keepalive := peer.persistentKeepaliveInterval.Load() != 0
		if want := client.initiatesHandshake(key); keepalive != want {
			t.Fatalf("keepalive (handshake start) = %v, want %v", keepalive, want)
		}
		if err := client.startDirectKeepalive(key); err != nil || peer.persistentKeepaliveInterval.Load() != 25 {
			t.Fatalf("fallback keepalive not enabled: %v", err)
		}
		pair[0].dev.RemovePeer(key)
		if err := client.startDirectKeepalive(key); err != nil || pair[0].dev.LookupPeer(key) != nil {
			t.Fatalf("fallback keepalive recreated a removed peer: %v", err)
		}
	}
}

func TestPunchRelayJoinsYoungSessionWithSecondNonce(t *testing.T) {
	pair := genTestPair(t, false)
	client := NewP2PClient(pair[0].dev)
	defer client.Close()
	remote := testNoisePublicKey(0x61)
	relay := func(nonce byte) *P2PMessage {
		m := &P2PMessage{Subtype: P2PSubtypePunchRelay, TargetID: 9, Nonce: [8]byte{nonce}}
		copy(m.PublicKey[:], remote[:])
		m.SetObservedAddr(&net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 41641})
		m.Payload = AppendP2PCandidatePayload(net.IPv4(10, 0, 0, 9).To4(), nil)
		return m
	}

	client.handlePunchRelay(relay(1))
	client.handlePunchRelay(relay(2))
	client.mu.RLock()
	session := client.sessions[9]
	first, second := client.sessionByNonce[[8]byte{1}], client.sessionByNonce[[8]byte{2}]
	client.mu.RUnlock()
	if session == nil || first != session || second != session || session.Nonce != [8]byte{1} {
		t.Fatalf("second relay did not join the young session")
	}
	if !session.acceptsNonce([8]byte{1}) || !session.acceptsNonce([8]byte{2}) || session.acceptsNonce([8]byte{3}) {
		t.Fatalf("session accepts the wrong nonces")
	}

	// An older session is replaced, and all of its nonces are forgotten.
	client.mu.Lock()
	session.createdAt = time.Now().Add(-p2pNonceGrace - time.Second)
	client.mu.Unlock()
	client.handlePunchRelay(relay(3))
	client.mu.RLock()
	replaced := client.sessions[9]
	_, oldFirst := client.sessionByNonce[[8]byte{1}]
	_, oldSecond := client.sessionByNonce[[8]byte{2}]
	client.mu.RUnlock()
	if replaced == session || replaced.Nonce != [8]byte{3} || oldFirst || oldSecond {
		t.Fatalf("stale session nonces survived replacement")
	}
	select {
	case <-session.done:
	default:
		t.Fatalf("replaced session was not stopped")
	}
}

func TestFilterLocalCandidates(t *testing.T) {
	ifaces := []p2pLocalInterface{
		{name: "lo0", flags: net.FlagUp | net.FlagLoopback, ips: []net.IP{net.ParseIP("127.0.0.1")}},
		{name: "en0", flags: net.FlagUp, ips: []net.IP{
			net.ParseIP("192.168.1.20"),
			net.ParseIP("fe80::1"),
			net.ParseIP("2001:db8::1"),
			net.ParseIP("2001:db8::2"),
			net.ParseIP("2001:db8::3"),
		}},
		{name: "en1", flags: net.FlagUp, ips: []net.IP{net.ParseIP("10.1.2.3"), net.ParseIP("169.254.3.4")}},
		{name: "en2", flags: 0, ips: []net.IP{net.ParseIP("10.9.9.9")}},
		{name: "utun4", flags: net.FlagUp, ips: []net.IP{net.ParseIP("10.200.0.1")}},
		{name: "tailscale0", flags: net.FlagUp, ips: []net.IP{net.ParseIP("10.201.0.1")}},
		{name: "wg0", flags: net.FlagUp, ips: []net.IP{net.ParseIP("10.202.0.1")}},
		{name: "ppp0", flags: net.FlagUp, ips: []net.IP{net.ParseIP("10.203.0.1")}},
		{name: "ipsec0", flags: net.FlagUp, ips: []net.IP{net.ParseIP("10.204.0.1")}},
		{name: "bridge100", flags: net.FlagUp, ips: []net.IP{net.ParseIP("10.205.0.1")}},
		{name: "wantastic", flags: net.FlagUp, ips: []net.IP{net.ParseIP("10.206.0.1")}},
		{name: "en3", flags: net.FlagUp, ips: []net.IP{net.ParseIP("100.100.1.1")}},
	}
	got := filterLocalCandidates(net.ParseIP("10.1.2.3").To4(), ifaces, "wantastic", 51820)
	var names []string
	for _, candidate := range got {
		names = append(names, candidate.String())
	}
	want := []string{"10.1.2.3:51820", "192.168.1.20:51820", "[2001:db8::1]:51820", "[2001:db8::2]:51820"}
	if len(names) != len(want) {
		t.Fatalf("candidates = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("candidates = %v, want %v", names, want)
		}
	}

	// A default route through another tunnel is not announced.
	got = filterLocalCandidates(net.ParseIP("10.200.0.1").To4(), ifaces, "wantastic", 51820)
	if len(got) == 0 || got[0].String() != "192.168.1.20:51820" {
		t.Fatalf("tunnel default-route address announced: %v", got)
	}
}

func TestPunchRelayForEstablishedPeerReturnsToRelay(t *testing.T) {
	pair := genTestPair(t, false)
	client := NewP2PClient(pair[0].dev)
	defer client.Close()
	destination := pair[1].ip.AsSlice()
	relayPeer := pair[0].dev.allowedips.Lookup(destination)
	client.serverPeerKey = relayPeer.handshake.remoteStatic

	directKey := testNoisePublicKey(0x71)
	assignedIP := net.IP(destination)
	if err := client.prepareDirectPeer(directKey, assignedIP, "127.0.0.1:55555"); err != nil {
		t.Fatalf("prepare direct peer: %v", err)
	}
	if err := client.activateDirectPeer(directKey, assignedIP); err != nil {
		t.Fatalf("activate direct peer: %v", err)
	}
	client.mu.Lock()
	client.peers[5] = &DiscoveredPeer{
		ID: 5, PublicKey: directKey, AssignedIP: assignedIP, P2PCapable: true,
		State: P2PStateEstablished, EstablishedAt: time.Now(), RelayPeer: relayPeer,
	}
	client.mu.Unlock()
	relay := &P2PMessage{Subtype: P2PSubtypePunchRelay, TargetID: 5, Nonce: [8]byte{7}}
	copy(relay.PublicKey[:], directKey[:])
	relay.SetObservedAddr(&net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 41641})
	relay.Payload = AppendP2PCandidatePayload(assignedIP, nil)

	client.handlePunchRelay(relay)
	client.mu.RLock()
	state := client.peers[5].State
	client.mu.RUnlock()
	if state != P2PStateEstablished || pair[0].dev.LookupPeer(directKey) == nil {
		t.Fatalf("relay racing a fresh promotion tore it down")
	}

	client.mu.Lock()
	client.peers[5].EstablishedAt = time.Now().Add(-time.Minute)
	client.mu.Unlock()
	client.handlePunchRelay(relay)
	client.mu.RLock()
	state, session := client.peers[5].State, client.sessions[5]
	client.mu.RUnlock()
	if state != P2PStateTrying || session == nil {
		t.Fatalf("established peer ignored the relay: state=%v", state)
	}
	if pair[0].dev.LookupPeer(directKey) != nil {
		t.Fatalf("direct peer kept after the peer started punching again")
	}
	if got := pair[0].dev.allowedips.Lookup(destination); got != relayPeer {
		t.Fatalf("relay route was not restored")
	}
}
