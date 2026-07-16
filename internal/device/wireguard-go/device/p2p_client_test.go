package device

import (
	"encoding/binary"
	"net"
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
	client := &P2PClient{sessions: make(map[uint32]*P2PSession)}
	peer := &DiscoveredPeer{ID: 10, State: P2PStateTrying}
	session := &P2PSession{TargetID: peer.ID}
	now := time.Now()
	client.sessions[peer.ID] = session

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
