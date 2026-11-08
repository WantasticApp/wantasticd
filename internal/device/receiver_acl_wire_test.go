package device

import (
	"encoding/binary"
	"net"
	"testing"
)

func encodeAddrs(addrs []net.IP) []byte {
	body := make([]byte, 0, len(addrs)*5)
	for _, a := range addrs {
		if a4 := a.To4(); a4 != nil {
			body = append(body, 4)
			body = append(body, a4...)
		} else {
			body = append(body, 6)
			body = append(body, a.To16()...)
		}
	}
	return body
}

// buildFrame encodes one receiver-ACL frame the way the hub does (deny list then
// relay-only list), for decode tests.
func buildFrame(flags, gen uint8, deny, relay []net.IP) []byte {
	denyBody := encodeAddrs(deny)
	relayBody := encodeAddrs(relay)
	f := make([]byte, 0, receiverACLHeaderSize+len(denyBody)+2+len(relayBody))
	hdr := make([]byte, receiverACLHeaderSize)
	hdr[0] = byte(TUNControlActionApplyReceiverACL)
	hdr[1] = receiverACLVersion
	hdr[2] = flags
	hdr[3] = gen
	binary.LittleEndian.PutUint16(hdr[4:6], uint16(len(deny)))
	f = append(f, hdr...)
	f = append(f, denyBody...)
	rc := make([]byte, 2)
	binary.LittleEndian.PutUint16(rc, uint16(len(relay)))
	f = append(f, rc...)
	f = append(f, relayBody...)
	return f
}

func TestReceiverACLFrameDecode(t *testing.T) {
	deny := []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)}
	relay := []net.IP{net.IPv4(10, 0, 0, 9)}
	d, r, flags, gen, err := decodeReceiverACLFrame(buildFrame(receiverACLFlagFirst|receiverACLFlagLast, 3, deny, relay))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gen != 3 || flags != (receiverACLFlagFirst|receiverACLFlagLast) {
		t.Fatalf("flags/gen mismatch: flags=%d gen=%d", flags, gen)
	}
	if len(d) != 2 || len(r) != 1 {
		t.Fatalf("deny=%d relay=%d, want 2/1", len(d), len(r))
	}
	if string(d[0]) != string(net.IPv4(10, 0, 0, 1).To4()) {
		t.Errorf("deny entry 0 mismatch")
	}
	if string(r[0]) != string(net.IPv4(10, 0, 0, 9).To4()) {
		t.Errorf("relay entry 0 mismatch")
	}

	// A frame with only a deny list and no trailing relay count still decodes
	// (relay empty) — the deny-only/old-style shape.
	denyOnly := []byte{byte(TUNControlActionApplyReceiverACL), receiverACLVersion, receiverACLFlagFirst | receiverACLFlagLast, 0, 0, 0}
	if d2, r2, _, _, err := decodeReceiverACLFrame(denyOnly); err != nil || len(d2) != 0 || len(r2) != 0 {
		t.Fatalf("deny-only frame decode: d=%d r=%d err=%v", len(d2), len(r2), err)
	}

	// Malformed frames are rejected (caller keeps the previous sets).
	bad := [][]byte{
		{},                                  // too short
		{9, receiverACLVersion, 3, 0, 0, 0}, // wrong action
		{byte(TUNControlActionApplyReceiverACL), 9, 3, 0, 0, 0}, // wrong version
	}
	for i, b := range bad {
		if _, _, _, _, err := decodeReceiverACLFrame(b); err == nil {
			t.Errorf("malformed frame %d accepted", i)
		}
	}
}

// TestReceiverACLChunkReassembly proves multi-chunk reassembly commits only on
// LAST, discards a continuation whose generation changed (lost FIRST), and keeps
// deny and relay lists separate.
func TestReceiverACLChunkReassembly(t *testing.T) {
	d := &Device{}

	deny1 := []net.IP{net.IPv4(10, 1, 1, 1), net.IPv4(10, 1, 1, 2)}
	relay1 := []net.IP{net.IPv4(10, 2, 2, 1)}
	deny2 := []net.IP{net.IPv4(10, 1, 1, 3)}

	// FIRST (not last): buffered, no commit.
	dk, rk, commit, err := d.ingestReceiverACLChunk(buildFrame(receiverACLFlagFirst, 5, deny1, relay1))
	if err != nil || commit {
		t.Fatalf("first chunk: commit=%v err=%v", commit, err)
	}
	if dk != nil || rk != nil {
		t.Fatal("first chunk must not return keys")
	}

	// A stray continuation of a DIFFERENT gen is discarded, leaving the batch.
	if _, _, commit, _ := d.ingestReceiverACLChunk(buildFrame(0, 99, deny2, nil)); commit {
		t.Fatal("mismatched-gen continuation must not commit")
	}

	// LAST of gen 5: commits the full sets (deny1+deny2, relay1).
	dk, rk, commit, err = d.ingestReceiverACLChunk(buildFrame(receiverACLFlagLast, 5, deny2, nil))
	if err != nil || !commit {
		t.Fatalf("last chunk: commit=%v err=%v", commit, err)
	}
	if len(dk) != 3 || len(rk) != 1 {
		t.Fatalf("reassembled deny=%d relay=%d, want 3/1", len(dk), len(rk))
	}
}

// TestReceiverACLEmptySetCommits proves an empty FIRST|LAST frame commits empty
// sets — the revocation/clear path.
func TestReceiverACLEmptySetCommits(t *testing.T) {
	d := &Device{}
	dk, rk, commit, err := d.ingestReceiverACLChunk(buildFrame(receiverACLFlagFirst|receiverACLFlagLast, 1, nil, nil))
	if err != nil || !commit {
		t.Fatalf("empty set: commit=%v err=%v", commit, err)
	}
	if len(dk) != 0 || len(rk) != 0 {
		t.Fatalf("empty set keys = %d/%d, want 0/0", len(dk), len(rk))
	}
}
