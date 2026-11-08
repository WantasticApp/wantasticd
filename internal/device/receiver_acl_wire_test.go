package device

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildFrame encodes one receiver-ACL frame the way the hub does, for decode
// tests (mirrors ISPApp-TunnelHub encodeReceiverACLChunks).
func buildFrame(flags, gen uint8, addrs []net.IP) []byte {
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
	f := make([]byte, receiverACLHeaderSize+len(body))
	f[0] = byte(TUNControlActionApplyReceiverACL)
	f[1] = receiverACLVersion
	f[2] = flags
	f[3] = gen
	binary.LittleEndian.PutUint16(f[4:6], uint16(len(addrs)))
	copy(f[receiverACLHeaderSize:], body)
	return f
}

func TestReceiverACLFrameDecode(t *testing.T) {
	addrs := []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)}
	entries, flags, gen, err := decodeReceiverACLFrame(buildFrame(receiverACLFlagFirst|receiverACLFlagLast, 3, addrs))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gen != 3 || flags != (receiverACLFlagFirst|receiverACLFlagLast) {
		t.Fatalf("flags/gen mismatch: flags=%d gen=%d", flags, gen)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if string(entries[0]) != string(net.IPv4(10, 0, 0, 1).To4()) {
		t.Errorf("entry 0 mismatch")
	}

	// Malformed frames are rejected (caller keeps the previous set).
	bad := [][]byte{
		{},                                  // too short
		{9, receiverACLVersion, 3, 0, 0, 0}, // wrong action
		{byte(TUNControlActionApplyReceiverACL), 9, 3, 0, 0, 0}, // wrong version
	}
	for i, b := range bad {
		if _, _, _, err := decodeReceiverACLFrame(b); err == nil {
			t.Errorf("malformed frame %d accepted", i)
		}
	}
}

// TestReceiverACLChunkReassembly proves multi-chunk reassembly commits only on
// LAST, and discards a continuation whose generation changed (lost FIRST).
func TestReceiverACLChunkReassembly(t *testing.T) {
	d := &Device{}

	a1 := []net.IP{net.IPv4(10, 1, 1, 1), net.IPv4(10, 1, 1, 2)}
	a2 := []net.IP{net.IPv4(10, 1, 1, 3)}

	// FIRST (not last): buffered, no commit.
	keys, commit, err := d.ingestReceiverACLChunk(buildFrame(receiverACLFlagFirst, 5, a1))
	if err != nil || commit {
		t.Fatalf("first chunk: commit=%v err=%v", commit, err)
	}
	if keys != nil {
		t.Fatal("first chunk must not return keys")
	}

	// A stray continuation of a DIFFERENT gen is discarded, leaving the batch.
	if _, commit, _ := d.ingestReceiverACLChunk(buildFrame(0, 99, a2)); commit {
		t.Fatal("mismatched-gen continuation must not commit")
	}

	// LAST of gen 5: commits the full set (a1 only; the stray was dropped).
	keys, commit, err = d.ingestReceiverACLChunk(buildFrame(receiverACLFlagLast, 5, a2))
	if err != nil || !commit {
		t.Fatalf("last chunk: commit=%v err=%v", commit, err)
	}
	if len(keys) != 3 {
		t.Fatalf("reassembled %d keys, want 3", len(keys))
	}
}

// TestReceiverACLEmptySetCommits proves an empty (count 0) FIRST|LAST frame
// commits an empty set — the revocation/clear path.
func TestReceiverACLEmptySetCommits(t *testing.T) {
	d := &Device{}
	keys, commit, err := d.ingestReceiverACLChunk(buildFrame(receiverACLFlagFirst|receiverACLFlagLast, 1, nil))
	if err != nil || !commit {
		t.Fatalf("empty set: commit=%v err=%v", commit, err)
	}
	if len(keys) != 0 {
		t.Fatalf("empty set keys = %d, want 0", len(keys))
	}
}
