package wusp

import (
	"encoding/binary"
	"testing"
)

// Every input below is reachable by any connected device, so each must be
// rejected with an error — never a panic, a crash or a giant allocation.

func hardeningFrame(flags byte, payload []byte) []byte {
	out := make([]byte, frameHdrSize, frameHdrSize+len(payload))
	out[0], out[1], out[2], out[5] = frameMagic0, frameMagic1, frameVersion, flags
	return append(out, payload...)
}

func decodeMustFail(t *testing.T, name string, frame []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: decoder panicked: %v", name, r)
		}
	}()
	if _, err := NewDecoder(DecodeOptions{}).Decode(frame); err == nil {
		t.Fatalf("%s: expected an error", name)
	}
}

func TestDecodeRejectsHostileFrames(t *testing.T) {
	huge := binary.AppendUvarint(nil, 1<<62)

	decodeMustFail(t, "huge field count", hardeningFrame(0, huge))

	// Device ID string with a length that overflows int.
	decodeMustFail(t, "negative blob length", hardeningFrame(flagDeviceID, binary.AppendUvarint(nil, 1<<63+5)))

	// One inline-path field holding a list that claims 2^62 items.
	decodeMustFail(t, "huge list count", hardeningFrame(0, append([]byte{1, 0, 1, 'x', byte(TagList)}, huge...)))

	// Deeply nested single-item lists would otherwise recurse ~1M levels.
	nested := []byte{1, 0, 1, 'x'}
	for i := 0; i < 1<<20; i++ {
		nested = append(nested, byte(TagList), 1)
	}
	decodeMustFail(t, "deep list nesting", hardeningFrame(0, append(nested, byte(TagNull))))

	// LZ4 frame declaring a 4 GiB raw size from a 4-byte body.
	lz := make([]byte, 4, 8)
	binary.LittleEndian.PutUint32(lz, 0xFFFFFFF0)
	decodeMustFail(t, "lz4 raw size bomb", hardeningFrame(flagLZ4, append(lz, 0x10, 'a', 0, 0)))
}

func TestControlFragmentLimits(t *testing.T) {
	frag := USPControlFragment{MessageID: 1, Count: 1, Compressed: true, RawSize: 0xFFFFFFF0, Data: []byte{0x10, 'a'}}
	if _, err := ReassembleUSPControlFragments([]USPControlFragment{frag}); err == nil {
		t.Fatal("expected oversized raw size to be rejected")
	}
	frag = USPControlFragment{MessageID: 1, Count: 1 << 31, Index: 0, Data: []byte{1}}
	if err := validateUSPControlFragment(frag); err == nil {
		t.Fatal("expected absurd fragment count to be rejected")
	}
}
