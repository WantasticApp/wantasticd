package device

import (
	"testing"

	"wantastic-agent/internal/wusp"
)

func newFragmentTestDevice() *Device {
	d := &Device{}
	d.wuspFragments.pending = make(map[wuspFragmentKey]*wuspFragmentAssembly)
	d.wuspFragments.bytesByPeer = make(map[*Peer]int)
	return d
}

// A peer streaming first fragments of messages that never complete must hit
// the per-peer budget instead of growing memory without bound.
func TestWUSPFragmentBufferIsBudgetedPerPeer(t *testing.T) {
	d := newFragmentTestDevice()
	peer, other := &Peer{}, &Peer{}
	rejected := false
	for id := uint64(1); id < 1<<20; id++ {
		raw, err := wusp.EncodeUSPControlFragment(wusp.USPControlFragment{
			MessageID: id, Count: wusp.MaxUSPControlFragmentCount, Index: 0, RawSize: 1, Data: []byte{1},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.consumeWUSPPayload(peer, raw); err != nil {
			rejected = true
			break
		}
	}
	if !rejected {
		t.Fatal("expected the per-peer fragment budget to reject the flood")
	}
	if got := d.wuspFragments.bytesByPeer[peer]; got > maxWUSPFragmentBytesPerPeer {
		t.Fatalf("buffered %d bytes, budget %d", got, maxWUSPFragmentBytesPerPeer)
	}

	// Another peer is unaffected, and a complete message still reassembles
	// and releases its budget.
	frames, err := wusp.FragmentUSPControlPayload([]byte("hello wusp control"), 7, 64)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for _, frame := range frames {
		payload, done, err := d.consumeWUSPPayload(other, frame)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			out = payload
		}
	}
	if string(out) != "hello wusp control" {
		t.Fatalf("reassembled %q", out)
	}
	if got := d.wuspFragments.bytesByPeer[other]; got != 0 {
		t.Fatalf("completed message left %d bytes charged", got)
	}
}
