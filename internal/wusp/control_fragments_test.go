package wusp

import (
	"bytes"
	"testing"
)

func TestUSPControlFragmentsRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("Device.DeviceInfo.HostName=wantastic-openwrt\n"), 256)

	frames, err := FragmentUSPControlPayload(payload, 42, WUSPMaxDatagramPayload)
	if err != nil {
		t.Fatalf("FragmentUSPControlPayload returned error: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("fragment count=0 want non-zero")
	}

	fragments := make([]USPControlFragment, 0, len(frames))
	for _, frame := range frames {
		fragment, ok, err := DecodeUSPControlFragment(frame)
		if err != nil {
			t.Fatalf("DecodeUSPControlFragment returned error: %v", err)
		}
		if !ok {
			t.Fatal("DecodeUSPControlFragment returned ok=false")
		}
		fragments = append(fragments, fragment)
	}

	roundTrip, err := ReassembleUSPControlFragments(fragments)
	if err != nil {
		t.Fatalf("ReassembleUSPControlFragments returned error: %v", err)
	}
	if !bytes.Equal(roundTrip, payload) {
		t.Fatalf("reassembled payload mismatch: got=%dB want=%dB", len(roundTrip), len(payload))
	}
}

func TestUSPControlFragmentsIgnoreRawPayload(t *testing.T) {
	raw := []byte{1, 2, 3, 4}

	_, ok, err := DecodeUSPControlFragment(raw)
	if err != nil {
		t.Fatalf("DecodeUSPControlFragment(raw) returned error: %v", err)
	}
	if ok {
		t.Fatal("DecodeUSPControlFragment(raw) ok=true want false")
	}
}
