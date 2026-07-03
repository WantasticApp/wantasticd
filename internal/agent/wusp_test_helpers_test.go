package agent

import (
	"testing"

	"wantastic-agent/internal/wusp"
)

func decodeControlResponseDatagram(t testing.TB, frame []byte) wusp.USPAgentResponse {
	t.Helper()
	return decodeControlResponseDatagrams(t, [][]byte{frame})
}

func decodeControlResponseDatagrams(t testing.TB, frames [][]byte) wusp.USPAgentResponse {
	t.Helper()
	var fragments []wusp.USPControlFragment
	for i, frame := range frames {
		if resp, err := wusp.DecodeUSPAgentResponse(frame); err == nil {
			if len(frames) != 1 {
				t.Fatalf("frame[%d] decoded as bare response inside multi-frame reply", i)
			}
			return resp
		}
		frag, isFrag, err := wusp.DecodeUSPControlFragment(frame)
		if err != nil {
			t.Fatalf("DecodeUSPControlFragment[%d]: %v", i, err)
		}
		if !isFrag {
			t.Fatalf("reply frame[%d] is neither response nor control fragment", i)
		}
		fragments = append(fragments, frag)
	}
	payload, err := wusp.ReassembleUSPControlFragments(fragments)
	if err != nil {
		t.Fatalf("ReassembleUSPControlFragments: %v", err)
	}
	resp, err := wusp.DecodeUSPAgentResponse(payload)
	if err != nil {
		t.Fatalf("DecodeUSPAgentResponse: %v", err)
	}
	return resp
}
