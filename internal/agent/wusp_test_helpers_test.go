package agent

import (
	"testing"

	"wantastic-agent/internal/wusp"
)

func decodeControlResponseDatagram(t testing.TB, frame []byte) wusp.USPAgentResponse {
	t.Helper()
	frag, isFrag, err := wusp.DecodeUSPControlFragment(frame)
	if err != nil {
		t.Fatalf("DecodeUSPControlFragment: %v", err)
	}
	payload := frame
	if isFrag {
		payload, err = wusp.ReassembleUSPControlFragments([]wusp.USPControlFragment{frag})
		if err != nil {
			t.Fatalf("ReassembleUSPControlFragments: %v", err)
		}
	}
	resp, err := wusp.DecodeUSPAgentResponse(payload)
	if err != nil {
		t.Fatalf("DecodeUSPAgentResponse: %v", err)
	}
	return resp
}
