package agent

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"

	"wantastic-agent/internal/wusp"
)

// countingCollector serves a large, incompressible message and counts how
// often it is asked, so a test can tell a replay from a fresh collection.
type countingCollector struct {
	calls atomic.Int32
	msg   *wusp.Message
}

func (c *countingCollector) Collect(context.Context, ...string) (*wusp.Message, error) {
	c.calls.Add(1)
	return c.msg, nil
}

func newReadReplayTestRuntime(t *testing.T) (*uspRuntime, *countingCollector) {
	t.Helper()
	runtime := newTestUSPRuntime(t)
	rng := rand.New(rand.NewSource(1))
	msg := wusp.NewMessage()
	for i := 0; i < 150; i++ {
		noise := make([]byte, 32)
		rng.Read(noise)
		msg.Set(fmt.Sprintf("Device.Hosts.Host.%d.HostName", i+1), wusp.String(fmt.Sprintf("%x", noise)))
	}
	collector := &countingCollector{msg: msg}
	runtime.agent = wusp.NewUSPAgent(wusp.USPAgentOptions{Collector: collector})
	return runtime, collector
}

func sendReadRequest(t *testing.T, runtime *uspRuntime, req wusp.USPAgentRequest) [][]byte {
	t.Helper()
	frame, err := wusp.EncodeUSPAgentRequest(req)
	if err != nil {
		t.Fatalf("EncodeUSPAgentRequest: %v", err)
	}
	var frames [][]byte
	if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, frame, func(out []byte) error {
		frames = append(frames, append([]byte(nil), out...))
		return nil
	}); err != nil {
		t.Fatalf("handleFrameFromPeer: %v", err)
	}
	return frames
}

func fragmentIndex(t *testing.T, frame []byte) uint32 {
	t.Helper()
	fragment, ok, err := wusp.DecodeUSPControlFragment(frame)
	if err != nil || !ok {
		t.Fatalf("frame is not a control fragment: ok=%v err=%v", ok, err)
	}
	return fragment.Index
}

func TestUSPRuntimeResendsOnlyRequestedReadFragments(t *testing.T) {
	runtime, collector := newReadReplayTestRuntime(t)
	req := wusp.USPAgentRequest{
		ID:     501,
		Method: wusp.USPAgentMethodGet,
		Paths:  []string{"Device.Hosts."},
		Metadata: wusp.WithResponseMaxControlPayload(
			wusp.WithRequestSequence(nil, 9), 512),
	}
	original := sendReadRequest(t, runtime, req)
	if len(original) < 4 {
		t.Fatalf("expected a multi-fragment reply, got %d frames", len(original))
	}
	resp := decodeControlResponseDatagrams(t, original)
	if !wusp.SupportsReadReplay(resp.Metadata) {
		t.Fatalf("reply does not advertise read replay: %v", resp.Metadata)
	}

	// The controller lost fragments 1 and 3. It asks again with the same
	// identity, a different response budget (it may have lowered it), and the
	// missing indices.
	resend := req
	resend.Metadata = wusp.WithResendFragments(
		wusp.WithResponseMaxControlPayload(wusp.WithRequestSequence(nil, 9), 700),
		[]uint32{1, 3})
	again := sendReadRequest(t, runtime, resend)
	if len(again) != 2 {
		t.Fatalf("resend returned %d frames, want 2", len(again))
	}
	for i, want := range []uint32{1, 3} {
		if got := fragmentIndex(t, again[i]); got != want {
			t.Fatalf("resend frame %d has index %d, want %d", i, got, want)
		}
		if !bytes.Equal(again[i], original[want]) {
			t.Fatalf("resent fragment %d differs from the original", want)
		}
	}
	if calls := collector.calls.Load(); calls != 1 {
		t.Fatalf("collector ran %d times, want 1 (a resend must not re-collect)", calls)
	}

	// A plain repeat of the same identity replays the whole kept reply.
	full := sendReadRequest(t, runtime, req)
	if len(full) != len(original) {
		t.Fatalf("full replay returned %d frames, want %d", len(full), len(original))
	}
}

func TestUSPRuntimeReadResendWithoutKeptReplyIsAMiss(t *testing.T) {
	runtime, collector := newReadReplayTestRuntime(t)
	req := wusp.USPAgentRequest{
		ID:       777,
		Method:   wusp.USPAgentMethodGet,
		Paths:    []string{"Device.Hosts."},
		Metadata: wusp.WithResendFragments(wusp.WithRequestSequence(nil, 3), []uint32{0}),
	}
	resp := decodeControlResponseDatagrams(t, sendReadRequest(t, runtime, req))
	if !wusp.IsReadReplayMiss(resp.Metadata) || resp.Error == "" {
		t.Fatalf("resend for an unknown reply = %+v, want a read replay miss", resp)
	}
	if calls := collector.calls.Load(); calls != 0 {
		t.Fatalf("a miss must not collect: collector ran %d times", calls)
	}
}

func TestUSPRuntimeReadReplayStaysWithinMemoryBudget(t *testing.T) {
	runtime, _ := newReadReplayTestRuntime(t)
	for id := uint64(1); id <= 64; id++ {
		sendReadRequest(t, runtime, wusp.USPAgentRequest{
			ID:       id,
			Method:   wusp.USPAgentMethodGet,
			Paths:    []string{"Device.Hosts."},
			Metadata: wusp.WithRequestSequence(nil, id),
		})
	}
	runtime.controlReplayMu.Lock()
	defer runtime.controlReplayMu.Unlock()
	total := 0
	for _, entry := range runtime.controlReplay {
		if entry.read {
			total += entry.bytes
		}
	}
	if total > wuspReadReplayMaxBytes {
		t.Fatalf("kept read replies use %d bytes, budget %d", total, wuspReadReplayMaxBytes)
	}
}
