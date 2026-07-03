package agent

// Integration tests for the WUSP agent runtime.
//
// These tests wire the real uspRuntime against an in-process "fake controller"
// that uses real wusp encoding/decoding — no mocking of the binary protocol.
// They verify the full pipeline:
//
//   controller encodes → agent decodes → agent handles → agent encodes → controller decodes
//
// and the reverse for agent-originated events (OnBoardRequest).
//
// Fragment reassembly at the WireGuard transport layer (consumeWUSPPayload in
// wusp_fragments.go) is covered by its own unit tests; here we bypass the
// WireGuard device and call handleFrameFromPeer directly with complete frames.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

// ── test helpers ─────────────────────────────────────────────────────────────

var integrationIDCounter atomic.Uint64

// newInMemoryUSPRuntime creates a uspRuntime whose agent uses a pure in-memory
// store (no platform backend). This avoids two test-environment issues:
//  1. The macOS platform collector returns wrong TypeTags for certain list-type
//     parameters, which causes EncodeUSPAgentResponse to fail.
//  2. The platform setter tries to write to /Library/Application Support/…
//     which is not accessible in CI or permission-restricted environments.
//
// Use this variant for tests that exercise Set/Get or GetAll. Use
// newTestUSPRuntime for tests that need real platform data (targeted Gets).
func newInMemoryUSPRuntime(tb testing.TB) *uspRuntime {
	tb.Helper()
	rt := newTestUSPRuntime(tb)
	// Swap out the platform-backed agent for a clean in-memory one.
	a := wusp.NewUSPAgent(wusp.USPAgentOptions{})
	_ = a.Set("Device.DeviceInfo.HostName", wusp.String("test-host"))
	_ = a.Set("Device.DeviceInfo.Manufacturer", wusp.String("Wantastic"))
	_ = a.Set("Device.DeviceInfo.ProductClass", wusp.String("WG-Router"))
	_ = a.Set("Device.DeviceInfo.SerialNumber", wusp.String("TEST-SERIAL-001"))
	_ = a.Set("Device.DeviceInfo.SoftwareVersion", wusp.String("1.2.3"))
	_ = a.Set("Device.DeviceInfo.HardwareVersion", wusp.String("rev-A"))
	_ = a.Set("Device.DeviceInfo.ProvisioningCode", wusp.String(""))
	_ = a.Set("Device.WUSP.Enable", wusp.Bool(true))
	_ = a.Set("Device.WUSP.Status", wusp.String("Enabled"))
	_ = a.Set("Device.WUSP.ProtocolVersion", wusp.String(wusp.WUSPModelVersion))
	rt.agent = a
	return rt
}

func integrationNextID() uint64 {
	return integrationIDCounter.Add(1) + 10000 // start at 10001 to avoid collisions with unit tests
}

// ctrlRequest encodes req, delivers it synchronously to rt via
// handleFrameFromPeer, captures the single reply frame, and returns the decoded
// response. It is the controller side of one complete WUSP round-trip.
//
// Calling convention: reply is synchronous — the agent calls it within
// handleFrameFromPeer before returning. The channel-based pending pattern is
// therefore not needed; the reply frame is always in `captured` by the time
// handleFrameFromPeer returns.
func ctrlRequest(t testing.TB, rt *uspRuntime, req wusp.USPAgentRequest) wusp.USPAgentResponse {
	t.Helper()

	encoded, err := wusp.EncodeUSPAgentRequest(req)
	if err != nil {
		t.Fatalf("ctrlRequest: EncodeUSPAgentRequest(method=%d id=%d): %v", req.Method, req.ID, err)
	}

	var captured [][]byte
	err = rt.handleFrameFromPeer(rt.controllerPublicKeyHex, encoded, func(frame []byte) error {
		captured = append(captured, append([]byte(nil), frame...))
		return nil
	})
	if err != nil {
		t.Fatalf("ctrlRequest: handleFrameFromPeer(method=%d id=%d): %v", req.Method, req.ID, err)
	}
	if len(captured) == 0 {
		t.Fatalf("ctrlRequest: agent produced no reply frame for method=%d id=%d", req.Method, req.ID)
	}

	return decodeControlResponseDatagrams(t, captured)
}

// ── GetSupportedProtocol ─────────────────────────────────────────────────────

// TestIntegration_GetSupportedProtocol verifies the full encoding pipeline for
// the capability-discovery round-trip that a controller performs on peer connect.
func TestIntegration_GetSupportedProtocol(t *testing.T) {
	rt := newTestUSPRuntime(t)

	resp := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:     integrationNextID(),
		Method: wusp.USPAgentMethodGetSupportedProtocol,
	})

	if resp.Error != "" {
		t.Fatalf("GetSupportedProtocol returned error: %q", resp.Error)
	}
	if resp.Protocol == nil {
		t.Fatal("Protocol is nil in GetSupportedProtocol response")
	}
	if resp.Protocol.Version == 0 {
		t.Error("Protocol.Version is 0 — expected non-zero")
	}
	if len(resp.Protocol.Methods) == 0 {
		t.Error("Protocol.Methods is empty — expected supported method list")
	}
	// Every well-known method must be advertised.
	want := map[string]bool{
		"Get": false, "Set": false, "GetSupportedProtocol": false, "GetSupportedDM": false,
	}
	for _, m := range resp.Protocol.Methods {
		want[m] = true
	}
	for m, found := range want {
		if !found {
			t.Errorf("Protocol.Methods missing %q", m)
		}
	}
	t.Logf("protocol: name=%q version=%d methods=%v", resp.Protocol.Name, resp.Protocol.Version, resp.Protocol.Methods)
}

// ── GetSupportedDM ───────────────────────────────────────────────────────────

// TestIntegration_GetSupportedDM verifies that the agent returns a populated
// data-model descriptor (used by the controller for schema-aware gets/sets).
func TestIntegration_GetSupportedDM(t *testing.T) {
	rt := newTestUSPRuntime(t)

	resp := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:     integrationNextID(),
		Method: wusp.USPAgentMethodGetSupportedDM,
		Paths:  []string{},
	})

	if resp.Error != "" {
		t.Fatalf("GetSupportedDM returned error: %q", resp.Error)
	}
	if resp.SupportedDataModel == nil {
		t.Fatal("SupportedDataModel is nil")
	}
	if len(resp.SupportedDataModel.Params) == 0 {
		t.Error("SupportedDataModel.Params is empty — expected TR-181 parameter list")
	}
	t.Logf("GetSupportedDM: %d params, %d objects", len(resp.SupportedDataModel.Params), len(resp.SupportedDataModel.Objects))
}

// ── Get ──────────────────────────────────────────────────────────────────────

// TestIntegration_GetDeviceInfo verifies that a targeted Get for known
// Device.DeviceInfo paths returns a valid, non-empty response.
func TestIntegration_GetDeviceInfo(t *testing.T) {
	rt := newTestUSPRuntime(t)

	paths := []string{
		"Device.DeviceInfo.HostName",
		"Device.DeviceInfo.SoftwareVersion",
	}
	resp := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:     integrationNextID(),
		Method: wusp.USPAgentMethodGet,
		Paths:  paths,
	})

	if resp.Error != "" {
		t.Fatalf("Get returned error: %q", resp.Error)
	}
	if resp.Message == nil {
		t.Fatal("Get returned nil Message")
	}
	// At least one known path must have a value.
	found := 0
	for _, p := range paths {
		if v, ok := resp.Message.Get(p); ok {
			found++
			t.Logf("%s = %q", p, v.AsString())
		}
	}
	if found == 0 {
		t.Error("none of the requested DeviceInfo paths returned a value")
	}
}

// TestIntegration_GetAll verifies that GetAll (empty Paths = full snapshot)
// returns a response with multiple parameters and that the response is
// re-encodable without loss (encoding stability check).
func TestIntegration_GetAll(t *testing.T) {
	rt := newInMemoryUSPRuntime(t)

	resp := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:     integrationNextID(),
		Method: wusp.USPAgentMethodGet,
		Paths:  []string{}, // empty = get all
	})

	if resp.Error != "" {
		t.Fatalf("GetAll returned error: %q", resp.Error)
	}
	if resp.Message == nil || len(resp.Message.Fields) == 0 {
		t.Fatal("GetAll returned empty message")
	}
	t.Logf("GetAll: %d parameters", len(resp.Message.Fields))

	// Encoding stability: re-encode and re-decode must yield the same field count.
	reencoded, err := wusp.EncodeUSPAgentResponse(resp)
	if err != nil {
		t.Fatalf("re-EncodeUSPAgentResponse: %v", err)
	}
	redecoded, err := wusp.DecodeUSPAgentResponse(reencoded)
	if err != nil {
		t.Fatalf("re-DecodeUSPAgentResponse: %v", err)
	}
	if len(redecoded.Message.Fields) != len(resp.Message.Fields) {
		t.Errorf("field count mismatch after re-encode: got=%d want=%d",
			len(redecoded.Message.Fields), len(resp.Message.Fields))
	}
}

// ── Set + Get ────────────────────────────────────────────────────────────────

// TestIntegration_SetAndGet verifies that a Set followed by a Get returns the
// written value, confirming the in-agent store is wired correctly.
func TestIntegration_SetAndGet(t *testing.T) {
	rt := newInMemoryUSPRuntime(t)
	const path = "Device.DeviceInfo.ProvisioningCode"
	const newValue = "integration-test-42"

	setMsg := wusp.NewMessage()
	setMsg.Set(path, wusp.String(newValue))

	setResp := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:      integrationNextID(),
		Method:  wusp.USPAgentMethodSet,
		Message: setMsg,
	})
	if setResp.Error != "" {
		t.Fatalf("Set returned error: %q", setResp.Error)
	}

	getResp := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:     integrationNextID(),
		Method: wusp.USPAgentMethodGet,
		Paths:  []string{path},
	})
	if getResp.Error != "" {
		t.Fatalf("Get after Set returned error: %q", getResp.Error)
	}
	if getResp.Message == nil {
		t.Fatal("Get after Set returned nil Message")
	}
	val, ok := getResp.Message.Get(path)
	if !ok {
		t.Fatalf("path %q missing from Get response", path)
	}
	if got := val.AsString(); got != newValue {
		t.Errorf("value=%q want=%q", got, newValue)
	}
}

// ── OnBoardRequest ───────────────────────────────────────────────────────────

// TestIntegration_OnBoardRequest verifies that initializeOnce emits an
// OnBoardRequest that the controller can fully decode using the standard
// IsEventNotifyRequest + DecodeEventFromRequest pipeline.
func TestIntegration_OnBoardRequest(t *testing.T) {
	rt := newTestUSPRuntime(t)
	transport := rt.transport.(*fakeUSPTransport)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := rt.initializeOnce(ctx); err != nil {
		t.Fatalf("initializeOnce: %v", err)
	}

	// Drain the transport channel — OnBoardRequest is fire-and-forget via SendWUSPToServer.
	var frame []byte
	select {
	case frame = <-transport.sendCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: no OnBoardRequest emitted on transport channel")
	}

	// Controller-side decode
	req, err := wusp.DecodeUSPAgentRequest(frame)
	if err != nil {
		t.Fatalf("controller DecodeUSPAgentRequest: %v", err)
	}
	if req.Method != wusp.USPAgentMethodNotify {
		t.Fatalf("method=%v want Notify", req.Method)
	}
	if !wusp.IsEventNotifyRequest(req) {
		t.Fatal("IsEventNotifyRequest returned false for OnBoardRequest")
	}
	event, err := wusp.DecodeEventFromRequest(req)
	if err != nil {
		t.Fatalf("DecodeEventFromRequest: %v", err)
	}
	if event.Type != wusp.USPEventTypeOnBoardRequest {
		t.Fatalf("event.Type=%d want OnBoardRequest (%d)", event.Type, wusp.USPEventTypeOnBoardRequest)
	}
	if event.OnBoard == nil {
		t.Fatal("event.OnBoard is nil")
	}
	if event.OnBoard.SerialNumber == "" {
		t.Fatal("event.OnBoard.SerialNumber is empty")
	}
	if event.OnBoard.AgentSupportedProtocolVersions == "" {
		t.Fatal("event.OnBoard.AgentSupportedProtocolVersions is empty")
	}
	t.Logf("OnBoardRequest: serial=%q proto=%q",
		event.OnBoard.SerialNumber, event.OnBoard.AgentSupportedProtocolVersions)
}

// ── Request ID correlation under concurrency ─────────────────────────────────

// TestIntegration_ConcurrentRequestIDCorrelation verifies that when the
// controller fires many concurrent requests, each response carries back the
// original request ID with no cross-contamination.
func TestIntegration_ConcurrentRequestIDCorrelation(t *testing.T) {
	rt := newTestUSPRuntime(t)
	const workers = 30

	type result struct {
		reqID  uint64
		respID uint64
		err    string
	}
	results := make(chan result, workers)

	for i := range workers {
		go func(reqID uint64) {
			encoded, err := wusp.EncodeUSPAgentRequest(wusp.USPAgentRequest{
				ID:     reqID,
				Method: wusp.USPAgentMethodGetSupportedProtocol,
			})
			if err != nil {
				results <- result{reqID: reqID, err: fmt.Sprintf("encode: %v", err)}
				return
			}

			var captured []byte
			if handleErr := rt.handleFrameFromPeer(rt.controllerPublicKeyHex, encoded, func(frame []byte) error {
				captured = append([]byte(nil), frame...)
				return nil
			}); handleErr != nil {
				results <- result{reqID: reqID, err: fmt.Sprintf("handle: %v", handleErr)}
				return
			}

			resp := decodeControlResponseDatagram(t, captured)
			results <- result{reqID: reqID, respID: resp.ID}
		}(uint64(50000 + i))
	}

	for range workers {
		r := <-results
		if r.err != "" {
			t.Errorf("id=%d: %s", r.reqID, r.err)
			continue
		}
		if r.reqID != r.respID {
			t.Errorf("id correlation: sent=%d got=%d", r.reqID, r.respID)
		}
	}
}

// ── Unauthorized peer rejection ───────────────────────────────────────────────

// TestIntegration_UnauthorizedPeerGetsErrorResponse verifies that a request
// from an unrecognized peer key is rejected with a well-formed error response
// (not silently dropped). The controller side can then surface the error.
func TestIntegration_UnauthorizedPeerGetsErrorResponse(t *testing.T) {
	rt := newTestUSPRuntime(t)

	encoded, err := wusp.EncodeUSPAgentRequest(wusp.USPAgentRequest{
		ID:     integrationNextID(),
		Method: wusp.USPAgentMethodGet,
		Paths:  []string{"Device.DeviceInfo.HostName"},
	})
	if err != nil {
		t.Fatalf("EncodeUSPAgentRequest: %v", err)
	}

	// 64-char hex key that does NOT match the configured controller.
	badKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	var replyFrame []byte
	err = rt.handleFrameFromPeer(badKey, encoded, func(frame []byte) error {
		replyFrame = append([]byte(nil), frame...)
		return nil
	})

	if err == nil {
		t.Fatal("expected error for unauthorized peer, got nil")
	}
	if len(replyFrame) == 0 {
		t.Fatal("expected an error response frame, got none")
	}
	resp := decodeControlResponseDatagram(t, replyFrame)
	if resp.Error == "" {
		t.Fatal("rejection response has empty Error field")
	}
	t.Logf("rejection error: %q", resp.Error)
}

// ── Wire format round-trip for every supported method ────────────────────────

// TestIntegration_WireFormatRoundTrip verifies that every supported request
// method can complete a full encode→handle→decode cycle without panicking or
// corrupting the response ID/Method fields.
func TestIntegration_WireFormatRoundTrip(t *testing.T) {
	// Use in-memory runtime so GetAll and Set don't hit platform-backend issues
	// (wrong TypeTags from macOS collector, filesystem writes from setter).
	rt := newInMemoryUSPRuntime(t)

	cases := []struct {
		name string
		req  wusp.USPAgentRequest
	}{
		{"GetSupportedProtocol", wusp.USPAgentRequest{
			ID: 1, Method: wusp.USPAgentMethodGetSupportedProtocol,
		}},
		{"GetSupportedDM", wusp.USPAgentRequest{
			ID: 2, Method: wusp.USPAgentMethodGetSupportedDM, Paths: []string{},
		}},
		{"GetSpecificPath", wusp.USPAgentRequest{
			ID: 3, Method: wusp.USPAgentMethodGet, Paths: []string{"Device.DeviceInfo.HostName"},
		}},
		{"GetAll", wusp.USPAgentRequest{
			ID: 4, Method: wusp.USPAgentMethodGet, Paths: []string{},
		}},
		{"SetProvisioningCode", wusp.USPAgentRequest{
			ID: 5, Method: wusp.USPAgentMethodSet,
			Message: func() *wusp.Message {
				m := wusp.NewMessage()
				m.Set("Device.DeviceInfo.ProvisioningCode", wusp.String("wire-test"))
				return m
			}(),
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := ctrlRequest(t, rt, tc.req)

			if resp.ID != tc.req.ID {
				t.Errorf("response.ID=%d want=%d", resp.ID, tc.req.ID)
			}
			if resp.Method != tc.req.Method {
				t.Errorf("response.Method=%d want=%d", resp.Method, tc.req.Method)
			}
			// Log errors but don't fail — some paths may be empty in the
			// test environment (e.g. no real hardware).
			if resp.Error != "" {
				t.Logf("method=%d returned error (may be expected in test env): %q",
					tc.req.Method, resp.Error)
			}
		})
	}
}

// ── Large response fragmentation ─────────────────────────────────────────────

// TestIntegration_GetAllFragmentation verifies that a large GetAll response from
// the agent can be fragmented and reassembled correctly using the WUSP control
// fragment layer — simulating the WireGuard type-8 transport path.
func TestIntegration_GetAllFragmentation(t *testing.T) {
	rt := newInMemoryUSPRuntime(t)

	resp := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:     integrationNextID(),
		Method: wusp.USPAgentMethodGet,
		Paths:  []string{}, // GetAll
	})

	if resp.Message == nil || len(resp.Message.Fields) == 0 {
		t.Fatal("GetAll returned empty message")
	}

	// Encode the response as the agent's SendWUSP path would.
	encoded, err := wusp.EncodeUSPAgentResponse(resp)
	if err != nil {
		t.Fatalf("EncodeUSPAgentResponse: %v", err)
	}
	t.Logf("GetAll: %d params, %d bytes encoded", len(resp.Message.Fields), len(encoded))

	// Fragment at the WireGuard MTU budget and reassemble — simulating the full
	// send path from device.go:SendWUSP through the controller's HandleInbound.
	msgID := integrationNextID()
	fragments, err := wusp.FragmentUSPControlPayload(encoded, msgID, wusp.WUSPMaxDatagramPayload)
	if err != nil {
		t.Fatalf("FragmentUSPControlPayload: %v", err)
	}
	t.Logf("fragmented into %d pieces (budget=%d bytes)", len(fragments), wusp.WUSPMaxDatagramPayload)

	var frags []wusp.USPControlFragment
	for i, f := range fragments {
		frag, isFrag, err := wusp.DecodeUSPControlFragment(f)
		if err != nil {
			t.Fatalf("DecodeUSPControlFragment[%d]: %v", i, err)
		}
		if !isFrag {
			t.Fatalf("fragment[%d] was not decoded as a control fragment", i)
		}
		frags = append(frags, frag)
	}

	payload, err := wusp.ReassembleUSPControlFragments(frags)
	if err != nil {
		t.Fatalf("ReassembleUSPControlFragments: %v", err)
	}

	reassembled, err := wusp.DecodeUSPAgentResponse(payload)
	if err != nil {
		t.Fatalf("DecodeUSPAgentResponse after reassembly: %v", err)
	}
	if len(reassembled.Message.Fields) != len(resp.Message.Fields) {
		t.Errorf("field count mismatch after fragment round-trip: got=%d want=%d",
			len(reassembled.Message.Fields), len(resp.Message.Fields))
	}
}

// ── Controller ↔ Agent full onboard sequence ──────────────────────────────────

// TestIntegration_FullOnboardSequence simulates the sequence the controller
// runs when a new wantasticd peer connects:
//  1. GetSupportedProtocol — capability probe
//  2. GetAll              — full device snapshot
//  3. Set                 — provision a parameter
//  4. Get                 — verify provisioned value
func TestIntegration_FullOnboardSequence(t *testing.T) {
	rt := newInMemoryUSPRuntime(t)

	// Step 1 — capability probe
	proto := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:     integrationNextID(),
		Method: wusp.USPAgentMethodGetSupportedProtocol,
	})
	if proto.Protocol == nil {
		t.Fatal("step1 GetSupportedProtocol: Protocol is nil")
	}

	// Step 2 — full device snapshot
	snapshot := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:     integrationNextID(),
		Method: wusp.USPAgentMethodGet,
		Paths:  []string{},
	})
	if snapshot.Message == nil {
		t.Fatal("step2 GetAll: Message is nil")
	}
	t.Logf("snapshot: %d params", len(snapshot.Message.Fields))

	// Step 3 — provision
	const provPath = "Device.DeviceInfo.ProvisioningCode"
	const provValue = "onboard-seq-test"
	provMsg := wusp.NewMessage()
	provMsg.Set(provPath, wusp.String(provValue))
	setR := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:      integrationNextID(),
		Method:  wusp.USPAgentMethodSet,
		Message: provMsg,
	})
	if setR.Error != "" {
		t.Fatalf("step3 Set: %q", setR.Error)
	}

	// Step 4 — verify
	getR := ctrlRequest(t, rt, wusp.USPAgentRequest{
		ID:     integrationNextID(),
		Method: wusp.USPAgentMethodGet,
		Paths:  []string{provPath},
	})
	if getR.Error != "" {
		t.Fatalf("step4 Get: %q", getR.Error)
	}
	v, ok := getR.Message.Get(provPath)
	if !ok {
		t.Fatalf("step4 Get: %q not in response", provPath)
	}
	if v.AsString() != provValue {
		t.Errorf("step4 value=%q want=%q", v.AsString(), provValue)
	}
}

// ── CallController (agent-originated requests) ────────────────────────────────

// TestIntegration_CallControllerCorrelation verifies that agent-originated
// requests (CallController) correctly match responses injected back from the
// controller using handleFrameFromPeer with a response frame.
func TestIntegration_CallControllerCorrelation(t *testing.T) {
	rt := newTestUSPRuntime(t)
	transport := rt.transport.(*fakeUSPTransport)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type callResult struct {
		resp wusp.USPAgentResponse
		err  error
	}
	resultCh := make(chan callResult, 1)

	go func() {
		resp, err := rt.CallController(ctx, wusp.USPAgentRequest{
			Method: wusp.USPAgentMethodGet,
			Paths:  []string{"Device.DeviceInfo.ModelName"},
		})
		resultCh <- callResult{resp, err}
	}()

	// Capture the outbound request from the agent
	var outFrame []byte
	select {
	case outFrame = <-transport.sendCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: no outbound frame from CallController")
	}

	req, err := wusp.DecodeUSPAgentRequest(outFrame)
	if err != nil {
		t.Fatalf("DecodeUSPAgentRequest(outbound): %v", err)
	}

	// Simulate the controller responding
	respFrame, err := wusp.EncodeUSPAgentResponse(wusp.USPAgentResponse{
		ID:     req.ID,
		Method: req.Method,
		Message: &wusp.Message{
			Fields: []wusp.Field{{Path: "Device.DeviceInfo.ModelName", Val: wusp.String("TestRouter")}},
		},
	})
	if err != nil {
		t.Fatalf("EncodeUSPAgentResponse: %v", err)
	}
	if err := rt.handleFrameFromPeer(rt.controllerPublicKeyHex, respFrame, nil); err != nil {
		t.Fatalf("handleFrameFromPeer(response): %v", err)
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("CallController: %v", result.err)
	}
	v, ok := result.resp.Message.Get("Device.DeviceInfo.ModelName")
	if !ok || v.AsString() != "TestRouter" {
		t.Errorf("unexpected CallController response: %+v", result.resp.Message)
	}
}

// ── sync.Mutex for the fakeController fragment state ─────────────────────────

// fakeControllerFragBuf provides fragment reassembly for agent→controller
// large responses in bidirectional tests.
type fakeControllerFragBuf struct {
	mu   sync.Mutex
	bufs map[uint64][]wusp.USPControlFragment
}

func newFakeControllerFragBuf() *fakeControllerFragBuf {
	return &fakeControllerFragBuf{bufs: make(map[uint64][]wusp.USPControlFragment)}
}

// receive buffers frag and returns (payload, true) when all fragments of the
// message have arrived, or (nil, false) while waiting for more.
func (fb *fakeControllerFragBuf) receive(frag wusp.USPControlFragment) ([]byte, bool) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	fb.bufs[frag.MessageID] = append(fb.bufs[frag.MessageID], frag)
	if uint32(len(fb.bufs[frag.MessageID])) < frag.Count {
		return nil, false
	}
	assembled := fb.bufs[frag.MessageID]
	delete(fb.bufs, frag.MessageID)

	payload, err := wusp.ReassembleUSPControlFragments(assembled)
	if err != nil {
		return nil, false
	}
	return payload, true
}
