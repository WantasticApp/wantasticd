package agent

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"wantastic-agent/internal/config"
	"wantastic-agent/internal/wusp"
)

type fakeUSPTransport struct {
	sendCh chan []byte
}

func (t *fakeUSPTransport) SendWUSPToServer(data []byte) error {
	if t.sendCh == nil {
		return errors.New("send channel not configured")
	}
	frame := append([]byte(nil), data...)
	t.sendCh <- frame
	return nil
}

func (t *fakeUSPTransport) IsServerConnected() bool { return true }

func TestUSPRuntimeHandlesControllerRequest(t *testing.T) {
	runtime := newTestUSPRuntime(t)

	reqFrame, err := wusp.EncodeUSPAgentRequest(wusp.USPAgentRequest{
		ID:     42,
		Method: wusp.USPAgentMethodGet,
		Paths:  []string{"Device.DeviceInfo.HostName"},
	})
	if err != nil {
		t.Fatalf("EncodeUSPAgentRequest: %v", err)
	}

	var respFrame []byte
	err = runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, reqFrame, func(frame []byte) error {
		respFrame = append([]byte(nil), frame...)
		return nil
	})
	if err != nil {
		t.Fatalf("handleFrameFromPeer: %v", err)
	}

	resp, err := wusp.DecodeUSPAgentResponse(respFrame)
	if err != nil {
		t.Fatalf("DecodeUSPAgentResponse: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("response error=%q", resp.Error)
	}
	if resp.Message == nil {
		t.Fatal("response message missing")
	}
	value, ok := resp.Message.Get("Device.DeviceInfo.HostName")
	if !ok {
		t.Fatal("Device.DeviceInfo.HostName missing from response")
	}
	if value.AsString() == "" {
		t.Fatal("Device.DeviceInfo.HostName is empty")
	}
}

func TestUSPRuntimeCallController(t *testing.T) {
	runtime := newTestUSPRuntime(t)
	transport := runtime.transport.(*fakeUSPTransport)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	var resp wusp.USPAgentResponse
	var err error
	go func() {
		defer close(done)
		resp, err = runtime.CallController(ctx, wusp.USPAgentRequest{
			Method: wusp.USPAgentMethodGet,
			Paths:  []string{"Device.DeviceInfo.ModelName"},
		})
	}()

	requestFrame := <-transport.sendCh
	req, decodeErr := wusp.DecodeUSPAgentRequest(requestFrame)
	if decodeErr != nil {
		t.Fatalf("DecodeUSPAgentRequest: %v", decodeErr)
	}

	responseFrame, encodeErr := wusp.EncodeUSPAgentResponse(wusp.USPAgentResponse{
		ID:     req.ID,
		Method: req.Method,
		Message: &wusp.Message{
			Fields: []wusp.Field{{Path: "Device.DeviceInfo.ModelName", Val: wusp.String("Wantastic Test Node")}},
		},
	})
	if encodeErr != nil {
		t.Fatalf("EncodeUSPAgentResponse: %v", encodeErr)
	}

	if handleErr := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, responseFrame, nil); handleErr != nil {
		t.Fatalf("handleFrameFromPeer(response): %v", handleErr)
	}
	<-done

	if err != nil {
		t.Fatalf("CallController: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("controller response error=%q", resp.Error)
	}
	value, ok := resp.Message.Get("Device.DeviceInfo.ModelName")
	if !ok || value.AsString() != "Wantastic Test Node" {
		t.Fatalf("unexpected controller response message: %#v", resp.Message)
	}
}

func TestUSPRuntimeUploadAndDownload(t *testing.T) {
	runtime := newTestUSPRuntime(t)
	root := t.TempDir()

	uploadTarget := filepath.Join(root, "uploaded.bin")
	uploadResult, err := runtime.handleUpload(context.Background(), wusp.USPTransferRequest{
		Path:    "Device.DeviceInfo.ProvisioningCode",
		URI:     "file://" + uploadTarget,
		Payload: []byte("hello-world"),
	})
	if err != nil {
		t.Fatalf("handleUpload(local): %v", err)
	}
	data, err := os.ReadFile(uploadTarget)
	if err != nil {
		t.Fatalf("ReadFile(uploadTarget): %v", err)
	}
	if string(data) != "hello-world" {
		t.Fatalf("upload target=%q want %q", string(data), "hello-world")
	}
	if uploadResult.Bytes != int64(len(data)) {
		t.Fatalf("upload bytes=%d want %d", uploadResult.Bytes, len(data))
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("downloaded-data"))
	}))
	defer server.Close()

	downloadTarget := filepath.Join(root, "downloaded.bin")
	downloadResult, err := runtime.handleDownload(context.Background(), wusp.USPTransferRequest{
		Path:     "Device.DeviceInfo.ProvisioningCode",
		URI:      server.URL,
		Filename: downloadTarget,
	})
	if err != nil {
		t.Fatalf("handleDownload(http): %v", err)
	}
	downloaded, err := os.ReadFile(downloadTarget)
	if err != nil {
		t.Fatalf("ReadFile(downloadTarget): %v", err)
	}
	if string(downloaded) != "downloaded-data" {
		t.Fatalf("download target=%q want %q", string(downloaded), "downloaded-data")
	}
	if downloadResult.Bytes != int64(len(downloaded)) {
		t.Fatalf("download bytes=%d want %d", downloadResult.Bytes, len(downloaded))
	}
}

func TestUSPRuntimeTunnelTransferUpload(t *testing.T) {
	runtime := newTestUSPRuntime(t)
	root := t.TempDir()
	target := filepath.Join(root, "stream-upload.bin")
	payload := bytes.Repeat([]byte("UPLOAD-CHUNK-"), 1024)

	reqFrame, err := wusp.EncodeUSPAgentRequest(wusp.USPAgentRequest{
		ID:     77,
		Method: wusp.USPAgentMethodUpload,
		Transfer: &wusp.USPTransferRequest{
			Path: "Device.DeviceInfo.ProvisioningCode",
			URI:  "file://" + target,
			Metadata: map[string]string{
				"size": strconv.Itoa(len(payload)),
			},
		},
	})
	if err != nil {
		t.Fatalf("EncodeUSPAgentRequest(upload) returned error: %v", err)
	}

	replyFrames := make([][]byte, 0, 8)
	replyFn := func(frame []byte) error {
		replyFrames = append(replyFrames, append([]byte(nil), frame...))
		return nil
	}
	if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, reqFrame, func(frame []byte) error {
		return replyFn(frame)
	}); err != nil {
		t.Fatalf("handleFrameFromPeer(upload control) returned error: %v", err)
	}
	if len(replyFrames) != 1 {
		t.Fatalf("replyFrames=%d want=1", len(replyFrames))
	}
	resp, err := wusp.DecodeUSPAgentResponse(replyFrames[0])
	if err != nil {
		t.Fatalf("DecodeUSPAgentResponse(upload) returned error: %v", err)
	}
	sessionID, err := strconv.ParseUint(resp.Transfer.Metadata["session_id"], 10, 64)
	if err != nil {
		t.Fatalf("ParseUint(session_id) returned error: %v", err)
	}

	openFrame, _ := wusp.EncodeUSPTransferStreamFrame(wusp.USPTransferStreamFrame{
		SessionID: sessionID,
		RequestID: 77,
		Method:    wusp.USPAgentMethodUpload,
		Phase:     wusp.USPTransferStreamOpen,
		Path:      "Device.DeviceInfo.ProvisioningCode",
	})
	if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, openFrame, replyFn); err != nil {
		t.Fatalf("handleFrameFromPeer(upload open) returned error: %v", err)
	}

	for seq, offset := uint32(1), 0; offset < len(payload); seq++ {
		end := offset + uspRecommendedChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunkFrame, _ := wusp.EncodeUSPTransferStreamFrame(wusp.USPTransferStreamFrame{
			SessionID: sessionID,
			RequestID: 77,
			Method:    wusp.USPAgentMethodUpload,
			Phase:     wusp.USPTransferStreamChunk,
			Sequence:  seq,
			Offset:    uint64(offset),
			TotalSize: uint64(len(payload)),
			Data:      append([]byte(nil), payload[offset:end]...),
			Final:     end == len(payload),
		})
		if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, chunkFrame, replyFn); err != nil {
			t.Fatalf("handleFrameFromPeer(upload chunk %d) returned error: %v", seq, err)
		}
		offset = end
	}

	completeFrame, _ := wusp.EncodeUSPTransferStreamFrame(wusp.USPTransferStreamFrame{
		SessionID: sessionID,
		RequestID: 77,
		Method:    wusp.USPAgentMethodUpload,
		Phase:     wusp.USPTransferStreamComplete,
		Final:     true,
	})
	if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, completeFrame, replyFn); err != nil {
		t.Fatalf("handleFrameFromPeer(upload complete) returned error: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile(target) returned error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("uploaded payload mismatch: got=%dB want=%dB", len(got), len(payload))
	}
	if len(replyFrames) < 2 {
		t.Fatal("expected upload stream ack frames")
	}
}

func TestUSPRuntimeTunnelTransferDownload(t *testing.T) {
	runtime := newTestUSPRuntime(t)
	root := t.TempDir()
	source := filepath.Join(root, "stream-download.bin")
	payload := bytes.Repeat([]byte("DOWNLOAD-CHUNK-"), 1024)
	if err := os.WriteFile(source, payload, 0o644); err != nil {
		t.Fatalf("WriteFile(source) returned error: %v", err)
	}

	reqFrame, err := wusp.EncodeUSPAgentRequest(wusp.USPAgentRequest{
		ID:     91,
		Method: wusp.USPAgentMethodDownload,
		Transfer: &wusp.USPTransferRequest{
			Path: "Device.DeviceInfo.VendorConfigFile.{i}.",
			URI:  "file://" + source,
		},
	})
	if err != nil {
		t.Fatalf("EncodeUSPAgentRequest(download) returned error: %v", err)
	}

	replyCh := make(chan []byte, 64)
	if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, reqFrame, func(frame []byte) error {
		replyCh <- append([]byte(nil), frame...)
		return nil
	}); err != nil {
		t.Fatalf("handleFrameFromPeer(download control) returned error: %v", err)
	}

	first := <-replyCh
	resp, err := wusp.DecodeUSPAgentResponse(first)
	if err != nil {
		t.Fatalf("DecodeUSPAgentResponse(download) returned error: %v", err)
	}
	sessionID, err := strconv.ParseUint(resp.Transfer.Metadata["session_id"], 10, 64)
	if err != nil {
		t.Fatalf("ParseUint(session_id) returned error: %v", err)
	}

	var downloaded []byte
	for {
		select {
		case frame := <-replyCh:
			streamFrame, err := wusp.DecodeUSPTransferStreamFrame(frame)
			if err != nil {
				t.Fatalf("DecodeUSPTransferStreamFrame returned error: %v", err)
			}
			switch streamFrame.Phase {
			case wusp.USPTransferStreamChunk:
				downloaded = append(downloaded, streamFrame.Data...)
				ackFrame, _ := wusp.EncodeUSPTransferStreamFrame(wusp.USPTransferStreamFrame{
					SessionID:   sessionID,
					RequestID:   91,
					Method:      wusp.USPAgentMethodDownload,
					Phase:       wusp.USPTransferStreamAck,
					AckSequence: streamFrame.Sequence,
				})
				if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, ackFrame, nil); err != nil {
					t.Fatalf("handleFrameFromPeer(download ack) returned error: %v", err)
				}
			case wusp.USPTransferStreamComplete:
				if !bytes.Equal(downloaded, payload) {
					t.Fatalf("downloaded payload mismatch: got=%dB want=%dB", len(downloaded), len(payload))
				}
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for streamed download frames")
		}
	}
}

// TestWUSPRetryDelay validates the grouped backoff schedule.
func TestWUSPRetryDelay(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		// Group 0: base 1s, doubles within group
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		// Group 1: base 8s
		{3, 8 * time.Second},
		{4, 16 * time.Second},
		{5, 32 * time.Second},
		// Group 2: base 60s
		{6, 60 * time.Second},
		{7, 120 * time.Second},
		{8, 240 * time.Second},
		// Group 3+: capped at 5 min
		{9, 5 * time.Minute},
		{12, 5 * time.Minute},
		{100, 5 * time.Minute},
	}
	for _, tc := range cases {
		got := wuspRetryDelay(tc.attempt)
		if got != tc.want {
			t.Errorf("wuspRetryDelay(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

// TestUSPRuntimeOnBoardRequestEmit validates that initializeOnce emits a
// well-formed OnBoardRequest frame over the transport.
func TestUSPRuntimeOnBoardRequestEmit(t *testing.T) {
	runtime := newTestUSPRuntime(t)
	transport := runtime.transport.(*fakeUSPTransport)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := runtime.initializeOnce(ctx)
	if err != nil {
		t.Fatalf("initializeOnce: %v", err)
	}

	var frame []byte
	select {
	case frame = <-transport.sendCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: no frame sent by initializeOnce")
	}

	// The frame must decode as a USPAgentRequest with Method == Notify and
	// event_type == 6 (OnBoardRequest).
	req, err := wusp.DecodeUSPAgentRequest(frame)
	if err != nil {
		t.Fatalf("DecodeUSPAgentRequest: %v", err)
	}
	if req.Method != wusp.USPAgentMethodNotify {
		t.Fatalf("method=%v want Notify", req.Method)
	}
	if !wusp.IsEventNotifyRequest(req) {
		t.Fatal("IsEventNotifyRequest returned false for OnBoardRequest frame")
	}

	event, err := wusp.DecodeEventFromRequest(req)
	if err != nil {
		t.Fatalf("DecodeEventFromRequest: %v", err)
	}
	if event.Type != wusp.USPEventTypeOnBoardRequest {
		t.Fatalf("event.Type=%d want %d (OnBoardRequest)", event.Type, wusp.USPEventTypeOnBoardRequest)
	}
	if event.OnBoard == nil {
		t.Fatal("event.OnBoard is nil")
	}
	if event.OnBoard.SerialNumber == "" {
		t.Fatal("event.OnBoard.SerialNumber is empty")
	}
}

// TestUSPRuntimeInitReady verifies that runInit signals initReady once the
// first initializeOnce call succeeds.
func TestUSPRuntimeInitReady(t *testing.T) {
	runtime := newTestUSPRuntime(t)

	if runtime.IsReady() {
		t.Fatal("IsReady() returned true before runInit")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		runtime.runInit(ctx)
		close(done)
	}()

	select {
	case <-runtime.initReady:
		// good
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: initReady never closed")
	}

	if !runtime.IsReady() {
		t.Fatal("IsReady() returned false after runInit succeeded")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout: runInit goroutine did not exit after cancel")
	}
}

// TestUSPRuntimeUnauthorizedPeerRejected verifies that frames from unknown
// peers get an error response rather than being silently dropped, and that
// frames from the authorised controller are processed normally.
func TestUSPRuntimeUnauthorizedPeerRejected(t *testing.T) {
	runtime := newTestUSPRuntime(t)

	reqFrame, err := wusp.EncodeUSPAgentRequest(wusp.USPAgentRequest{
		ID:     99,
		Method: wusp.USPAgentMethodGet,
		Paths:  []string{"Device.DeviceInfo.HostName"},
	})
	if err != nil {
		t.Fatalf("EncodeUSPAgentRequest: %v", err)
	}

	var replyFrame []byte
	err = runtime.handleFrameFromPeer("deadbeef0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", reqFrame, func(frame []byte) error {
		replyFrame = append([]byte(nil), frame...)
		return nil
	})
	// The function should return an error (unauthorized).
	if err == nil {
		t.Fatal("expected error for unauthorized peer, got nil")
	}
	// And it should have sent an error response frame.
	if replyFrame == nil {
		t.Fatal("expected error response frame for unauthorized peer")
	}
	resp, decErr := wusp.DecodeUSPAgentResponse(replyFrame)
	if decErr != nil {
		t.Fatalf("DecodeUSPAgentResponse(error response): %v", decErr)
	}
	if resp.Error == "" {
		t.Fatal("expected non-empty Error in unauthorized response")
	}
}

func newTestUSPRuntime(tb testing.TB) *uspRuntime {
	tb.Helper()

	cfg := &config.Config{
		DeviceID: "test-device",
		Server: config.Server{
			PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
	}
	transport := &fakeUSPTransport{sendCh: make(chan []byte, 4)}
	runtime, err := newUSPRuntime(cfg, transport, "test-0.0.0")
	if err != nil {
		tb.Fatalf("newUSPRuntime: %v", err)
	}
	if runtime == nil {
		tb.Fatal("newUSPRuntime returned nil")
	}
	return runtime
}
