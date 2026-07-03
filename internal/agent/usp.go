package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wantastic-agent/internal/auth"
	"wantastic-agent/internal/config"
	wgdevice "wantastic-agent/internal/device/wireguard-go/device"
	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/platforms"
)

type uspTransport interface {
	SendWUSPToServer([]byte) error
	// IsServerConnected reports whether there is an active WireGuard handshake
	// with the server peer. Used to gate OnBoardRequest sending so we don't
	// fire into the void before the tunnel is up.
	IsServerConnected() bool
}

// uspInitPending / uspInitReady are the two init-state values stored in
// uspRuntime.initState via atomic load/store.
const (
	uspInitPending int32 = 0
	uspInitReady   int32 = 1
)

type uspRuntime struct {
	transport              uspTransport
	agent                  *wusp.USPAgent
	controllerPublicKeyHex string
	deviceID               string
	softwareVersion        string
	httpClient             *http.Client
	transferDir            string
	stats                  uspRuntimeStats

	nextID  atomic.Uint64
	pending sync.Map // map[uint64]chan wusp.USPAgentResponse
	streams sync.Map // map[uint64]*uspTransferSession

	// Initialization state machine.
	initState atomic.Int32
	initReady chan struct{} // closed once initState == uspInitReady
}

type USPRuntimeStats struct {
	InboundFrames              uint64
	InboundBytes               uint64
	InboundRequests            uint64
	InboundResponses           uint64
	UnauthorizedRequests       uint64
	OutboundResponses          uint64
	ResponseFragmentsSent      uint64
	FragmentedResponses        uint64
	TransferFramesSent         uint64
	TransferFrameBytesSent     uint64
	TransferFramesReceived     uint64
	TransferFrameBytesReceived uint64
	TransferSessionsStarted    uint64
	TransferSessionsCompleted  uint64
	TransferSessionsAborted    uint64
	TransferAckTimeouts        uint64
	TransferChunkResends       uint64
	TransferUnknownSessions    uint64
	TransferPayloadBytes       uint64
	TransferDurationTotal      time.Duration
	TransferDurationMax        time.Duration
}

type uspRuntimeStats struct {
	inboundFrames              atomic.Uint64
	inboundBytes               atomic.Uint64
	inboundRequests            atomic.Uint64
	inboundResponses           atomic.Uint64
	unauthorizedRequests       atomic.Uint64
	outboundResponses          atomic.Uint64
	responseFragmentsSent      atomic.Uint64
	fragmentedResponses        atomic.Uint64
	transferFramesSent         atomic.Uint64
	transferFrameBytesSent     atomic.Uint64
	transferFramesReceived     atomic.Uint64
	transferFrameBytesReceived atomic.Uint64
	transferSessionsStarted    atomic.Uint64
	transferSessionsCompleted  atomic.Uint64
	transferSessionsAborted    atomic.Uint64
	transferAckTimeouts        atomic.Uint64
	transferChunkResends       atomic.Uint64
	transferUnknownSessions    atomic.Uint64
	transferPayloadBytes       atomic.Uint64
	transferDurationNS         atomic.Uint64
	transferDurationMaxNS      atomic.Uint64
}

func (r *uspRuntime) StatsSnapshot() USPRuntimeStats {
	if r == nil {
		return USPRuntimeStats{}
	}
	return USPRuntimeStats{
		InboundFrames:              r.stats.inboundFrames.Load(),
		InboundBytes:               r.stats.inboundBytes.Load(),
		InboundRequests:            r.stats.inboundRequests.Load(),
		InboundResponses:           r.stats.inboundResponses.Load(),
		UnauthorizedRequests:       r.stats.unauthorizedRequests.Load(),
		OutboundResponses:          r.stats.outboundResponses.Load(),
		ResponseFragmentsSent:      r.stats.responseFragmentsSent.Load(),
		FragmentedResponses:        r.stats.fragmentedResponses.Load(),
		TransferFramesSent:         r.stats.transferFramesSent.Load(),
		TransferFrameBytesSent:     r.stats.transferFrameBytesSent.Load(),
		TransferFramesReceived:     r.stats.transferFramesReceived.Load(),
		TransferFrameBytesReceived: r.stats.transferFrameBytesReceived.Load(),
		TransferSessionsStarted:    r.stats.transferSessionsStarted.Load(),
		TransferSessionsCompleted:  r.stats.transferSessionsCompleted.Load(),
		TransferSessionsAborted:    r.stats.transferSessionsAborted.Load(),
		TransferAckTimeouts:        r.stats.transferAckTimeouts.Load(),
		TransferChunkResends:       r.stats.transferChunkResends.Load(),
		TransferUnknownSessions:    r.stats.transferUnknownSessions.Load(),
		TransferPayloadBytes:       r.stats.transferPayloadBytes.Load(),
		TransferDurationTotal:      time.Duration(r.stats.transferDurationNS.Load()),
		TransferDurationMax:        time.Duration(r.stats.transferDurationMaxNS.Load()),
	}
}

func (r *uspRuntime) recordTransferDuration(duration time.Duration) {
	if r == nil || duration <= 0 {
		return
	}
	value := uint64(duration)
	r.stats.transferDurationNS.Add(value)
	observeUSPUint64Max(&r.stats.transferDurationMaxNS, value)
}

func (r *uspRuntime) recordTransferSessionStart() {
	if r == nil {
		return
	}
	r.stats.transferSessionsStarted.Add(1)
}

func (r *uspRuntime) recordTransferSessionComplete(session *uspTransferSession) {
	if r == nil || session == nil {
		return
	}
	r.stats.transferSessionsCompleted.Add(1)
	r.stats.transferPayloadBytes.Add(uint64(maxInt64(session.transferred, 0)))
	r.recordTransferDuration(time.Since(session.startedAt))
	log.Printf("[USP] transfer session completed: peer=%s session=%d method=%s bytes=%d duration=%s",
		session.peerPublicKeyHex, session.id, session.method.String(), session.transferred, time.Since(session.startedAt))
}

func (r *uspRuntime) recordTransferSessionAbort(session *uspTransferSession, err error) {
	if r == nil || session == nil {
		return
	}
	r.stats.transferSessionsAborted.Add(1)
	r.recordTransferDuration(time.Since(session.startedAt))
	if err != nil {
		log.Printf("[USP] transfer session aborted: peer=%s session=%d method=%s bytes=%d duration=%s err=%v",
			session.peerPublicKeyHex, session.id, session.method.String(), session.transferred, time.Since(session.startedAt), err)
		return
	}
	log.Printf("[USP] transfer session aborted: peer=%s session=%d method=%s bytes=%d duration=%s",
		session.peerPublicKeyHex, session.id, session.method.String(), session.transferred, time.Since(session.startedAt))
}

func observeUSPUint64Max(target *atomic.Uint64, value uint64) {
	if target == nil {
		return
	}
	for {
		current := target.Load()
		if value <= current {
			return
		}
		if target.CompareAndSwap(current, value) {
			return
		}
	}
}

func newUSPRuntime(cfg *config.Config, transport uspTransport, softwareVersion string) (*uspRuntime, error) {
	if cfg == nil {
		log.Printf("[USP] WUSP disabled: no configuration provided")
		return nil, nil
	}

	controllerPublicKeyHex, err := normalizeWGPublicKeyToHex(cfg.Server.PublicKey)
	if err != nil {
		return nil, err
	}

	wuspSerial := cfg.DeviceID
	if serial, serialErr := auth.PersistentSerialNumber(); serialErr == nil && strings.TrimSpace(serial) != "" {
		wuspSerial = strings.TrimSpace(serial)
	} else if serialErr != nil {
		log.Printf("[USP] persistent serial unavailable, using config device ID: %v", serialErr)
	}

	if controllerPublicKeyHex == "" {
		log.Printf("[USP] WARNING: Server.PublicKey not configured — WUSP accepts any WireGuard peer (open mode)")
	} else {
		log.Printf("[USP] Runtime initializing: deviceID=%q serial=%q controllerKey=%q", cfg.DeviceID, wuspSerial, controllerPublicKeyHex)
	}

	backend := platforms.NewBackend(platforms.Options{})
	runtime := &uspRuntime{
		transport:              transport,
		controllerPublicKeyHex: controllerPublicKeyHex,
		deviceID:               wuspSerial,
		softwareVersion:        softwareVersion,
		httpClient: &http.Client{
			Timeout: 2 * time.Minute,
		},
		transferDir: filepath.Join(os.TempDir(), "wantastic-usp"),
		initReady:   make(chan struct{}),
	}
	runtime.agent = wusp.NewUSPAgent(wusp.USPAgentOptions{
		Collector:       backend,
		Setter:          backend,
		UploadHandler:   runtime.handleUpload,
		DownloadHandler: runtime.handleDownload,
		OperateHandler:  runtime.handleOperate,
		EventSender:     runtime, // uspRuntime implements wusp.USPEventSender
	})
	if err := runtime.agent.Bootstrap(wusp.FillOptions{
		Profile:   wusp.FillProfileRealistic,
		DeviceID:  wuspSerial,
		Timestamp: time.Now().UTC(),
		Overwrite: true,
	}); err != nil {
		return nil, err
	}
	// Override WUSP-specific fields with actual values (Bootstrap fills
	// them with synthetic path-derived placeholders).
	wuspOverrides := map[string]wusp.Value{
		"Device.WUSP.Enable":              wusp.Bool(true),
		"Device.WUSP.Status":              wusp.String("Active"),
		"Device.WUSP.ProtocolVersion":     wusp.String(wusp.WUSPModelVersion),
		"Device.WUSP.MaxControlPayload":   wusp.Uint(uint64(wusp.WUSPMaxDatagramPayload)),
		"Device.WUSP.TunnelOnly":          wusp.Bool(true),
		"Device.WUSP.ReliableControl":     wusp.Bool(false),
		"Device.WUSP.ControlCompression":  wusp.List(wusp.String("nested-message-lz4")),
		"Device.WUSP.TransferCompression": wusp.List(wusp.String("stream-chunk-lz4")),
	}
	for path, val := range wuspOverrides {
		if err := runtime.agent.Set(path, val); err != nil {
			log.Printf("[USP] WARNING: Set(%s) failed: %v", path, err)
		}
	}
	return runtime, nil
}

func (r *uspRuntime) HandlePeerPacket(peer *wgdevice.Peer, data []byte) {
	if peer == nil {
		return
	}
	peerHex := peer.PublicKeyHex()
	log.Printf("[USP] HandlePeerPacket: peer=%s bytes=%d", peerHex, len(data))
	if err := r.handleFrameFromPeer(peerHex, data, func(frame []byte) error {
		log.Printf("[USP] Sending WUSP response: peer=%s bytes=%d", peerHex, len(frame))
		return peer.SendWUSPDatagram(frame)
	}); err != nil {
		log.Printf("[USP] WUSP frame handling failed: peer=%s err=%v", peerHex, err)
	}
}

func (r *uspRuntime) handleFrameFromPeer(peerPublicKeyHex string, data []byte, reply func([]byte) error) error {
	if r == nil || len(data) == 0 {
		return nil
	}
	r.stats.inboundFrames.Add(1)
	r.stats.inboundBytes.Add(uint64(len(data)))

	if streamFrame, err := wusp.DecodeUSPTransferStreamFrame(data); err == nil {
		r.stats.transferFramesReceived.Add(1)
		r.stats.transferFrameBytesReceived.Add(uint64(len(data)))
		log.Printf("[USP] handleFrameFromPeer: stream frame from peer=%s phase=%d", peerPublicKeyHex, streamFrame.Phase)
		return r.handleTransferStreamFrame(peerPublicKeyHex, streamFrame)
	}

	if resp, err := wusp.DecodeUSPAgentResponse(data); err == nil {
		r.stats.inboundResponses.Add(1)
		log.Printf("[USP] handleFrameFromPeer: response id=%d method=%d from peer=%s", resp.ID, resp.Method, peerPublicKeyHex)
		if !r.isControllerPeer(peerPublicKeyHex) {
			return nil
		}
		if r.dispatchResponse(resp) {
			return nil
		}
		return nil
	}

	req, err := wusp.DecodeUSPAgentRequest(data)
	if err != nil {
		isCtrl := r.isControllerPeer(peerPublicKeyHex)
		prefix := data[:min(4, len(data))]
		if isCtrl {
			// Controller sent something we can't decode — worth logging as a warning.
			log.Printf("[USP] handleFrameFromPeer: failed to decode controller request peer=%s bytes=%d err=%v data[0:4]=%x",
				peerPublicKeyHex, len(data), err, prefix)
		} else {
			// Non-controller peer sent something on the WUSP channel (type-8) that is
			// not a valid WUSP payload — likely IP traffic from a P2P peer that has a
			// different interpretation of message type 8. Drop silently.
			log.Printf("[USP] handleFrameFromPeer: ignoring non-WUSP type-8 from non-controller peer=%s bytes=%d data[0:4]=%x (isController=false)",
				peerPublicKeyHex, len(data), prefix)
		}
		return nil // don't propagate — not actionable, prevents HandlePeerPacket error spam
	}
	r.stats.inboundRequests.Add(1)

	log.Printf("[USP] handleFrameFromPeer: request id=%d method=%d from peer=%s isController=%v",
		req.ID, req.Method, peerPublicKeyHex, r.isControllerPeer(peerPublicKeyHex))

	if !r.isControllerPeer(peerPublicKeyHex) {
		r.stats.unauthorizedRequests.Add(1)
		// Authorization failed. Reply with an explicit error so the controller
		// receives an immediate response instead of waiting for a probe timeout.
		// Also log so the operator can diagnose key-mismatch issues.
		log.Printf("[USP] Rejected request method=%d id=%d from peer %s (configured controller=%q)",
			req.Method, req.ID, peerPublicKeyHex, r.controllerPublicKeyHex)
		if reply != nil {
			if encErr := r.replyControlResponse(reply, req, wusp.USPAgentResponse{
				ID:     req.ID,
				Method: req.Method,
				Error:  "unauthorized",
			}); encErr != nil {
				log.Printf("[USP] failed to encode unauthorized reply: %v", encErr)
			}
		}
		return fmt.Errorf("wusp request from unauthorized peer %s", peerPublicKeyHex)
	}

	if reply == nil {
		return fmt.Errorf("missing reply transport for request %d", req.ID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if req.Method == wusp.USPAgentMethodUpload || req.Method == wusp.USPAgentMethodDownload {
		return r.handleTransferControlRequest(ctx, peerPublicKeyHex, req, reply)
	}

	if req.Method == wusp.USPAgentMethodGetSupportedProtocol {
		log.Printf("[USP] Replying GetSupportedProtocol directly: id=%d", req.ID)
		return r.replyControlResponse(reply, req, wusp.USPAgentResponse{
			ID:       req.ID,
			Method:   req.Method,
			Protocol: r.agent.GetSupportedProtocol(),
		})
	}

	log.Printf("[USP] Calling agent.HandleRequest method=%d id=%d", req.Method, req.ID)
	resp, err := r.agent.HandleRequest(ctx, req)
	if err != nil {
		log.Printf("[USP] agent.HandleRequest failed: method=%d id=%d err=%v", req.Method, req.ID, err)
		return err
	}
	frame, err := wusp.EncodeUSPAgentResponse(resp)
	if err != nil {
		// Encoding can fail if the platform backend returned a value whose
		// TypeTag doesn't match the BBF TR-181 schema (e.g. string instead of
		// list).  Send an error response so the controller gets an immediate
		// reply rather than waiting for a round-trip timeout.
		log.Printf("[USP] EncodeUSPAgentResponse failed: method=%d id=%d err=%v — sending error response", req.Method, req.ID, err)
		if encErr := r.replyControlResponse(reply, req, wusp.USPAgentResponse{
			ID:     req.ID,
			Method: req.Method,
			Error:  err.Error(),
		}); encErr == nil {
			return nil
		} else {
			return encErr
		}
	}
	log.Printf("[USP] HandleRequest done: method=%d id=%d response_bytes=%d", req.Method, req.ID, len(frame))
	return r.replyControlPayload(reply, req, frame)
}

func (r *uspRuntime) replyControlResponse(reply func([]byte) error, req wusp.USPAgentRequest, resp wusp.USPAgentResponse) error {
	frame, err := wusp.EncodeUSPAgentResponse(resp)
	if err != nil {
		return err
	}
	return r.replyControlPayload(reply, req, frame)
}

func (r *uspRuntime) replyControlPayload(reply func([]byte) error, req wusp.USPAgentRequest, payload []byte) error {
	if reply == nil {
		return fmt.Errorf("missing reply transport for request %d", req.ID)
	}
	budget := wusp.RequestedResponseMaxControlPayload(req.Metadata, wusp.WUSPMaxDatagramPayload)
	frames, err := wusp.FragmentUSPControlPayload(payload, req.ID, budget)
	if err != nil {
		return err
	}
	r.stats.outboundResponses.Add(1)
	r.stats.responseFragmentsSent.Add(uint64(len(frames)))
	if len(frames) > 1 {
		r.stats.fragmentedResponses.Add(1)
		log.Printf("[USP] fragmented control response: request=%d method=%s budget=%d fragments=%d payload_bytes=%d",
			req.ID, req.Method.String(), budget, len(frames), len(payload))
	}
	for _, frame := range frames {
		if err := reply(frame); err != nil {
			return err
		}
	}
	return nil
}

func (r *uspRuntime) CallController(ctx context.Context, req wusp.USPAgentRequest) (wusp.USPAgentResponse, error) {
	if r == nil || r.transport == nil {
		return wusp.USPAgentResponse{}, fmt.Errorf("usp transport unavailable")
	}
	if r.controllerPublicKeyHex == "" {
		return wusp.USPAgentResponse{}, fmt.Errorf("controller public key not configured")
	}

	if req.ID == 0 {
		req.ID = r.nextID.Add(1)
	}
	frame, err := wusp.EncodeUSPAgentRequest(req)
	if err != nil {
		return wusp.USPAgentResponse{}, err
	}

	waitCh := make(chan wusp.USPAgentResponse, 1)
	r.pending.Store(req.ID, waitCh)
	defer r.pending.Delete(req.ID)

	if err := r.transport.SendWUSPToServer(frame); err != nil {
		return wusp.USPAgentResponse{}, err
	}

	select {
	case <-ctx.Done():
		return wusp.USPAgentResponse{}, ctx.Err()
	case resp := <-waitCh:
		return resp, nil
	}
}

func (r *uspRuntime) dispatchResponse(resp wusp.USPAgentResponse) bool {
	waitCh, ok := r.pending.Load(resp.ID)
	if !ok {
		return false
	}
	ch, ok := waitCh.(chan wusp.USPAgentResponse)
	if !ok {
		return false
	}
	select {
	case ch <- resp:
	default:
	}
	return true
}

func (r *uspRuntime) isControllerPeer(peerPublicKeyHex string) bool {
	if r.controllerPublicKeyHex == "" {
		// No controller key configured — accept requests from any WireGuard peer.
		// WireGuard already authenticates peers at the cryptographic layer, so any
		// packet that reaches this point came from a peer listed in our config.
		return true
	}
	return strings.EqualFold(strings.TrimSpace(peerPublicKeyHex), r.controllerPublicKeyHex)
}

// handleOperate implements TR-181 USP Operate commands. The dashboard sends
// canonical "Device.Foo()" command paths; we route them to platform-specific
// effects. Unsupported commands return ErrUSPPathUnsupported, which the
// controller surfaces back to the dashboard as a clean "not supported" error.
func (r *uspRuntime) handleOperate(ctx context.Context, cmdPath string, _ *wusp.Message, _ map[string]string) (*wusp.Message, error) {
	cmd := strings.TrimSpace(cmdPath)
	log.Printf("[USP] Operate request: %s", cmd)
	switch cmd {
	case "Device.Reboot()":
		// Schedule a reboot a few seconds out so the response can flow back
		// to the controller before the device disappears. Real reboot needs
		// root privileges; if `reboot`/`shutdown` is not on PATH or the
		// process lacks privileges, the OS call fails silently and we just
		// exit the agent (let the supervisor restart us in a cleaner state).
		go func() {
			time.Sleep(2 * time.Second)
			log.Printf("[USP] Executing Device.Reboot()")
			// Best-effort: try `reboot`, fall through to os.Exit for non-root
			// or non-privileged environments where supervisor will respawn us.
			if err := tryReboot(); err != nil {
				log.Printf("[USP] Reboot fallback (process exit): %v", err)
				os.Exit(0)
			}
		}()
		return nil, nil
	case "Device.FactoryReset()":
		// Best-effort: clear the on-disk config and exit. The supervisor
		// (systemd / wantasticd-watch / launchd) restarts the agent in a
		// clean state, which then prompts the user to re-enroll.
		go func() {
			time.Sleep(2 * time.Second)
			log.Printf("[USP] Executing Device.FactoryReset()")
			_ = tryFactoryReset()
			os.Exit(0)
		}()
		return nil, nil
	default:
		return nil, wusp.ErrUSPPathUnsupported
	}
}

// tryReboot attempts to issue a system reboot. Returns an error if no
// reboot mechanism is available; the caller treats that as a signal to
// exit the agent process (supervisor will restart us).
func tryReboot() error {
	// Implementation lives in platform-specific files; here we just return
	// an error so the caller falls back to process exit. Platforms can
	// override via build tags if they need a real reboot.
	return errors.New("native reboot not implemented; exiting for supervisor restart")
}

// tryFactoryReset removes the agent's on-disk config so the supervisor
// restarts it in an unenrolled state.
func tryFactoryReset() error {
	cfgPath := os.Getenv("WANTASTIC_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/wantastic"
	}
	// Best-effort cleanup. We don't hard-fail on missing files because
	// the next start will treat the agent as unenrolled regardless.
	_ = os.RemoveAll(cfgPath + "/config.json")
	_ = os.RemoveAll(cfgPath + "/agent.json")
	return nil
}

func (r *uspRuntime) handleUpload(ctx context.Context, req wusp.USPTransferRequest) (wusp.USPTransferResult, error) {
	switch schemeFromURI(req.URI) {
	case "http", "https":
		return r.httpUpload(ctx, req)
	default:
		return r.localUpload(req)
	}
}

func (r *uspRuntime) handleDownload(ctx context.Context, req wusp.USPTransferRequest) (wusp.USPTransferResult, error) {
	switch schemeFromURI(req.URI) {
	case "http", "https":
		return r.httpDownload(ctx, req)
	default:
		return r.localDownload(req)
	}
}

func (r *uspRuntime) httpUpload(ctx context.Context, req wusp.USPTransferRequest) (wusp.USPTransferResult, error) {
	body, err := r.uploadBody(req)
	if err != nil {
		return wusp.USPTransferResult{}, err
	}

	method := strings.ToUpper(strings.TrimSpace(req.Metadata["method"]))
	if method == "" {
		method = http.MethodPut
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URI, bytes.NewReader(body))
	if err != nil {
		return wusp.USPTransferResult{}, err
	}
	if contentType := strings.TrimSpace(req.ContentType); contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return wusp.USPTransferResult{}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return wusp.USPTransferResult{}, fmt.Errorf("http upload failed: %s", resp.Status)
	}

	return wusp.USPTransferResult{
		Path:  req.Path,
		URI:   req.URI,
		Bytes: int64(len(body)),
		Metadata: map[string]string{
			"status":      resp.Status,
			"contentType": firstNonEmpty(req.ContentType, httpReq.Header.Get("Content-Type")),
		},
	}, nil
}

func (r *uspRuntime) localUpload(req wusp.USPTransferRequest) (wusp.USPTransferResult, error) {
	targetPath := firstNonEmpty(localPathFromURI(req.URI), strings.TrimSpace(req.Filename))
	if targetPath == "" {
		targetPath = filepath.Join(r.transferDirectory(), sanitizeTransferName(req.Path)+".upload")
	}
	body, err := r.uploadBody(req)
	if err != nil {
		return wusp.USPTransferResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return wusp.USPTransferResult{}, err
	}
	if err := os.WriteFile(targetPath, body, 0o644); err != nil {
		return wusp.USPTransferResult{}, err
	}
	return wusp.USPTransferResult{
		Path:  req.Path,
		URI:   "file://" + targetPath,
		Bytes: int64(len(body)),
		Metadata: map[string]string{
			wusp.TransferMetadataDestination: targetPath,
		},
	}, nil
}

func (r *uspRuntime) httpDownload(ctx context.Context, req wusp.USPTransferRequest) (wusp.USPTransferResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URI, nil)
	if err != nil {
		return wusp.USPTransferResult{}, err
	}

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return wusp.USPTransferResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return wusp.USPTransferResult{}, fmt.Errorf("http download failed: %s", resp.Status)
	}

	targetPath := firstNonEmpty(strings.TrimSpace(req.Filename), req.Metadata[wusp.TransferMetadataDestination])
	if targetPath == "" {
		targetPath = filepath.Join(r.transferDirectory(), sanitizeTransferName(req.Path)+".download")
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return wusp.USPTransferResult{}, err
	}
	file, err := os.Create(targetPath)
	if err != nil {
		return wusp.USPTransferResult{}, err
	}
	defer file.Close()

	written, err := io.Copy(file, resp.Body)
	if err != nil {
		return wusp.USPTransferResult{}, err
	}
	return wusp.USPTransferResult{
		Path:  req.Path,
		URI:   req.URI,
		Bytes: written,
		Metadata: map[string]string{
			wusp.TransferMetadataDestination: targetPath,
			"status":                         resp.Status,
		},
	}, nil
}

func (r *uspRuntime) localDownload(req wusp.USPTransferRequest) (wusp.USPTransferResult, error) {
	sourcePath := firstNonEmpty(localPathFromURI(req.URI), strings.TrimSpace(req.Filename))
	if sourcePath == "" {
		return wusp.USPTransferResult{}, fmt.Errorf("local download source not provided")
	}

	info, err := os.Stat(sourcePath)
	if err != nil {
		return wusp.USPTransferResult{}, err
	}

	destination := strings.TrimSpace(req.Metadata[wusp.TransferMetadataDestination])
	if destination != "" && filepath.Clean(destination) != filepath.Clean(sourcePath) {
		if err := copyFile(sourcePath, destination); err != nil {
			return wusp.USPTransferResult{}, err
		}
		return wusp.USPTransferResult{
			Path:  req.Path,
			URI:   "file://" + sourcePath,
			Bytes: info.Size(),
			Metadata: map[string]string{
				wusp.TransferMetadataSource:      sourcePath,
				wusp.TransferMetadataDestination: destination,
			},
		}, nil
	}

	return wusp.USPTransferResult{
		Path:  req.Path,
		URI:   "file://" + sourcePath,
		Bytes: info.Size(),
		Metadata: map[string]string{
			wusp.TransferMetadataSource: sourcePath,
		},
	}, nil
}

func (r *uspRuntime) uploadBody(req wusp.USPTransferRequest) ([]byte, error) {
	if len(req.Payload) > 0 {
		return append([]byte(nil), req.Payload...), nil
	}
	sourcePath := firstNonEmpty(strings.TrimSpace(req.Metadata[wusp.TransferMetadataSource]), strings.TrimSpace(req.Filename))
	if sourcePath == "" {
		return nil, errors.New("upload payload or source file required")
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (r *uspRuntime) transferDirectory() string {
	if strings.TrimSpace(r.transferDir) != "" {
		return r.transferDir
	}
	return os.TempDir()
}

func normalizeWGPublicKeyToHex(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		if len(decoded) != 32 {
			return "", fmt.Errorf("invalid wireguard public key length %d", len(decoded))
		}
		return hex.EncodeToString(decoded), nil
	}
	if len(value) == 64 {
		if _, err := hex.DecodeString(value); err == nil {
			return strings.ToLower(value), nil
		}
	}
	return "", fmt.Errorf("invalid wireguard public key encoding")
}

func schemeFromURI(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return ""
	}
	return strings.ToLower(u.Scheme)
}

func localPathFromURI(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return raw
	}
	switch strings.ToLower(u.Scheme) {
	case "":
		return raw
	case "file":
		return u.Path
	default:
		return ""
	}
}

func sanitizeTransferName(path string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", ".", "_", "{", "", "}", "")
	value := replacer.Replace(strings.TrimSpace(path))
	if value == "" {
		return "transfer"
	}
	return value
}

func copyFile(sourcePath, destinationPath string) error {
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
		return err
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(destinationPath)
	if err != nil {
		return err
	}
	defer destination.Close()

	if _, err := io.Copy(destination, source); err != nil {
		return err
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func maxInt64(values ...int64) int64 {
	var max int64
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

// SendUSPNotify implements wusp.USPEventSender. It delivers encoded WUSP
// Notify payloads (output of wusp.EncodeUSPAgentRequest) to the controller
// over the tunnel. Notifications are fire-and-forget; no response is awaited.
func (r *uspRuntime) SendUSPNotify(ctx context.Context, data []byte) error {
	if r == nil || r.transport == nil {
		return fmt.Errorf("usp transport unavailable")
	}
	return r.transport.SendWUSPToServer(data)
}

// IsReady reports whether WUSP initialization has completed successfully.
func (r *uspRuntime) IsReady() bool {
	return r != nil && r.initState.Load() == uspInitReady
}

// wuspRetryDelay returns the backoff duration for the given attempt number.
// Attempts are grouped in sets of 3; each group uses a larger base delay and
// the delay doubles within the group (expanding margin).
//
//	Group 0 (attempts 0-2):  1s → 2s → 4s
//	Group 1 (attempts 3-5):  8s → 16s → 32s
//	Group 2 (attempts 6-8):  60s → 120s → 240s
//	Group 3+ (attempts 9+):  capped at 5 min
func wuspRetryDelay(attempt int) time.Duration {
	const maxDelay = 5 * time.Minute
	groupBases := [3]time.Duration{
		1 * time.Second,  // group 0
		8 * time.Second,  // group 1
		60 * time.Second, // group 2
	}
	group := attempt / 3
	if group >= len(groupBases) {
		return maxDelay
	}
	delay := groupBases[group] << uint(attempt%3) // base * 2^pos
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

// uspReannounceInterval is how often we re-send OnBoardRequest after the
// initial successful send. This handles controller restarts transparently —
// the controller uses OnBoardRequest as the sole discovery mechanism for new
// WUSP peers (no probing). Must be less than activeHandshakeWindow (8 min)
// so the tunnel is always considered live when the re-announce fires.
const uspReannounceInterval = 2 * time.Minute

// runInit drives the WUSP initialization loop with grouped retry backoff.
// After the first successful OnBoardRequest it keeps re-announcing at
// uspReannounceInterval so the controller always knows this peer is alive
// and WUSP-capable (handles controller restarts transparently).
func (r *uspRuntime) runInit(ctx context.Context) {
	log.Printf("[USP] Starting WUSP initialization")
	for attempt := 0; ; attempt++ {
		if err := r.initializeOnce(ctx); err == nil {
			if !r.IsReady() {
				r.initState.Store(uspInitReady)
				close(r.initReady)
				log.Printf("[USP] WUSP ready (attempt %d)", attempt+1)
			} else {
				log.Printf("[USP] WUSP re-announced OnBoardRequest to controller")
			}
			// Re-announce periodically. Reset backoff counter so the next
			// failure (e.g. controller restart) uses fast initial retries again.
			attempt = -1
			select {
			case <-ctx.Done():
				return
			case <-time.After(uspReannounceInterval):
			}
		} else {
			delay := wuspRetryDelay(attempt)
			log.Printf("[USP] Init failed (attempt %d, group %d): %v — retry in %s",
				attempt+1, attempt/3, err, delay)
			select {
			case <-ctx.Done():
				log.Printf("[USP] Init cancelled: %v", ctx.Err())
				return
			case <-time.After(delay):
			}
		}
	}
}

// initializeOnce performs one WUSP initialization attempt.
//
// WUSP is controller-initiated: the controller sends requests TO the device.
// The device's role at startup is only to ANNOUNCE itself via OnBoardRequest
// (a fire-and-forget notification). We must NOT send requests to the controller
// (e.g. GetSupportedProtocol) — the controller doesn't act as a WUSP endpoint
// that responds to device-originated requests, and doing so causes it to mark
// the device as malfunctioning.
//
// We gate sending on an active WireGuard handshake because peer.SendWUSP drops
// the packet silently when the peer goroutines haven't started yet, and returns
// nil anyway (fire-and-forget). Without this check the init loop would declare
// success immediately and never retry even though the packet was discarded.
func (r *uspRuntime) initializeOnce(ctx context.Context) error {
	connected := r.transport.IsServerConnected()
	log.Printf("[USP] initializeOnce: server_connected=%v deviceID=%q", connected, r.deviceID)
	if !connected {
		return fmt.Errorf("wusp: server tunnel not up (no active WireGuard handshake)")
	}
	log.Printf("[USP] Sending OnBoardRequest to controller")
	err := r.agent.EmitOnBoardRequest(ctx, wusp.USPOnBoardInfo{
		SerialNumber:                   r.deviceID,
		Manufacturer:                   "Wantastic",
		ProductClass:                   "wantasticd",
		SoftwareVersion:                r.softwareVersion,
		AgentSupportedProtocolVersions: wusp.WUSPModelVersion,
	})
	if err != nil {
		log.Printf("[USP] OnBoardRequest emit failed: %v", err)
	}
	return err
}
