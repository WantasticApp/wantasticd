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

	"wantastic-agent/internal/config"
	wgdevice "wantastic-agent/internal/device/wireguard-go/device"
	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/platforms"
)

type uspTransport interface {
	SendWUSPToServer([]byte) error
}

type uspRuntime struct {
	transport              uspTransport
	agent                  *wusp.USPAgent
	controllerPublicKeyHex string
	httpClient             *http.Client
	transferDir            string

	nextID  atomic.Uint64
	pending sync.Map // map[uint64]chan wusp.USPAgentResponse
	streams sync.Map // map[uint64]*uspTransferSession
}

func newUSPRuntime(cfg *config.Config, transport uspTransport) (*uspRuntime, error) {
	if cfg == nil {
		return nil, nil
	}

	controllerPublicKeyHex, err := normalizeWGPublicKeyToHex(cfg.Server.PublicKey)
	if err != nil {
		return nil, err
	}

	backend := platforms.NewBackend(platforms.Options{})
	runtime := &uspRuntime{
		transport:              transport,
		controllerPublicKeyHex: controllerPublicKeyHex,
		httpClient: &http.Client{
			Timeout: 2 * time.Minute,
		},
		transferDir: filepath.Join(os.TempDir(), "wantastic-usp"),
	}
	runtime.agent = wusp.NewUSPAgent(wusp.USPAgentOptions{
		Collector:       backend,
		Setter:          backend,
		UploadHandler:   runtime.handleUpload,
		DownloadHandler: runtime.handleDownload,
	})
	if err := runtime.agent.Bootstrap(wusp.FillOptions{
		Profile:   wusp.FillProfileRealistic,
		DeviceID:  cfg.DeviceID,
		Timestamp: time.Now().UTC(),
		Overwrite: true,
	}); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (r *uspRuntime) HandlePeerPacket(peer *wgdevice.Peer, data []byte) {
	if peer == nil {
		return
	}
	if err := r.handleFrameFromPeer(peer.PublicKeyHex(), data, func(frame []byte) error {
		peer.SendWUSP(frame)
		return nil
	}); err != nil {
		log.Printf("[USP] WUSP frame handling failed: %v", err)
	}
}

func (r *uspRuntime) handleFrameFromPeer(peerPublicKeyHex string, data []byte, reply func([]byte) error) error {
	if r == nil || len(data) == 0 {
		return nil
	}

	if streamFrame, err := wusp.DecodeUSPTransferStreamFrame(data); err == nil {
		return r.handleTransferStreamFrame(peerPublicKeyHex, streamFrame)
	}

	if resp, err := wusp.DecodeUSPAgentResponse(data); err == nil {
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
		return err
	}
	if !r.isControllerPeer(peerPublicKeyHex) {
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

	resp, err := r.agent.HandleRequest(ctx, req)
	if err != nil {
		return err
	}
	frame, err := wusp.EncodeUSPAgentResponse(resp)
	if err != nil {
		return err
	}
	return reply(frame)
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
	return r.controllerPublicKeyHex != "" && strings.EqualFold(strings.TrimSpace(peerPublicKeyHex), r.controllerPublicKeyHex)
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
			"destination": targetPath,
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

	targetPath := firstNonEmpty(strings.TrimSpace(req.Filename), req.Metadata["destination"])
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
			"destination": targetPath,
			"status":      resp.Status,
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

	destination := strings.TrimSpace(req.Metadata["destination"])
	if destination != "" && filepath.Clean(destination) != filepath.Clean(sourcePath) {
		if err := copyFile(sourcePath, destination); err != nil {
			return wusp.USPTransferResult{}, err
		}
		return wusp.USPTransferResult{
			Path:  req.Path,
			URI:   "file://" + sourcePath,
			Bytes: info.Size(),
			Metadata: map[string]string{
				"source":      sourcePath,
				"destination": destination,
			},
		}, nil
	}

	return wusp.USPTransferResult{
		Path:  req.Path,
		URI:   "file://" + sourcePath,
		Bytes: info.Size(),
		Metadata: map[string]string{
			"source": sourcePath,
		},
	}, nil
}

func (r *uspRuntime) uploadBody(req wusp.USPTransferRequest) ([]byte, error) {
	if len(req.Payload) > 0 {
		return append([]byte(nil), req.Payload...), nil
	}
	sourcePath := firstNonEmpty(strings.TrimSpace(req.Metadata["source"]), strings.TrimSpace(req.Filename))
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
