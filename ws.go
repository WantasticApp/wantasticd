package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/publicsuffix"
)

// portalPeerMeta holds display metadata for a peer received from the portal WebSocket.
type portalPeerMeta struct {
	Name      string
	Hostname  string
	IsOnline  bool
	Latency   int64
	RxBytes   uint64
	TxBytes   uint64
	AssignedIP string
}

// portalWSClient connects to the Wantastic portal WebSocket (/ws endpoint) to
// receive real-time peer metadata and stats that WireGuard alone doesn't provide.
//
// Protocol (from portal websocket.ts):
//   - WS URL: wss://<portal>/ws
//   - Auth: auth_session cookie obtained via GET /api/device-handoff?t=<token>
//   - Heartbeat: {"type":"ping"} ↔ {"type":"pong"} every 15 s
//   - gRPC-over-WS: {id, service, method, request} → {id, type:"response", response:{...}}
//   - Real-time push: {type:"peer_event"|"peer_status"|"stats_update"|"status_change", payload:{...}}
type portalWSClient struct {
	mu    sync.RWMutex
	peers map[string]portalPeerMeta // key = WireGuard public key (base64)

	// gRPC-over-WS pending requests
	pendingMu sync.Mutex
	pending   map[string]chan json.RawMessage

	cancel context.CancelFunc
}

func newPortalWSClient() *portalWSClient {
	return &portalWSClient{
		peers:   make(map[string]portalPeerMeta),
		pending: make(map[string]chan json.RawMessage),
	}
}

// peerMeta returns display metadata for the given WireGuard public key.
func (pw *portalWSClient) peerMeta(pubKey string) portalPeerMeta {
	pw.mu.RLock()
	defer pw.mu.RUnlock()
	return pw.peers[pubKey]
}

// start launches a persistent WebSocket connection to the portal.
// sessionToken is the value returned by RegisterDevice (used to obtain the auth_session cookie).
func (pw *portalWSClient) start(parentCtx context.Context, sessionToken string) {
	if sessionToken == "" {
		return
	}
	pw.mu.Lock()
	if pw.cancel != nil {
		pw.cancel()
	}
	ctx, cancel := context.WithCancel(parentCtx)
	pw.cancel = cancel
	pw.mu.Unlock()

	go pw.runLoop(ctx, sessionToken)
}

func (pw *portalWSClient) stop() {
	pw.mu.Lock()
	if pw.cancel != nil {
		pw.cancel()
		pw.cancel = nil
	}
	pw.mu.Unlock()
}

func (pw *portalWSClient) runLoop(ctx context.Context, sessionToken string) {
	// First exchange the session token for the auth_session cookie
	jar, err := pw.doDeviceHandoff(ctx, sessionToken)
	if err != nil {
		log.Printf("portalWS: device-handoff failed (%v) — will use raw token as fallback", err)
	}

	backoff := 3 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := pw.connect(ctx, sessionToken, jar); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("portalWS: disconnected (%v) — reconnecting in %s", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			jitter := time.Duration(rand.Int63n(int64(backoff / 4)))
			backoff += jitter
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		} else {
			backoff = 3 * time.Second
		}
	}
}

// doDeviceHandoff performs GET /api/device-handoff?t=<token> to exchange the
// session token for an auth_session cookie. Returns a jar with all cookies set
// by the response (including redirects).
func (pw *portalWSClient) doDeviceHandoff(ctx context.Context, sessionToken string) (http.CookieJar, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	handoffURL := portalBaseURL() + "/api/device-handoff?t=" + sessionToken
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, handoffURL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET device-handoff: %w", err)
	}
	resp.Body.Close()
	return jar, nil
}

func (pw *portalWSClient) connect(ctx context.Context, sessionToken string, jar http.CookieJar) error {
	base := portalBaseURL()
	wsURL := ""
	if strings.HasPrefix(base, "https://") {
		wsURL = "wss://" + base[8:] + "/ws"
	} else if strings.HasPrefix(base, "http://") {
		wsURL = "ws://" + base[7:] + "/ws"
	} else {
		wsURL = "wss://" + base + "/ws"
	}

	// Build cookie header from jar + fallback raw token
	cookieHdr := "auth_session=" + sessionToken + "; tenant_session=" + sessionToken
	if jar != nil {
		u, err := url.Parse(base)
		if err == nil {
			cookies := jar.Cookies(u)
			parts := make([]string, 0, len(cookies)+2)
			for _, c := range cookies {
				parts = append(parts, c.Name+"="+c.Value)
			}
			if len(parts) > 0 {
				cookieHdr = strings.Join(parts, "; ")
			}
		}
	}

	headers := http.Header{
		"Cookie":     {cookieHdr},
		"User-Agent": {"WantasticAgent/1.0"},
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}

	conn, resp, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return fmt.Errorf("dial %s (HTTP %d): %w", wsURL, status, err)
	}
	defer conn.Close()

	log.Printf("portalWS: connected to %s", wsURL)

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		return nil
	})

	// Fetch peer list right after connection
	go pw.fetchPeerList(ctx, conn)

	pingTicker := time.NewTicker(15 * time.Second)
	defer pingTicker.Stop()

	msgCh := make(chan []byte, 64)
	errCh := make(chan error, 1)
	go func() {
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			select {
			case msgCh <- data:
			default:
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			return nil
		case err := <-errCh:
			return err
		case <-pingTicker.C:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = conn.WriteJSON(map[string]string{"type": "ping"})
		case data := <-msgCh:
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			pw.handleMessage(conn, data)
		}
	}
}

// wsMsg is the portal WebSocket message envelope.
type wsMsg struct {
	Type      string          `json:"type"`
	ID        string          `json:"id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Response  json.RawMessage `json:"response,omitempty"`
	Error     string          `json:"error,omitempty"`
}

func (pw *portalWSClient) handleMessage(conn *websocket.Conn, data []byte) {
	var msg wsMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}

	switch msg.Type {
	case "pong":
		// keepalive ack

	case "response":
		pw.deliverPending(msg.ID, msg.Response, false)

	case "error":
		pw.deliverPending(msg.ID, nil, true)
		if msg.Error != "" {
			log.Printf("portalWS: gRPC error [%s]: %s", msg.ID, msg.Error)
		}

	case "peer_status":
		// {peerId, isOnline, latency, transferRx, transferTx}
		var p struct {
			PeerID     string `json:"peerId"`
			IsOnline   bool   `json:"isOnline"`
			Latency    int64  `json:"latency"`
			TransferRx uint64 `json:"transferRx"`
			TransferTx uint64 `json:"transferTx"`
		}
		if err := json.Unmarshal(msg.Payload, &p); err == nil && p.PeerID != "" {
			pw.mu.Lock()
			m := pw.peers[p.PeerID]
			m.IsOnline = p.IsOnline
			if p.Latency > 0 {
				m.Latency = p.Latency
			}
			if p.TransferRx > 0 {
				m.RxBytes = p.TransferRx
			}
			if p.TransferTx > 0 {
				m.TxBytes = p.TransferTx
			}
			pw.peers[p.PeerID] = m
			pw.mu.Unlock()
		}

	case "peer_event":
		// {type, peerId, data:{name?, hostname?, isOnline?}}
		var ev struct {
			Type   string `json:"type"`
			PeerID string `json:"peerId"`
			Data   struct {
				Name     string `json:"name"`
				Hostname string `json:"hostname"`
				IsOnline *bool  `json:"isOnline"`
			} `json:"data"`
		}
		if err := json.Unmarshal(msg.Payload, &ev); err == nil && ev.PeerID != "" {
			pw.mu.Lock()
			m := pw.peers[ev.PeerID]
			if ev.Data.Name != "" {
				m.Name = ev.Data.Name
			}
			if ev.Data.Hostname != "" {
				m.Hostname = ev.Data.Hostname
			}
			if ev.Data.IsOnline != nil {
				m.IsOnline = *ev.Data.IsOnline
			}
			pw.peers[ev.PeerID] = m
			pw.mu.Unlock()
		}

	case "status_change":
		// {peerId, isOnline, is_online}
		var sc struct {
			PeerID   string `json:"peerId"`
			IsOnline *bool  `json:"isOnline"`
			IsOnline2 *bool `json:"is_online"`
		}
		if err := json.Unmarshal(msg.Payload, &sc); err == nil && sc.PeerID != "" {
			online := sc.IsOnline
			if online == nil {
				online = sc.IsOnline2
			}
			if online != nil {
				pw.mu.Lock()
				m := pw.peers[sc.PeerID]
				m.IsOnline = *online
				pw.peers[sc.PeerID] = m
				pw.mu.Unlock()
			}
		}

	case "stats_update":
		// {peers:[{peerId, isOnline, latency, transferRx, transferTx}]}
		var stats struct {
			Peers []struct {
				PeerID     string `json:"peerId"`
				IsOnline   bool   `json:"isOnline"`
				Latency    int64  `json:"latency"`
				TransferRx uint64 `json:"transferRx"`
				TransferTx uint64 `json:"transferTx"`
			} `json:"peers"`
		}
		if err := json.Unmarshal(msg.Payload, &stats); err == nil {
			pw.mu.Lock()
			for _, p := range stats.Peers {
				m := pw.peers[p.PeerID]
				m.IsOnline = p.IsOnline
				if p.Latency > 0 {
					m.Latency = p.Latency
				}
				if p.TransferRx > 0 {
					m.RxBytes = p.TransferRx
				}
				if p.TransferTx > 0 {
					m.TxBytes = p.TransferTx
				}
				pw.peers[p.PeerID] = m
			}
			pw.mu.Unlock()
		}
	}
}

func (pw *portalWSClient) deliverPending(id string, resp json.RawMessage, isErr bool) {
	pw.pendingMu.Lock()
	ch, ok := pw.pending[id]
	if ok {
		delete(pw.pending, id)
	}
	pw.pendingMu.Unlock()
	if !ok {
		return
	}
	if isErr {
		close(ch)
	} else {
		select {
		case ch <- resp:
		default:
		}
	}
}

// callGRPC sends a gRPC-over-WS call and waits for the response (max 20 s).
func (pw *portalWSClient) callGRPC(ctx context.Context, conn *websocket.Conn, service, method string, request interface{}) (json.RawMessage, error) {
	reqID := fmt.Sprintf("%s-%s-%d", service, method, time.Now().UnixNano())
	ch := make(chan json.RawMessage, 1)

	pw.pendingMu.Lock()
	pw.pending[reqID] = ch
	pw.pendingMu.Unlock()

	payload, _ := json.Marshal(request)
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteJSON(map[string]interface{}{
		"id":        reqID,
		"service":   service,
		"method":    method,
		"request":   json.RawMessage(payload),
		"timestamp": time.Now().Format(time.RFC3339),
	}); err != nil {
		pw.pendingMu.Lock()
		delete(pw.pending, reqID)
		pw.pendingMu.Unlock()
		return nil, fmt.Errorf("send: %w", err)
	}

	select {
	case <-ctx.Done():
		pw.pendingMu.Lock()
		delete(pw.pending, reqID)
		pw.pendingMu.Unlock()
		return nil, ctx.Err()
	case <-time.After(20 * time.Second):
		pw.pendingMu.Lock()
		delete(pw.pending, reqID)
		pw.pendingMu.Unlock()
		return nil, fmt.Errorf("timeout: %s.%s", service, method)
	case resp, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("gRPC error: %s.%s", service, method)
		}
		return resp, nil
	}
}

// fetchPeerList calls TenantPeerService.ListTenantPeers to load peer names.
func (pw *portalWSClient) fetchPeerList(ctx context.Context, conn *websocket.Conn) {
	time.Sleep(500 * time.Millisecond)

	resp, err := pw.callGRPC(ctx, conn, "TenantPeerService", "ListTenantPeers",
		map[string]string{"tenant_id": ""})
	if err != nil {
		log.Printf("portalWS: ListTenantPeers failed: %v", err)
		return
	}

	// Response: {"peers":[{id, name, public_key, assigned_ip, is_online, ...}]}
	var result struct {
		Peers []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			PublicKey  string `json:"public_key"`
			AssignedIP string `json:"assigned_ip"`
			Hostname   string `json:"hostname"`
			IsOnline   bool   `json:"is_online"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		log.Printf("portalWS: parse peer list: %v", err)
		return
	}

	pw.mu.Lock()
	for _, p := range result.Peers {
		if p.PublicKey == "" {
			continue
		}
		m := pw.peers[p.PublicKey]
		if p.Name != "" {
			m.Name = p.Name
		}
		if p.AssignedIP != "" {
			m.AssignedIP = p.AssignedIP
		}
		if p.Hostname != "" {
			m.Hostname = p.Hostname
		}
		m.IsOnline = p.IsOnline
		pw.peers[p.PublicKey] = m
	}
	pw.mu.Unlock()

	log.Printf("portalWS: loaded %d peers from portal", len(result.Peers))
}
