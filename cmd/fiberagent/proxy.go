package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// proxyBridge relays a curated subset of the agent's local IPC API
// (127.0.0.1:9034) to browser pages on the OLT web UI. The bridge is
// CORS-allowlisted to the OLT origin only (configurable), so arbitrary
// websites cannot drive the agent. Operations are limited to the ones the
// OLT onboarding dashboard needs: status, exit node, local access.
type proxyBridge struct {
	agentBase  string // e.g. http://127.0.0.1:9034
	corsOrigin string // e.g. http://192.168.100.100
	client     *http.Client
}

func newProxyBridge(agentBase, corsOrigin string) *proxyBridge {
	if agentBase == "" {
		agentBase = "http://127.0.0.1:9034"
	}
	return &proxyBridge{
		agentBase:  strings.TrimRight(agentBase, "/"),
		corsOrigin: corsOrigin,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// register wires the bridge endpoints into the onboarding mux.
func (b *proxyBridge) register(mux *http.ServeMux) {
	mux.HandleFunc("/api/agent/status", b.relay("GET", "/api/status"))
	mux.HandleFunc("/api/agent/exitnode/toggle", b.relay("POST", "/api/exitnode/toggle"))
	mux.HandleFunc("/api/agent/localaccess", b.relay("POST", "/api/localaccess"))
	mux.HandleFunc("/api/agent/state/toggle", b.relay("POST", "/api/state/toggle"))
}

// relay proxies one IPC endpoint verbatim (JSON passthrough).
func (b *proxyBridge) relay(method, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.corsHeaders(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body := io.LimitReader(r.Body, 64<<10)
		req, err := http.NewRequestWithContext(r.Context(), method, b.agentBase+path, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := b.client.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("agent unreachable: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 4<<20))
	}
}

// corsHeaders allows only the configured origin (default: the OLT origin).
func (b *proxyBridge) corsHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowed := b.corsOrigin
	if allowed == "" {
		allowed = "http://192.168.100.100"
	}
	if origin != "" && origin == allowed {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

// oltShell runs commands on the OLT over its debug telnetd and returns the
// combined output. Credentials come from flags; empty host disables the
// channel.
type oltShell struct {
	host string
	user string
	pass string
}

func (s *oltShell) exec(cmds ...string) (string, error) {
	if s == nil || s.host == "" {
		return "", fmt.Errorf("olt shell not configured")
	}
	conn, err := net.DialTimeout("tcp", s.host, 8*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 4096)
	read := func(wait time.Duration) string {
		var out strings.Builder
		conn.SetReadDeadline(time.Now().Add(wait))
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		return out.String()
	}
	// login handshake: banner -> "login:" -> user -> "Password:" -> pass
	read(1500 * time.Millisecond)
	if _, err := conn.Write([]byte(s.user + "\r\n")); err != nil {
		return "", err
	}
	read(1200 * time.Millisecond)
	if _, err := conn.Write([]byte(s.pass + "\r\n")); err != nil {
		return "", err
	}
	read(1200 * time.Millisecond)
	var out strings.Builder
	for _, cmd := range cmds {
		if _, err := conn.Write([]byte(cmd + "\r\n")); err != nil {
			return out.String(), err
		}
		out.WriteString(read(2500 * time.Millisecond))
	}
	return out.String(), nil
}

// resetOLTClaim regenerates the device claim key on the OLT and republishes
// the onboarding artifacts (same commands as the user.rcS hook).
func (s *oltShell) resetOLTClaim() error {
	script := "rm -f /mnt/config/wantastic/private.key /mnt/config/wantastic/device-claim-key.json; " +
		"head -c 32 /dev/urandom | /tmp/app/wantasticd-olt genkey > /tmp/wan-gen.out; " +
		"grep '^PRIVATE=' /tmp/wan-gen.out | cut -d= -f2- > /mnt/config/wantastic/private.key; " +
		"PRIV=$(cat /mnt/config/wantastic/private.key); " +
		"/tmp/app/wantasticd-olt pubkey \"$PRIV\" > /tmp/wan-pub.out; " +
		"URL=$(grep '^CLAIMURL=' /tmp/wan-pub.out | cut -d= -f2-); " +
		"cat > /tmp/app/web/wantastic-onboard.js <<WANEOF\nwindow.__WANTASTIC__ = { claim_url: \"$URL\" };\nWANEOF\n; " +
		"rm -f /tmp/wan-gen.out /tmp/wan-pub.out"
	_, err := s.exec(script)
	return err
}

// marshalOK writes a small JSON envelope.
func marshalOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
