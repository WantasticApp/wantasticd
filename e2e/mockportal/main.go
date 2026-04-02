// mockportal is a self-contained HTTP server that simulates the Wantastic
// portal OAuth2 + device-register endpoints for e2e testing.
//
// Endpoints:
//
//	POST /oauth/device/code       RFC 8628 §3.2 — returns device + user codes
//	POST /oauth/token             RFC 8628 §3.5 — pending on 1st poll, token on 2nd
//	POST /api/agent/register      validates HMAC, returns ChaCha20-encrypted WireGuard config
//	GET  /health                  liveness probe
package main

import (
	"golang.org/x/crypto/chacha20poly1305"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ── constants matching wantastic-agent/internal/auth ──────────────────────────

const (
	SharedSecret    = "wantastic_cipher_v_1_0_0"
	HeaderTimestamp = "x-wantastic-ts"
	HeaderDevice    = "x-wantastic-device"
	HeaderSig       = "x-wantastic-sig"
)

// wireguardConfig is the plaintext config that will be delivered encrypted.
// It uses the same keys as the e2e docker-compose client1.conf so the agent
// can connect to the host-side WireGuard server (wg.wantastic.local).
const wireguardConfig = `[Interface]
PrivateKey = eKXmUsd6TCb/anDlf/N5O4BOw4Qc+tw3iSAYZl3E02E=
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = tKB1m94+XsYmTf+8jmLSXze/BL+0clxhIfp0q1VRxUg=
Endpoint = wg.wantastic.local:51820
AllowedIPs = 10.0.0.0/27
PersistentKeepalive = 25
`

// ── per-device poll state (keyed by device_code) ──────────────────────────────

type deviceState struct {
	userCode   string
	verifyURL  string
	expiresAt  time.Time
	pollCount  int32 // atomic
	accessToken string
}

var (
	devicesMu sync.Mutex
	devices   = map[string]*deviceState{}
)

// ── request / response types ─────────────────────────────────────────────────

type credentialsResponse struct {
	Domain   string `json:"domain"`
	ClientID string `json:"client_id"`
}

type deviceCodeRequest struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type tokenSuccessResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type registerRequest struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Nonce    uint64 `json:"nonce"`
}

type registerResponse struct {
	EncryptedConfig []byte `json:"encrypted_config"` // ChaCha20-Poly1305 ciphertext; JSON base64
	Token           string `json:"token"`
	ServerURL       string `json:"server_url,omitempty"`
	HandoffURL      string `json:"handoff_url,omitempty"`
}

// ── helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func encryptConfig(accessToken string, nonce uint64, plaintext string) ([]byte, error) {
	key := sha256.Sum256([]byte(accessToken))
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonceBytes := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonceBytes[:8], nonce)
	return aead.Seal(nil, nonceBytes, []byte(plaintext), nil), nil
}

func verifyHMAC(ts, deviceID, sig string) bool {
	if ts == "" || deviceID == "" || sig == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(SharedSecret))
	mac.Write([]byte(ts + ":" + deviceID))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

// ── handlers ─────────────────────────────────────────────────────────────────

func handleCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ts := r.Header.Get(HeaderTimestamp)
	deviceID := r.Header.Get(HeaderDevice)
	sig := r.Header.Get(HeaderSig)

	if !verifyHMAC(ts, deviceID, sig) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
		return
	}

	// Return the host:port so the agent uses the same base URL (no https:// prefix)
	host := r.Host
	writeJSON(w, http.StatusOK, credentialsResponse{
		Domain:   host,
		ClientID: "e2e-client-id",
	})
}

func handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	deviceCode := fmt.Sprintf("e2e-device-%d", time.Now().UnixNano())
	userCode := "E2E-TEST"
	accessToken := "e2e-access-token-" + deviceCode
	verifyURL := "http://mockportal:8080/activate?user_code=" + userCode

	state := &deviceState{
		userCode:    userCode,
		verifyURL:   verifyURL,
		expiresAt:   time.Now().Add(5 * time.Minute),
		accessToken: accessToken,
	}

	devicesMu.Lock()
	devices[deviceCode] = state
	devicesMu.Unlock()

	writeJSON(w, http.StatusOK, deviceCodeResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verifyURL,
		VerificationURIComplete: verifyURL,
		ExpiresIn:               300,
		Interval:                1, // 1 second for fast e2e
	})
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "urn:ietf:params:oauth:grant-type:device_code" {
		writeJSON(w, http.StatusBadRequest, tokenErrorResponse{Error: "unsupported_grant_type"})
		return
	}

	deviceCode := r.FormValue("device_code")
	devicesMu.Lock()
	state, ok := devices[deviceCode]
	devicesMu.Unlock()

	if !ok || time.Now().After(state.expiresAt) {
		writeJSON(w, http.StatusBadRequest, tokenErrorResponse{Error: "expired_token"})
		return
	}

	count := atomic.AddInt32(&state.pollCount, 1)
	if count < 2 {
		// Simulate "user hasn't approved yet" on first poll
		writeJSON(w, http.StatusBadRequest, tokenErrorResponse{Error: "authorization_pending"})
		return
	}

	writeJSON(w, http.StatusOK, tokenSuccessResponse{
		AccessToken: state.accessToken,
		TokenType:   "bearer",
	})
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate Bearer token
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return
	}
	accessToken := authHeader[7:]

	// Validate HMAC signing headers
	ts := r.Header.Get(HeaderTimestamp)
	deviceID := r.Header.Get(HeaderDevice)
	sig := r.Header.Get(HeaderSig)

	if !verifyHMAC(ts, deviceID, sig) {
		log.Printf("[mockportal] HMAC validation failed: ts=%q device=%q sig=%q", ts, deviceID, sig)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
		return
	}

	// Reject stale timestamps (>5 minutes)
	tsUnix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || abs(time.Now().Unix()-tsUnix) > 300 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "timestamp out of range"})
		return
	}

	// Decode request body
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}

	log.Printf("[mockportal] Register: hostname=%q os=%q arch=%q nonce=%d", req.Hostname, req.OS, req.Arch, req.Nonce)

	// Encrypt the WireGuard config for this device
	ciphertext, err := encryptConfig(accessToken, req.Nonce, wireguardConfig)
	if err != nil {
		log.Printf("[mockportal] encrypt error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, registerResponse{
		EncryptedConfig: ciphertext,
		Token:           "e2e-session-token",
		HandoffURL:      "http://mockportal:8080/console?device=" + deviceID,
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	addr := ":8080"
	if v := os.Getenv("MOCKPORTAL_ADDR"); v != "" {
		addr = v
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/agent/credentials", handleCredentials)
	mux.HandleFunc("/oauth/device/code", handleDeviceCode)
	mux.HandleFunc("/oauth/token", handleToken)
	mux.HandleFunc("/api/agent/register", handleRegister)
	mux.HandleFunc("/health", handleHealth)

	log.Printf("[mockportal] Listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[mockportal] fatal: %v", err)
	}
}
