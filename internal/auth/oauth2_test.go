// Package auth_test holds integration tests for the OAuth2 / device-registration flow.
// It starts a mock portal HTTP server and exercises every stage end-to-end.
package auth_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/chacha20poly1305"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"wantastic-agent/internal/auth"
)

func TestMain(m *testing.M) {
	// Eliminate per-poll sleep so tests that exercise multiple rounds finish
	// in milliseconds instead of seconds.
	auth.SetTestPollInterval(0)
	os.Exit(m.Run())
}

// ── test constants ────────────────────────────────────────────────────────────

const (
	testHashedDeviceID = "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
	testClientID       = "wantastic-test-client"
	testAccessToken    = "at_test_access_token_abc123"
	testSessionToken   = "st_session_token_xyz789"
	testGRPCServerURL  = "grpc.wantastic.test:443"
	testHandoffURL     = "https://console.wantastic.test/handoff?t=abc"
	testDeviceCode     = "device_code_test_abc123"
	testUserCode       = "WNTC-TEST"
)

// testWireGuardConfig is the plaintext WireGuard config the mock portal returns.
const testWireGuardConfig = `[Interface]
PrivateKey = mKX5O+XnNJXPJJ8uGCnlbJBMvMUFdmB6aaGMPg0L1WI=
Address = 10.99.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = abc123def456abc123def456abc123def456abc123def456abc123def456abcd
Endpoint = wg.wantastic.test:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

// ── helpers ───────────────────────────────────────────────────────────────────

// encryptForToken encrypts plaintext with the same scheme the portal uses:
//
//	key   = SHA256(accessToken)
//	nonce = little-endian uint64(nonce), zero-padded to 12 bytes
func encryptForToken(t *testing.T, accessToken string, nonce uint64, plaintext []byte) []byte {
	t.Helper()
	hash := sha256.Sum256([]byte(accessToken))
	aead, err := chacha20poly1305.New(hash[:])
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}
	nonceBytes := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonceBytes[:8], nonce)
	return aead.Seal(nil, nonceBytes, plaintext, nil)
}

// verifyHMACHeaders checks that the request carries valid HMAC signing headers.
// Returns false and writes a 400 if any header is missing or the signature is wrong.
func verifyHMACHeaders(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()
	ts := r.Header.Get("x-wantastic-ts")
	device := r.Header.Get("x-wantastic-device")
	sig := r.Header.Get("x-wantastic-sig")

	if ts == "" || device == "" || sig == "" {
		http.Error(w, "missing HMAC headers", http.StatusBadRequest)
		t.Errorf("request to %s missing HMAC headers (ts=%q device=%q sig=%q)", r.URL.Path, ts, device, sig)
		return false
	}

	// Recompute expected signature.
	message := ts + ":" + device
	mac := hmac.New(sha256.New, []byte(auth.SharedSecret))
	mac.Write([]byte(message))
	expected := hex.EncodeToString(mac.Sum(nil))
	if sig != expected {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		t.Errorf("signature mismatch: got %q, want %q", sig, expected)
		return false
	}

	// Timestamp must be a recent unix timestamp.
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		http.Error(w, "bad timestamp", http.StatusBadRequest)
		t.Errorf("bad timestamp %q: %v", ts, err)
		return false
	}
	delta := time.Since(time.Unix(tsInt, 0)).Abs()
	if delta > 30*time.Second {
		t.Errorf("timestamp too old or in the future: delta=%v", delta)
	}
	return true
}

// suppressStderr redirects os.Stderr to /dev/null for the duration of the test
// to keep QR-code and banner output out of the test log.
func suppressStderr(t *testing.T) {
	t.Helper()
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return
	}
	old := os.Stderr
	os.Stderr = devNull
	t.Cleanup(func() {
		os.Stderr = old
		devNull.Close()
	})
}

// ── mock portal constructor ───────────────────────────────────────────────────

// portalConfig controls the mock portal's behaviour.
type portalConfig struct {
	// FetchCredentials
	credDomain   string
	credClientID string

	// Device flow — how many "authorization_pending" responses before success.
	pendingPolls int32
	// Set to a non-empty error value to return from POST /oauth/token.
	tokenError     string
	tokenErrorDesc string

	// Register
	// If true, return 403 instead of config.
	registerForbidden bool
	// If true, return 401.
	registerUnauthorized bool
	// If true, omit encrypted_config.
	registerMissingConfig bool
}

// newPortalServer starts a mock portal HTTP server.
// It returns the server and a poll-count pointer (for asserting poll count).
func newPortalServer(t *testing.T, cfg portalConfig) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var pollCount atomic.Int32
	var srv *httptest.Server

	mux := http.NewServeMux()

	// /api/agent/credentials — GET returns OAuth2 creds, POST registers device
	// (RegisterPath == CredentialsPath since the agent uses the same endpoint)
	mux.HandleFunc(auth.CredentialsPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if !verifyHMACHeaders(t, w, r) {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"domain":    cfg.credDomain,
				"client_id": cfg.credClientID,
			})

		case http.MethodPost:
			if cfg.registerUnauthorized {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if cfg.registerForbidden {
				http.Error(w, "peer limit exceeded", http.StatusForbidden)
				return
			}

			bearer := r.Header.Get("Authorization")
			if bearer != "Bearer "+testAccessToken {
				http.Error(w, "bad token", http.StatusUnauthorized)
				t.Errorf("register: Authorization: got %q, want %q", bearer, "Bearer "+testAccessToken)
				return
			}
			if !verifyHMACHeaders(t, w, r) {
				return
			}

			var regReq auth.RegisterRequest
			if err := json.NewDecoder(r.Body).Decode(&regReq); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				t.Errorf("decode register request: %v", err)
				return
			}

			w.Header().Set("Content-Type", "application/json")

			if cfg.registerMissingConfig {
				json.NewEncoder(w).Encode(map[string]string{
					"token":      testSessionToken,
					"server_url": testGRPCServerURL,
				})
				return
			}

			ciphertext := encryptForToken(t, testAccessToken, regReq.Nonce, []byte(testWireGuardConfig))
			json.NewEncoder(w).Encode(auth.RegisterResponse{
				EncryptedConfig: ciphertext,
				Token:           testSessionToken,
				ServerURL:       testGRPCServerURL,
				HandoffURL:      testHandoffURL,
			})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// POST /oauth/device/code
	mux.HandleFunc(auth.DeviceCodePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               testDeviceCode,
			"user_code":                 testUserCode,
			"verification_uri":          srv.URL + "/activate",
			"verification_uri_complete": srv.URL + "/activate?user_code=" + testUserCode,
			"expires_in":                300,
			"interval":                  0, // poll immediately in tests
		})
	})

	// POST /oauth/token
	mux.HandleFunc(auth.TokenPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		if cfg.tokenError != "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             cfg.tokenError,
				"error_description": cfg.tokenErrorDesc,
			})
			return
		}

		n := pollCount.Add(1)
		if n <= cfg.pendingPolls {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": testAccessToken,
			"token_type":   "Bearer",
		})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Fill in the credentials domain from the test server hostname.
	if cfg.credDomain == "" {
		cfg.credDomain = "localhost"
	}
	return srv, &pollCount
}

// ── FetchCredentials ──────────────────────────────────────────────────────────

func TestFetchCredentials_HappyPath(t *testing.T) {
	srv, _ := newPortalServer(t, portalConfig{
		credDomain:   "auth.example.com",
		credClientID: testClientID,
	})

	creds, err := auth.FetchCredentials(context.Background(), srv.URL, testHashedDeviceID)
	if err != nil {
		t.Fatalf("FetchCredentials: %v", err)
	}
	if creds.Domain != "auth.example.com" {
		t.Errorf("domain: got %q, want %q", creds.Domain, "auth.example.com")
	}
	if creds.ClientID != testClientID {
		t.Errorf("client_id: got %q, want %q", creds.ClientID, testClientID)
	}
}

func TestFetchCredentials_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	_, err := auth.FetchCredentials(context.Background(), srv.URL, testHashedDeviceID)
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
}

func TestFetchCredentials_MissingFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"domain": ""}) // missing client_id
	}))
	t.Cleanup(srv.Close)

	_, err := auth.FetchCredentials(context.Background(), srv.URL, testHashedDeviceID)
	if err == nil {
		t.Fatal("expected error for missing fields, got nil")
	}
}

func TestFetchCredentials_SignatureIsHMAC(t *testing.T) {
	var gotSig, gotTS, gotDevice string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("x-wantastic-sig")
		gotTS = r.Header.Get("x-wantastic-ts")
		gotDevice = r.Header.Get("x-wantastic-device")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"domain":    "x.example.com",
			"client_id": "c",
		})
	}))
	t.Cleanup(srv.Close)

	auth.FetchCredentials(context.Background(), srv.URL, testHashedDeviceID) //nolint:errcheck

	// Recompute expected signature.
	message := gotTS + ":" + gotDevice
	mac := hmac.New(sha256.New, []byte(auth.SharedSecret))
	mac.Write([]byte(message))
	expected := hex.EncodeToString(mac.Sum(nil))

	if gotSig != expected {
		t.Errorf("signature mismatch: got %q, want %q", gotSig, expected)
	}
	if gotDevice != testHashedDeviceID {
		t.Errorf("device header: got %q, want %q", gotDevice, testHashedDeviceID)
	}
}

// ── Device flow polling ───────────────────────────────────────────────────────

func TestStartHTTPDeviceFlow_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != auth.DeviceCodePath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               testDeviceCode,
			"user_code":                 testUserCode,
			"verification_uri":          "https://example.com/activate",
			"verification_uri_complete": "https://example.com/activate?code=" + testUserCode,
			"expires_in":                300,
			"interval":                  5,
		})
	}))
	t.Cleanup(srv.Close)

	dc, err := auth.StartHTTPDeviceFlow(context.Background(), srv.URL, testClientID)
	if err != nil {
		t.Fatalf("StartHTTPDeviceFlow: %v", err)
	}
	if dc.DeviceCode != testDeviceCode {
		t.Errorf("device_code: got %q, want %q", dc.DeviceCode, testDeviceCode)
	}
	if dc.UserCode != testUserCode {
		t.Errorf("user_code: got %q, want %q", dc.UserCode, testUserCode)
	}
	if dc.Interval != 5 {
		t.Errorf("interval: got %d, want 5", dc.Interval)
	}
}

func TestStartHTTPDeviceFlow_DefaultInterval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// interval deliberately omitted — should default to 5.
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code": testDeviceCode,
			"user_code":   testUserCode,
			"expires_in":  300,
		})
	}))
	t.Cleanup(srv.Close)

	dc, err := auth.StartHTTPDeviceFlow(context.Background(), srv.URL, testClientID)
	if err != nil {
		t.Fatalf("StartHTTPDeviceFlow: %v", err)
	}
	if dc.Interval != 5 {
		t.Errorf("default interval: got %d, want 5", dc.Interval)
	}
}

func TestPollHTTPDeviceFlow_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": testAccessToken,
			"token_type":   "Bearer",
		})
	}))
	t.Cleanup(srv.Close)

	token, err := auth.PollHTTPDeviceFlow(context.Background(), srv.URL, testClientID, testDeviceCode)
	if err != nil {
		t.Fatalf("PollHTTPDeviceFlow: %v", err)
	}
	if token != testAccessToken {
		t.Errorf("token: got %q, want %q", token, testAccessToken)
	}
}

func TestPollHTTPDeviceFlow_Pending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
	}))
	t.Cleanup(srv.Close)

	token, err := auth.PollHTTPDeviceFlow(context.Background(), srv.URL, testClientID, testDeviceCode)
	if err != nil {
		t.Fatalf("pending should not be an error: %v", err)
	}
	if token != "" {
		t.Errorf("token should be empty while pending, got %q", token)
	}
}

func TestPollHTTPDeviceFlow_ExpiredToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
	}))
	t.Cleanup(srv.Close)

	_, err := auth.PollHTTPDeviceFlow(context.Background(), srv.URL, testClientID, testDeviceCode)
	if err == nil {
		t.Fatal("expected error for expired_token")
	}
}

func TestPollHTTPDeviceFlow_AccessDenied_PeerLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "access_denied",
			"error_description": "peer_limit_exceeded",
		})
	}))
	t.Cleanup(srv.Close)

	_, err := auth.PollHTTPDeviceFlow(context.Background(), srv.URL, testClientID, testDeviceCode)
	if err != auth.ErrPeerLimitExceeded {
		t.Errorf("expected ErrPeerLimitExceeded, got %v", err)
	}
}

func TestPollHTTPDeviceFlow_AccessDenied_UserDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "access_denied",
			"error_description": "user_denied",
		})
	}))
	t.Cleanup(srv.Close)

	_, err := auth.PollHTTPDeviceFlow(context.Background(), srv.URL, testClientID, testDeviceCode)
	if err != auth.ErrUserDenied {
		t.Errorf("expected ErrUserDenied, got %v", err)
	}
}

// ── RunDeviceFlow (polling loop) ──────────────────────────────────────────────

func TestRunDeviceFlow_ImmediateApproval(t *testing.T) {
	suppressStderr(t)

	srv, pollCount := newPortalServer(t, portalConfig{
		credDomain:   "localhost",
		credClientID: testClientID,
		pendingPolls: 0, // approve on first poll
	})

	token, err := auth.RunDeviceFlow(context.Background(), srv.URL, testClientID)
	if err != nil {
		t.Fatalf("RunDeviceFlow: %v", err)
	}
	if token != testAccessToken {
		t.Errorf("token: got %q, want %q", token, testAccessToken)
	}
	if pollCount.Load() != 1 {
		t.Errorf("poll count: got %d, want 1", pollCount.Load())
	}
}

func TestRunDeviceFlow_PendingThenApproval(t *testing.T) {
	suppressStderr(t)

	srv, pollCount := newPortalServer(t, portalConfig{
		credDomain:   "localhost",
		credClientID: testClientID,
		pendingPolls: 3, // 3 pending before approval
	})

	token, err := auth.RunDeviceFlow(context.Background(), srv.URL, testClientID)
	if err != nil {
		t.Fatalf("RunDeviceFlow: %v", err)
	}
	if token != testAccessToken {
		t.Errorf("token: got %q, want %q", token, testAccessToken)
	}
	if pollCount.Load() != 4 { // 3 pending + 1 success
		t.Errorf("poll count: got %d, want 4", pollCount.Load())
	}
}

func TestRunDeviceFlow_UserDenied(t *testing.T) {
	suppressStderr(t)

	srv, _ := newPortalServer(t, portalConfig{
		credDomain:     "localhost",
		credClientID:   testClientID,
		tokenError:     "access_denied",
		tokenErrorDesc: "user_denied",
	})

	_, err := auth.RunDeviceFlow(context.Background(), srv.URL, testClientID)
	if err != auth.ErrUserDenied {
		t.Errorf("expected ErrUserDenied, got %v", err)
	}
}

func TestRunDeviceFlow_PeerLimitExceeded(t *testing.T) {
	suppressStderr(t)

	srv, _ := newPortalServer(t, portalConfig{
		credDomain:     "localhost",
		credClientID:   testClientID,
		tokenError:     "access_denied",
		tokenErrorDesc: "peer_limit_exceeded",
	})

	_, err := auth.RunDeviceFlow(context.Background(), srv.URL, testClientID)
	if err != auth.ErrPeerLimitExceeded {
		t.Errorf("expected ErrPeerLimitExceeded, got %v", err)
	}
}

func TestRunDeviceFlow_ContextCancelled(t *testing.T) {
	suppressStderr(t)

	// Server that always returns pending.
	srv, _ := newPortalServer(t, portalConfig{
		credDomain:   "localhost",
		credClientID: testClientID,
		pendingPolls: 1_000_000,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := auth.RunDeviceFlow(ctx, srv.URL, testClientID)
	if err == nil {
		t.Fatal("expected error from context cancellation, got nil")
	}
}

// ── RegisterDevice ────────────────────────────────────────────────────────────

func TestRegisterDevice_HappyPath(t *testing.T) {
	srv, _ := newPortalServer(t, portalConfig{
		credDomain:   "localhost",
		credClientID: testClientID,
	})

	regResp, nonce, err := auth.RegisterDevice(
		context.Background(), srv.URL, testAccessToken, testHashedDeviceID,
	)
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if nonce == 0 {
		t.Error("nonce should be non-zero")
	}
	if regResp.Token != testSessionToken {
		t.Errorf("token: got %q, want %q", regResp.Token, testSessionToken)
	}
	if regResp.ServerURL != testGRPCServerURL {
		t.Errorf("server_url: got %q, want %q", regResp.ServerURL, testGRPCServerURL)
	}
	if regResp.HandoffURL != testHandoffURL {
		t.Errorf("handoff_url: got %q, want %q", regResp.HandoffURL, testHandoffURL)
	}
	if len(regResp.EncryptedConfig) == 0 {
		t.Error("encrypted_config should not be empty")
	}
}

func TestRegisterDevice_Unauthorized(t *testing.T) {
	srv, _ := newPortalServer(t, portalConfig{registerUnauthorized: true})

	_, _, err := auth.RegisterDevice(
		context.Background(), srv.URL, testAccessToken, testHashedDeviceID,
	)
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
}

func TestRegisterDevice_PeerLimitForbidden(t *testing.T) {
	srv, _ := newPortalServer(t, portalConfig{registerForbidden: true})

	_, _, err := auth.RegisterDevice(
		context.Background(), srv.URL, testAccessToken, testHashedDeviceID,
	)
	if err != auth.ErrPeerLimitExceeded {
		t.Errorf("expected ErrPeerLimitExceeded, got %v", err)
	}
}

func TestRegisterDevice_MissingEncryptedConfig(t *testing.T) {
	srv, _ := newPortalServer(t, portalConfig{registerMissingConfig: true})

	_, _, err := auth.RegisterDevice(
		context.Background(), srv.URL, testAccessToken, testHashedDeviceID,
	)
	if err == nil {
		t.Fatal("expected error for missing encrypted_config, got nil")
	}
}

func TestRegisterDevice_ConfigDecryptable(t *testing.T) {
	// Verify that the ciphertext returned by the mock server can be decrypted
	// correctly using the same key + nonce scheme.
	srv, _ := newPortalServer(t, portalConfig{
		credDomain:   "localhost",
		credClientID: testClientID,
	})

	regResp, nonce, err := auth.RegisterDevice(
		context.Background(), srv.URL, testAccessToken, testHashedDeviceID,
	)
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	// Decrypt.
	hash := sha256.Sum256([]byte(testAccessToken))
	aead, err := chacha20poly1305.New(hash[:])
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}
	nonceBytes := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonceBytes[:8], nonce)

	plaintext, err := aead.Open(nil, nonceBytes, regResp.EncryptedConfig, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plaintext) != testWireGuardConfig {
		t.Errorf("decrypted config mismatch:\ngot:\n%s\nwant:\n%s", plaintext, testWireGuardConfig)
	}
}

// ── Full OAuth2 flow end-to-end ───────────────────────────────────────────────

// TestFullOAuth2Flow runs the entire sequence:
//
//  1. FetchCredentials → domain + client_id
//  2. StartHTTPDeviceFlow → device code
//  3. PollHTTPDeviceFlow (2 pending + success) → access token
//  4. RegisterDevice → encrypted WireGuard config
//  5. Decrypt config → verify plaintext
func TestFullOAuth2Flow(t *testing.T) {
	suppressStderr(t)

	srv, pollCount := newPortalServer(t, portalConfig{
		credDomain:   "auth.test.local",
		credClientID: testClientID,
		pendingPolls: 2,
	})

	ctx := context.Background()

	// Step 1: fetch credentials.
	creds, err := auth.FetchCredentials(ctx, srv.URL, testHashedDeviceID)
	if err != nil {
		t.Fatalf("FetchCredentials: %v", err)
	}
	if creds.ClientID != testClientID {
		t.Fatalf("client_id: got %q, want %q", creds.ClientID, testClientID)
	}

	// Step 2+3: device flow → access token.
	accessToken, err := auth.RunDeviceFlow(ctx, srv.URL, creds.ClientID)
	if err != nil {
		t.Fatalf("RunDeviceFlow: %v", err)
	}
	if accessToken != testAccessToken {
		t.Fatalf("access token: got %q, want %q", accessToken, testAccessToken)
	}
	if got := pollCount.Load(); got != 3 {
		t.Errorf("poll count: got %d, want 3 (2 pending + 1 success)", got)
	}

	// Step 4: register device.
	regResp, nonce, err := auth.RegisterDevice(ctx, srv.URL, accessToken, testHashedDeviceID)
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if regResp.HandoffURL != testHandoffURL {
		t.Errorf("handoff_url: got %q, want %q", regResp.HandoffURL, testHandoffURL)
	}

	// Step 5: decrypt config.
	hash := sha256.Sum256([]byte(accessToken))
	aead, err := chacha20poly1305.New(hash[:])
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	nonceBytes := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonceBytes[:8], nonce)
	plaintext, err := aead.Open(nil, nonceBytes, regResp.EncryptedConfig, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plaintext) != testWireGuardConfig {
		t.Errorf("config mismatch:\ngot:\n%s\nwant:\n%s", plaintext, testWireGuardConfig)
	}
}

// TestGeneratePKCE verifies RFC 7636 §4.1–4.2 compliance.
func TestGeneratePKCE(t *testing.T) {
	pair, err := auth.GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}

	// Verifier must be at least 43 chars (32 raw bytes base64url-encoded).
	if len(pair.Verifier) < 43 {
		t.Errorf("verifier too short: len=%d", len(pair.Verifier))
	}

	// Challenge = BASE64URL(SHA256(verifier)), no padding.
	sum := sha256.Sum256([]byte(pair.Verifier))
	want := base64URLNoPad(sum[:])
	if pair.Challenge != want {
		t.Errorf("challenge: got %q, want %q", pair.Challenge, want)
	}
}

func TestGeneratePKCE_IsRandom(t *testing.T) {
	a, _ := auth.GeneratePKCE()
	b, _ := auth.GeneratePKCE()
	if a.Verifier == b.Verifier {
		t.Error("two PKCE pairs have the same verifier — not random")
	}
}

// base64URLNoPad is a test-local reimplementation to avoid importing
// encoding/base64 just for the test assertion.
func base64URLNoPad(data []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out []byte
	for i := 0; i < len(data); i += 3 {
		remaining := len(data) - i
		var b0, b1, b2 byte
		b0 = data[i]
		if remaining > 1 {
			b1 = data[i+1]
		}
		if remaining > 2 {
			b2 = data[i+2]
		}
		out = append(out, chars[b0>>2])
		out = append(out, chars[((b0&0x03)<<4)|(b1>>4)])
		if remaining > 1 {
			out = append(out, chars[((b1&0x0f)<<2)|(b2>>6)])
		}
		if remaining > 2 {
			out = append(out, chars[b2&0x3f])
		}
	}
	return string(out)
}

// ── HandoffURL ────────────────────────────────────────────────────────────────

func TestHandoffURL(t *testing.T) {
	got := auth.HandoffURL("https://console.wantastic.app", "my-session-token")
	want := "https://console.wantastic.app/api/device-handoff?t=my-session-token"
	if got != want {
		t.Errorf("HandoffURL: got %q, want %q", got, want)
	}
}

func TestHandoffURL_TrailingSlash(t *testing.T) {
	got := auth.HandoffURL("https://console.wantastic.app/", "tok")
	want := fmt.Sprintf("https://console.wantastic.app%s?t=tok", auth.HandoffPath)
	if got != want {
		t.Errorf("HandoffURL: got %q, want %q", got, want)
	}
}
