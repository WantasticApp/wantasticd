package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wantastic-agent/internal/config"
	wantasticgrpc "wantastic-agent/internal/grpc"

	"github.com/denisbrodbeck/machineid"
)

// ─── Portal URL ────────────────────────────────────────────────────────────
// Set WANTASTIC_PORTAL_URL=http://wantastic.local for local development.
// Production default: https://console.wantastic.app

const (
	defaultPortalURL = "https://console.wantastic.app"
	defaultAPIServer = "api.wantastic.app:52990"

	// HMAC shared secret — must match OverlayServiceNode cipher.SharedSecret
	agentSharedSecret = "wantastic_cipher_v_1_0_0"

	// HTTP header names used for agent HMAC authentication
	headerTimestamp = "x-wantastic-ts"
	headerDevice    = "x-wantastic-device"
	headerSignature = "x-wantastic-sig"
)

func portalBaseURL() string {
	if u := os.Getenv("WANTASTIC_PORTAL_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return defaultPortalURL
}

func apiServerAddr() string {
	if s := os.Getenv("WANTASTIC_SERVER_URL"); s != "" {
		return s
	}
	return defaultAPIServer
}

// ─── Portal credentials (dynamic Auth0 config) ────────────────────────────

type portalCredentials struct {
	Auth0Domain   string `json:"auth0_domain"`
	Auth0ClientID string `json:"auth0_client_id"`
	Audience      string `json:"audience"`
}

// fetchPortalCredentials calls GET /api/agent/credentials on the portal using
// HMAC-signed headers to retrieve the Auth0 domain and client ID dynamically.
// Falls back to safe defaults so the app still works if the portal is unreachable.
func fetchPortalCredentials(deviceID string) portalCredentials {
	defaults := portalCredentials{
		Auth0Domain:   "auth.wantastic.app",
		Auth0ClientID: "wantastic-desktop-client",
		Audience:      "https://api.wantastic.app",
	}

	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(agentSharedSecret))
	mac.Write([]byte(ts + ":" + deviceID))
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodGet, portalBaseURL()+"/api/agent/credentials", nil)
	if err != nil {
		return defaults
	}
	req.Header.Set(headerTimestamp, ts)
	req.Header.Set(headerDevice, deviceID)
	req.Header.Set(headerSignature, sig)

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return defaults
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return defaults
	}

	var creds portalCredentials
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return defaults
	}
	if creds.Auth0Domain == "" || creds.Auth0ClientID == "" {
		return defaults
	}
	if creds.Audience == "" {
		creds.Audience = defaults.Audience
	}
	return creds
}

// stableDeviceID returns a stable hardware-derived identifier for this machine.
// Uses machineid.ProtectedID (scoped to "wantastic") hashed with SHA256 so the
// raw hardware ID is never transmitted. Falls back to a hostname-derived hash
// when the platform machine ID is unavailable (e.g. sandboxed builds).
func stableDeviceID() string {
	if id, err := machineid.ProtectedID("wantastic"); err == nil && id != "" {
		h := sha256.Sum256([]byte(id))
		return hex.EncodeToString(h[:16])
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	h := sha256.Sum256([]byte("wantastic:" + hostname))
	return "devhash_" + hex.EncodeToString(h[:8])
}

// ─── Auth0Client ───────────────────────────────────────────────────────────

// Auth0Client manages the PKCE flow and token persistence
type Auth0Client struct {
	tokenPath string
}

func NewAuth0Client() *Auth0Client {
	dir, _ := os.UserConfigDir()
	return &Auth0Client{
		tokenPath: filepath.Join(dir, "wantastic", "auth_token.json"),
	}
}

// ─── Stored token ─────────────────────────────────────────────────────────────

type storedTokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (c *Auth0Client) StoredToken() string {
	data, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return ""
	}
	var t storedTokens
	if err := json.Unmarshal(data, &t); err != nil {
		return ""
	}
	if time.Now().After(t.ExpiresAt) {
		return "" // expired
	}
	return t.AccessToken
}

func (c *Auth0Client) saveTokens(t storedTokens) error {
	_ = os.MkdirAll(filepath.Dir(c.tokenPath), 0700)
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return os.WriteFile(c.tokenPath, data, 0600)
}

func (c *Auth0Client) ClearToken() error {
	return os.Remove(c.tokenPath)
}

// ─── gRPC Device Flow ─────────────────────────────────────────────────────

// RunDeviceFlow implements the Wantastic Agent Authentication Protocol:
//  1. Fetches portal credentials (connectivity gate)
//  2. Opens a gRPC device flow: StartDeviceFlow → browser open → poll → RegisterDevice
//  3. Decrypts the WireGuard config with the Auth0 access token
//
// onVerification is called as soon as the user_code and verification_uri are
// available — the caller should open the browser and surface the code in the UI.
// Returns the account info, the decrypted WireGuard config, the portal session
// token (for /api/device-handoff auto-login), and any error.
func (c *Auth0Client) RunDeviceFlow(
	ctx context.Context,
	onVerification func(userCode, uri string),
) (*AccountInfo, *config.Config, string, error) {
	deviceID := stableDeviceID()

	// Step 1: Fetch portal credentials (connectivity / HMAC gate)
	fetchPortalCredentials(deviceID) // returned fields unused in gRPC path

	// Step 2: gRPC device flow
	grpcClient, err := wantasticgrpc.New(apiServerAddr(), deviceID, "")
	if err != nil {
		return nil, nil, "", fmt.Errorf("connect to auth server: %w", err)
	}
	defer grpcClient.Close()

	accessToken, nonce, regResp, err := grpcClient.StartDeviceFlowWithCallback(ctx, onVerification)
	if err != nil {
		return nil, nil, "", fmt.Errorf("device flow: %w", err)
	}

	// Persist Auth0 access token
	_ = c.saveTokens(storedTokens{
		AccessToken: accessToken,
		ExpiresAt:   time.Now().Add(24 * time.Hour), // best-effort; server sets real expiry
	})

	// Step 3: Decrypt WireGuard config from RegisterDeviceResponse
	cfg, err := config.LoadFromRegisterResponse(regResp, accessToken, nonce, apiServerAddr())
	if err != nil {
		return nil, nil, "", fmt.Errorf("load config from registration: %w", err)
	}

	info := c.ParseDisplayClaims(accessToken)
	info.LoggedIn = true
	info.Token = accessToken

	sessionToken := regResp.GetToken() // portal session token for /api/device-handoff
	return info, cfg, sessionToken, nil
}

// ParseDisplayClaims returns basic user info from the JWT claims (no verification)
func (c *Auth0Client) ParseDisplayClaims(token string) *AccountInfo {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return &AccountInfo{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return &AccountInfo{}
	}
	var claims struct {
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
		Sub     string `json:"sub"`
	}
	_ = json.Unmarshal(payload, &claims)
	return &AccountInfo{
		DisplayName: claims.Name,
		Email:       claims.Email,
		AvatarURL:   claims.Picture,
	}
}

// openBrowserURL opens a URL in the default system browser
func openBrowserURL(u string) {
	openBrowser(u)
}
