package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ─── Portal URL ────────────────────────────────────────────────────────────
// Set WANTASTIC_PORTAL_URL=http://wantastic.local for local development.
// Production default: https://console.wantastic.app

const (
	defaultPortalURL = "https://console.wantastic.app"
	defaultAPIServer = "api.wantastic.app:443"

	// HMAC shared secret — must match OverlayServiceNode cipher.SharedSecret
	agentSharedSecret = "Wantastic_v1_Rolling_Code_Secret"

	// HTTP header names used for agent HMAC authentication
	headerTimestamp = "x-wantastic-ts"
	headerDevice    = "x-wantastic-device"
	headerSignature = "x-wantastic-sig"

	auth0CallbackPort = 0 // 0 = auto-assign free port
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

// stableDeviceID returns a short stable identifier for this machine,
// derived from the hostname SHA256 (fallback when machineid is unavailable).
func stableDeviceID() string {
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

// ─── PKCE helpers ──────────────────────────────────────────────────────────

func generateCodeVerifier() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ─── PKCE flow ─────────────────────────────────────────────────────────────

// RunPKCEFlow fetches Auth0 credentials from the portal, opens the system
// browser for login, waits for the local callback, exchanges the code for
// tokens, persists them, and returns account info.
func (c *Auth0Client) RunPKCEFlow(ctx context.Context) (*AccountInfo, error) {
	// Fetch Auth0 config dynamically from the portal — works for production
	// (console.wantastic.app) and local dev (wantastic.local).
	deviceID := stableDeviceID()
	creds := fetchPortalCredentials(deviceID)

	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generate verifier: %w", err)
	}
	challenge := generateCodeChallenge(verifier)
	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	// Start local callback listener on a random free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("callback listener: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	// Build authorization URL
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {creds.Auth0ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email offline_access"},
		"audience":              {creds.Audience},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authURL := fmt.Sprintf("https://%s/authorize?%s", creds.Auth0Domain, params.Encode())

	// Open browser
	openBrowserURL(authURL)

	// Serve callback
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	srv := &http.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			errCh <- fmt.Errorf("state mismatch")
			return
		}
		if errMsg := q.Get("error"); errMsg != "" {
			http.Error(w, errMsg, http.StatusBadRequest)
			errCh <- fmt.Errorf("auth error: %s — %s", errMsg, q.Get("error_description"))
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			errCh <- fmt.Errorf("missing code in callback")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><html><body style="font-family:system-ui;text-align:center;padding:4rem;">
<h2>✅ Login successful</h2><p>You can close this tab and return to Wantastic.</p>
</body></html>`)
		codeCh <- code
	})
	srv.Handler = mux

	go srv.Serve(ln)
	defer srv.Close()

	// Wait for code or timeout
	var code string
	select {
	case code = <-codeCh:
	case err = <-errCh:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("login timed out")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Exchange code for tokens
	tokens, err := c.exchangeCode(code, verifier, redirectURI, creds)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	if err := c.saveTokens(*tokens); err != nil {
		return nil, fmt.Errorf("save tokens: %w", err)
	}

	info := c.ParseDisplayClaims(tokens.AccessToken)
	info.LoggedIn = true
	info.Token = tokens.AccessToken
	return info, nil
}

// exchangeCode trades the auth code for access + refresh tokens
func (c *Auth0Client) exchangeCode(code, verifier, redirectURI string, creds portalCredentials) (*storedTokens, error) {
	body := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {creds.Auth0ClientID},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}

	resp, err := http.PostForm(fmt.Sprintf("https://%s/oauth/token", creds.Auth0Domain), body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		Description  string `json:"error_description"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	if result.Error != "" {
		return nil, fmt.Errorf("token error: %s — %s", result.Error, result.Description)
	}

	return &storedTokens{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(result.ExpiresIn) * time.Second),
	}, nil
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
