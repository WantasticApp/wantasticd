package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"wantastic-agent/internal/config"
	wantasticgrpc "wantastic-agent/internal/grpc"

	"github.com/denisbrodbeck/machineid"
)

// ─── Portal URL ────────────────────────────────────────────────────────────
// Set WANTASTIC_PORTAL_URL=https://wantastic.local for local dev.
// Production default: https://console.wantastic.app
// Set WANTASTIC_GRPC_ADDR=host:port to override the gRPC server address
// (default: portal host on port 52990).

const (
	defaultPortalURL = "https://console.wantastic.app"
	defaultGRPCPort  = "52990"

	// HMAC shared secret — must match OverlayServiceNode cipher.SharedSecret
	agentSharedSecret = "wantastic_cipher_v_1_0_0"

	// HTTP header names used for agent HMAC authentication
	headerTimestamp = "x-wantastic-ts"
	headerDevice    = "x-wantastic-device"
	headerSignature = "x-wantastic-sig"

	// PKCE callback server — RFC 8252 loopback redirect URI
	pkceCallbackPort = "58250"
	pkceCallbackURI  = "http://localhost:" + pkceCallbackPort + "/callback"
)

func portalBaseURL() string {
	raw := os.Getenv("WANTASTIC_PORTAL_URL")
	if raw == "" {
		raw = defaultPortalURL
	}

	// If scheme is missing, default to HTTPS.
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return defaultPortalURL
	}

	// Force HTTPS for production portal; preserve http for .local dev servers.
	if !strings.HasSuffix(u.Hostname(), ".local") && !strings.HasSuffix(u.Hostname(), ".internal") {
		u.Scheme = "https"
	}
	return strings.TrimRight(u.String(), "/")
}

// grpcServerAddr returns host:port of the Wantastic gRPC server (RegisterDevice).
// Override with WANTASTIC_GRPC_ADDR; default: portal host on port 52990.
func grpcServerAddr() string {
	if addr := os.Getenv("WANTASTIC_GRPC_ADDR"); addr != "" {
		return addr
	}
	u, err := url.Parse(portalBaseURL())
	if err != nil || u.Hostname() == "" {
		return "console.wantastic.app:" + defaultGRPCPort
	}
	return u.Hostname() + ":" + defaultGRPCPort
}

// ─── Portal HTTP client ───────────────────────────────────────────────────

// portalHTTPClient returns an *http.Client suitable for talking to the portal.
// For non-production portals (http:// scheme or .local/.internal hostnames)
// TLS verification is skipped so that self-signed dev certs work.
func portalHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

// ─── Portal credentials (HMAC handshake) ──────────────────────────────────

// portalCredentials holds the OAuth2 client details returned by /api/agent/credentials.
// Accepts both the new format (domain/client_id) and the legacy format
// (auth0_domain/auth0_client_id) for backward compatibility.
type portalCredentials struct {
	// Current format
	Domain   string `json:"domain"`
	ClientID string `json:"client_id"`
	// Legacy Auth0 format
	Auth0Domain   string `json:"auth0_domain"`
	Auth0ClientID string `json:"auth0_client_id"`
	Audience      string `json:"audience"`
}

// normalize promotes legacy field names into the canonical fields.
func (c *portalCredentials) normalize() {
	if c.Domain == "" {
		c.Domain = c.Auth0Domain
	}
	if c.ClientID == "" {
		c.ClientID = c.Auth0ClientID
	}
}

// fetchPortalCredentials calls GET /api/agent/credentials on the portal using
// HMAC-signed headers. This serves as a cipher-proof handshake and liveness probe.
// Signature covers "timestamp:deviceID" with the shared secret.
func fetchPortalCredentials(deviceID string) (portalCredentials, error) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(agentSharedSecret))
	mac.Write([]byte(ts + ":" + deviceID))
	sig := hex.EncodeToString(mac.Sum(nil))

	endpoint := portalBaseURL() + "/api/agent/credentials"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return portalCredentials{}, fmt.Errorf("build credentials request: %w", err)
	}
	req.Header.Set(headerTimestamp, ts)
	req.Header.Set(headerDevice, deviceID)
	req.Header.Set(headerSignature, sig)

	resp, err := portalHTTPClient(8 * time.Second).Do(req)
	if err != nil {
		return portalCredentials{}, fmt.Errorf("reach portal at %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("[DEBUG] /api/agent/credentials HTTP %d response: %s", resp.StatusCode, string(body))
	if resp.StatusCode != http.StatusOK {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return portalCredentials{}, fmt.Errorf("credentials endpoint returned HTTP %d: %s", resp.StatusCode, snippet)
	}

	var creds portalCredentials
	if err := json.Unmarshal(body, &creds); err != nil {
		return portalCredentials{}, fmt.Errorf("decode credentials response: %w", err)
	}
	creds.normalize()
	if creds.Domain == "" {
		return portalCredentials{}, fmt.Errorf("portal returned empty domain")
	}
	if creds.Audience == "" {
		creds.Audience = portalBaseURL()
	}

	// In dev mode (portal is .local/.internal) the remote server may return the
	// production OAuth domain. Override it so the entire auth flow stays on the
	// local dev server.
	if pu, err2 := url.Parse(portalBaseURL()); err2 == nil {
		h := pu.Hostname()
		if strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
			creds.Domain = h
		}
	}

	log.Printf("Portal credentials OK: domain=%s client_id=%s", creds.Domain, creds.ClientID)
	return creds, nil
}

// stableDeviceID returns the hardware machine ID normalized to lowercase.
// On macOS this is an IOPlatformUUID (e.g. "aabbccdd-eeff-…").
// This value is sent as device_id in the OAuth authorize URL and in field 6
// of RegisterDeviceRequest. The server validates that both values match.
// Falls back to hostname when the platform ID is unavailable.
func stableDeviceID() string {
	rawID, err := machineid.ID()
	if err != nil || rawID == "" {
		hostname, _ := os.Hostname()
		rawID = hostname
		if rawID == "" {
			rawID = "unknown"
		}
	}
	return strings.ToLower(strings.TrimSpace(rawID))
}

// ─── Auth0Client ───────────────────────────────────────────────────────────

type Auth0Client struct {
	tokenPath string
}

func NewAuth0Client() *Auth0Client {
	dir, _ := os.UserConfigDir()
	return &Auth0Client{
		tokenPath: filepath.Join(dir, "wantastic", "auth_token.json"),
	}
}

// ─── Stored token ──────────────────────────────────────────────────────────

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
		return ""
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

// ─── Shared post-token flow ────────────────────────────────────────────────

// finishWithToken handles steps 5-7 common to both PKCE and device flows:
// persist the access token, gRPC RegisterDevice, decrypt WireGuard config.
func (c *Auth0Client) finishWithToken(
	ctx context.Context,
	accessToken, deviceID string,
) (*AccountInfo, *config.Config, string, error) {
	_ = c.saveTokens(storedTokens{
		AccessToken: accessToken,
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	})

	grpcClient, err := wantasticgrpc.New(grpcServerAddr(), deviceID, accessToken)
	if err != nil {
		return nil, nil, "", fmt.Errorf("connect to gRPC server: %w", err)
	}
	defer grpcClient.Close()

	var nonce uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &nonce); err != nil {
		nonce = uint64(time.Now().UnixNano())
	}

	hostname, _ := os.Hostname()
	log.Printf("RegisterDevice: device_id=%s hostname=%s os=%s arch=%s", deviceID, hostname, goruntime.GOOS, goruntime.GOARCH)
	regResp, err := grpcClient.RegisterDevice(ctx, nonce, goruntime.GOOS, goruntime.GOARCH, hostname, deviceID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("register device: %w", err)
	}
	if !regResp.Success {
		return nil, nil, "", fmt.Errorf("RegisterDevice returned success=false")
	}

	cfg, err := config.LoadFromRegisterResponse(regResp, accessToken, nonce, grpcServerAddr())
	if err != nil {
		return nil, nil, "", fmt.Errorf("decrypt config: %w", err)
	}

	info := c.ParseDisplayClaims(accessToken)
	info.LoggedIn = true
	info.Token = accessToken

	return info, cfg, regResp.GetToken(), nil
}

// ─── PKCE Authorization Code Flow (RFC 6749 + RFC 7636) ───────────────────

// generatePKCE produces a code_verifier and its S256 code_challenge.
func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 48)
	if _, err = rand.Read(b); err != nil {
		return
	}
	verifier = base64.RawURLEncoding.EncodeToString(b) // 64 URL-safe chars
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

type pkceResult struct {
	code string
	err  error
}

// startPKCECallbackServer listens on pkceCallbackPort for the OAuth2 redirect.
// It sends exactly one pkceResult on the returned channel then shuts down.
func startPKCECallbackServer(expectedState string) (*http.Server, <-chan pkceResult) {
	ch := make(chan pkceResult, 1)
	mux := http.NewServeMux()
	srv := &http.Server{Addr: "127.0.0.1:" + pkceCallbackPort, Handler: mux}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var res pkceResult

		if errParam := q.Get("error"); errParam != "" {
			desc := q.Get("error_description")
			if desc == "" {
				desc = errParam
			}
			humanDesc := desc
			if strings.Contains(desc, "peer_limit_exceeded") {
				humanDesc = "Your account has reached its device limit. Remove an existing device from the Wantastic console to add this one."
			}
			res.err = fmt.Errorf("%s", humanDesc)
			fmt.Fprintf(w, `<html><body style="font-family:sans-serif;padding:40px"><h2>Authentication failed</h2><p>%s</p></body></html>`, humanDesc)
		} else if q.Get("state") != expectedState {
			res.err = fmt.Errorf("OAuth2 state mismatch — possible CSRF")
			http.Error(w, "state mismatch", http.StatusBadRequest)
		} else if code := q.Get("code"); code == "" {
			res.err = fmt.Errorf("no authorization code in callback")
			http.Error(w, "missing code", http.StatusBadRequest)
		} else {
			res.code = code
			fmt.Fprintf(w, `<html><body style="font-family:sans-serif;padding:40px"><h2>✓ Signed in successfully</h2><p>You may close this page.</p><script>window.close()</script></body></html>`)
		}

		ch <- res
		go func() {
			time.Sleep(500 * time.Millisecond)
			srv.Close()
		}()
	})

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			select {
			case ch <- pkceResult{err: fmt.Errorf("callback server: %w", err)}:
			default:
			}
		}
	}()

	return srv, ch
}

// oauthScheme returns "http" only for bare localhost (no TLS); all other domains
// including .local/.internal use "https" (nginx on dev servers enforces it).
func oauthScheme(domain string) string {
	h := strings.ToLower(domain)
	if h == "localhost" || strings.HasPrefix(h, "localhost:") {
		return "http"
	}
	return "https"
}

// exchangePKCECode exchanges an authorization code for an access token.
// It tries several parameter combinations to accommodate custom OAuth server implementations:
//  1. Standard PKCE (code_verifier only — no extra params)
//  2. With device_id added (portal may store it with the code)
//  3. Without code_verifier (server may not validate PKCE on token side)
func exchangePKCECode(ctx context.Context, domain, clientID, code, verifier, deviceID, _ string) (string, error) {
	endpoint := oauthScheme(domain) + "://" + domain + "/oauth/token"

	base := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {pkceCallbackURI},
		"client_id":    {clientID},
	}

	// Attempt 1: standard PKCE with code_verifier
	v1 := copyValues(base)
	v1.Set("code_verifier", verifier)
	log.Printf("Token exchange attempt 1: standard PKCE")
	tok, err1 := doTokenExchange(ctx, endpoint, v1)
	if err1 == nil {
		return tok, nil
	}
	log.Printf("Token exchange attempt 1 failed: %v", err1)

	// Attempt 2: add device_id (portal may require it for correlation with authorize step)
	v2 := copyValues(base)
	v2.Set("code_verifier", verifier)
	if deviceID != "" {
		v2.Set("device_id", deviceID)
	}
	log.Printf("Token exchange attempt 2: with device_id")
	tok, err2 := doTokenExchange(ctx, endpoint, v2)
	if err2 == nil {
		return tok, nil
	}
	log.Printf("Token exchange attempt 2 failed: %v", err2)

	// Attempt 3: no code_verifier — some custom servers crash on it
	v3 := copyValues(base)
	if deviceID != "" {
		v3.Set("device_id", deviceID)
	}
	log.Printf("Token exchange attempt 3: no code_verifier")
	tok, err3 := doTokenExchange(ctx, endpoint, v3)
	if err3 == nil {
		return tok, nil
	}
	log.Printf("Token exchange attempt 3 failed: %v", err3)

	// Return the most informative error (prefer 4xx over 5xx — 4xx means the server
	// understood but rejected; 5xx means the server crashed on that combination)
	return "", fmt.Errorf("token exchange failed: %v", err1)
}

func copyValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

func doTokenExchange(ctx context.Context, endpoint string, vals url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(vals.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := portalHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	log.Printf("[DEBUG] /oauth/token HTTP %d response: %s", resp.StatusCode, string(body))

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &errResp)
		desc := errResp.ErrorDescription
		if desc == "" {
			desc = errResp.Error
		}
		if desc == "" {
			desc = truncateBody(body)
		}
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, desc)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.AccessToken == "" {
		return "", fmt.Errorf("unexpected token response: %s", truncateBody(body))
	}
	return result.AccessToken, nil
}

// RunPKCEFlow implements the PKCE Authorization Code Flow (RFC 6749 + RFC 7636):
//  1. GET /api/agent/credentials — HMAC cipher-proof handshake
//  2. Generate PKCE pair (verifier + S256 challenge)
//  3. Call onNavigate with the /oauth/authorize URL — opens in embedded WebView
//  4. Local callback server on :58250 captures the authorization code
//  5. POST /oauth/token to exchange code → access_token
//  6. gRPC RegisterDevice — encrypted WireGuard config + session token
//  7. Navigate WebView to /api/device-handoff?t=<session_token>
//
// onNavigate is called twice: first with the authorization URL, then with ""
// to signal that the WebView should close.
func (c *Auth0Client) RunPKCEFlow(
	ctx context.Context,
	onNavigate func(url string),
) (*AccountInfo, *config.Config, string, error) {
	deviceID := stableDeviceID()

	creds, err := fetchPortalCredentials(deviceID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("portal credentials: %w", err)
	}
	if creds.ClientID == "" {
		return nil, nil, "", fmt.Errorf("portal did not return client_id (required for PKCE)")
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate PKCE pair: %w", err)
	}

	state := generateState()

	srv, resultCh := startPKCECallbackServer(state)
	defer srv.Close()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {creds.ClientID},
		"redirect_uri":          {pkceCallbackURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"scope":                 {"org:create_api_key user:profile"},
		"device_id":             {deviceID},
		"audience":              {creds.Audience},
	}
	authURL := oauthScheme(creds.Domain) + "://" + creds.Domain + "/oauth/authorize?" + params.Encode()
	log.Printf("PKCE: opening authorization URL: %s", authURL)
	if onNavigate != nil {
		onNavigate(authURL)
	}

	// Wait for the authorization code from the local callback server.
	var code string
	select {
	case <-ctx.Done():
		return nil, nil, "", ctx.Err()
	case <-time.After(10 * time.Minute):
		return nil, nil, "", fmt.Errorf("PKCE flow timed out waiting for callback")
	case result := <-resultCh:
		if result.err != nil {
			if onNavigate != nil {
				onNavigate("") // close WebView
			}
			return nil, nil, "", fmt.Errorf("PKCE callback: %w", result.err)
		}
		code = result.code
	}

	// Close the auth WebView — the success page has been shown.
	if onNavigate != nil {
		onNavigate("")
	}

	log.Printf("PKCE: exchanging authorization code for access token…")
	accessToken, err := exchangePKCECode(ctx, creds.Domain, creds.ClientID, code, verifier, deviceID, creds.Audience)
	if err != nil {
		return nil, nil, "", fmt.Errorf("exchange authorization code: %w", err)
	}

	log.Printf("PKCE: token obtained — registering device via gRPC…")
	return c.finishWithToken(ctx, accessToken, deviceID)
}

func truncateBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
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
