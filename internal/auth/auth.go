package auth

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxResponseBytes caps every portal response to prevent memory-exhaustion from
// a rogue or compromised server.
const maxResponseBytes = 1 << 20 // 1 MiB

// limitDecode decodes JSON from r into v, reading at most maxResponseBytes.
func limitDecode(r io.Reader, v any) error {
	return json.NewDecoder(io.LimitReader(r, maxResponseBytes)).Decode(v)
}

// Shared secret used for HMAC-SHA256 signing on both HTTP and gRPC.
const SharedSecret = "wantastic_cipher_v_1_0_0"

// Default OAuth2 application coordinates for the Wantastic portal.
const (
	DefaultOAuth2Domain    = "console.wantastic.app"
	DefaultOAuth2DevDomain = "wantastic.local"
	DefaultOAuth2ClientID  = "wantastic_cipher_v_1_0_0"
)

// HTTP header names used for agent authentication.
const (
	HeaderTimestamp = "x-wantastic-ts"
	HeaderDevice    = "x-wantastic-device"
	HeaderSig       = "x-wantastic-sig"
)

// Well-known HTTP paths on the portal.
const (
	CredentialsPath = "/api/agent/credentials"
	ClaimConfigPath = "/api/agent/claim-config"
	ClaimWaitPath   = "/api/agent/claim-wait"
	DeviceCodePath  = "/oauth/device/code"
	TokenPath       = "/oauth/token"
	HandoffPath     = "/api/device-handoff"
)

// PKCECallbackPort is the loopback port the agent listens on during a PKCE flow.
const PKCECallbackPort = 58250

// ErrPeerLimitExceeded is returned when the portal denies the OAuth2 authorization
// because the user has reached their plan's device limit.
var ErrPeerLimitExceeded = errors.New("account has reached its device limit — upgrade your plan or remove an existing device")

// ErrUserDenied is returned when the user explicitly cancels the authorization.
var ErrUserDenied = errors.New("authorization was denied by the user")

// Credentials holds the OAuth2 parameters returned by /api/agent/credentials.
type Credentials struct {
	Domain   string `json:"domain"`
	ClientID string `json:"client_id"`
}

type ClaimConfig struct {
	Claimed             bool     `json:"claimed"`
	PublicKey           string   `json:"public_key"`
	AssignedIP          string   `json:"assigned_ip"`
	ServerKey           string   `json:"server_key"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	DNSServers          []string `json:"dns_servers"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	MTU                 int      `json:"mtu"`
	ListenPort          int      `json:"listen_port"`
}

// PortalBaseURL returns the full HTTPS base URL for the portal domain.
func (c *Credentials) PortalBaseURL() string {
	return fmt.Sprintf("https://%s", c.Domain)
}

// DeviceCode holds the response from POST /oauth/device/code (RFC 8628 §3.2).
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenResponse is returned by POST /oauth/token for both device and PKCE flows.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// PKCEPair holds a generated PKCE code verifier and its challenge.
type PKCEPair struct {
	Verifier  string // random, min 43 chars
	Challenge string // BASE64URL(SHA256(Verifier)), no padding
}

// httpClient is the shared HTTP client for all auth package requests.
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

var insecureSkipVerify bool

// SetInsecureSkipVerify replaces the shared HTTP client with one that skips
// TLS certificate verification. Only call this in dev mode.
func SetInsecureSkipVerify() {
	insecureSkipVerify = true
	httpClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}
