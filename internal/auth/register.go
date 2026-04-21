package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json" // for Marshal only; Decode uses limitDecode
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const RegisterPath = "/api/agent/credentials"

// RegisterRequest is the JSON body sent to POST /api/agent/register.
type RegisterRequest struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Nonce    uint64 `json:"nonce"` // random uint64; caller uses it to derive decryption nonce
}

// RegisterResponse is the JSON response from POST /api/agent/register.
//
// The portal returns an encrypted WireGuard configuration (ChaCha20-Poly1305)
// together with a session token and a handoff URL the user can open in a browser
// to confirm the device appeared in the console.
//
// Encryption spec:
//
//	key   = SHA256(access_token)
//	nonce = little-endian uint64(RegisterRequest.Nonce), zero-padded to 12 bytes
type RegisterResponse struct {
	// EncryptedConfig is the ChaCha20-Poly1305 ciphertext of the WireGuard
	// config (WireGuard INI format).  The JSON value is base64-standard-encoded.
	EncryptedConfig []byte `json:"encrypted_config"`

	// Token is a long-lived session token the agent uses for gRPC runtime calls
	// (GetConfiguration, RefreshAuth, etc.).
	Token string `json:"token"`

	// ServerURL is the gRPC runtime server the agent should connect to after
	// login (e.g. "auth.wantastic.app:443").  Optional — if empty the agent
	// falls back to a sensible default.
	ServerURL string `json:"server_url,omitempty"`

	// HandoffURL is the portal confirmation URL.  After the agent applies the
	// new config it should print this URL so the user can open it in a browser
	// and confirm the device appeared in their console.
	HandoffURL string `json:"handoff_url,omitempty"`
}

// RegisterDevice registers the device with the portal after OAuth2 consent and
// returns the portal's response together with the nonce that was used in the
// request body (the caller needs it to decrypt EncryptedConfig).
//
// Headers sent alongside the access-token bearer:
//
//	Authorization:        Bearer <accessToken>
//	x-wantastic-ts:       Unix timestamp (seconds)
//	x-wantastic-device:   hashedDeviceID
//	x-wantastic-sig:      HMAC-SHA256(SharedSecret, "ts:deviceID")
func RegisterDevice(ctx context.Context, portalBaseURL, accessToken, hashedDeviceID string) (*RegisterResponse, uint64, error) {
	var nonce uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &nonce); err != nil {
		nonce = uint64(time.Now().UnixNano())
	}

	hostname, _ := os.Hostname()
	reqBody := RegisterRequest{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Nonce:    nonce,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal register request: %w", err)
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	message := ts + ":" + hashedDeviceID
	mac := hmac.New(sha256.New, []byte(SharedSecret))
	mac.Write([]byte(message))
	sig := hex.EncodeToString(mac.Sum(nil))

	endpoint := strings.TrimRight(portalBaseURL, "/") + RegisterPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("build register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderDevice, hashedDeviceID)
	req.Header.Set(HeaderSig, sig)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		// success — decode below
	case http.StatusUnauthorized:
		return nil, 0, fmt.Errorf("registration rejected (401): invalid or expired access token")
	case http.StatusForbidden:
		return nil, 0, ErrPeerLimitExceeded
	default:
		return nil, 0, fmt.Errorf("register endpoint returned %d", resp.StatusCode)
	}

	var regResp RegisterResponse
	if err := limitDecode(resp.Body, &regResp); err != nil {
		return nil, 0, fmt.Errorf("decode register response: %w", err)
	}
	if len(regResp.EncryptedConfig) == 0 {
		return nil, 0, fmt.Errorf("register response missing encrypted_config")
	}
	return &regResp, nonce, nil
}
