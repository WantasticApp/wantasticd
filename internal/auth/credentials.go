package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// FetchCredentials calls GET /api/agent/credentials on the portal and returns
// the OAuth2 domain and client_id needed to start an auth flow.
//
// The request carries three headers as per the spec:
//   - x-wantastic-ts      : current Unix timestamp in seconds
//   - x-wantastic-device  : HMAC-SHA256 hashed device fingerprint
//   - x-wantastic-sig     : HMAC-SHA256("ts:deviceID")
//
// portalURL must be an https:// URL (e.g. "https://console.wantastic.app").
func FetchCredentials(ctx context.Context, portalURL, hashedDeviceID string) (*Credentials, error) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	// Signature covers "timestamp:deviceID" to bind the proof to this device.
	message := ts + ":" + hashedDeviceID
	mac := hmac.New(sha256.New, []byte(SharedSecret))
	mac.Write([]byte(message))
	sig := hex.EncodeToString(mac.Sum(nil))

	url := strings.TrimRight(portalURL, "/") + CredentialsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build credentials request: %w", err)
	}
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderDevice, hashedDeviceID)
	req.Header.Set(HeaderSig, sig)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch credentials: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// success — fall through to decode
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("credentials rejected (401): invalid signature or timestamp out of window")
	default:
		return nil, fmt.Errorf("unexpected status from credentials endpoint: %d", resp.StatusCode)
	}

	var creds Credentials
	if err := limitDecode(resp.Body, &creds); err != nil {
		return nil, fmt.Errorf("decode credentials response: %w", err)
	}
	if creds.Domain == "" || creds.ClientID == "" {
		return nil, fmt.Errorf("credentials response missing domain or client_id")
	}
	return &creds, nil
}
