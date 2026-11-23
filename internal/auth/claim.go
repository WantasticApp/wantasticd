package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func signedAgentHeaders(hashedDeviceID string) http.Header {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	message := ts + ":" + hashedDeviceID
	mac := hmac.New(sha256.New, []byte(SharedSecret))
	mac.Write([]byte(message))
	sig := hex.EncodeToString(mac.Sum(nil))

	headers := http.Header{}
	headers.Set(HeaderTimestamp, ts)
	headers.Set(HeaderDevice, hashedDeviceID)
	headers.Set(HeaderSig, sig)
	return headers
}

func FetchClaimConfig(ctx context.Context, portalURL, hashedDeviceID, publicKey string) (*ClaimConfig, error) {
	endpoint := strings.TrimRight(portalURL, "/") + ClaimConfigPath + "?public_key=" + url.QueryEscape(strings.TrimSpace(publicKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build claim config request: %w", err)
	}
	for key, values := range signedAgentHeaders(hashedDeviceID) {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch claim config: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("claim config rejected (401): invalid signature or timestamp out of window")
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("claim config unavailable (503)")
	default:
		return nil, fmt.Errorf("unexpected status from claim config endpoint: %d", resp.StatusCode)
	}

	var cfg ClaimConfig
	if err := limitDecode(resp.Body, &cfg); err != nil {
		return nil, fmt.Errorf("decode claim config response: %w", err)
	}
	return &cfg, nil
}

func claimWaitURL(portalURL, publicKey string) (string, error) {
	u, err := url.Parse(strings.TrimRight(portalURL, "/"))
	if err != nil {
		return "", fmt.Errorf("parse portal url: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "wss", "ws":
	default:
		return "", fmt.Errorf("unsupported portal scheme for claim wait: %s", u.Scheme)
	}
	u.Path = ClaimWaitPath
	u.RawQuery = url.Values{"public_key": {strings.TrimSpace(publicKey)}}.Encode()
	return u.String(), nil
}
