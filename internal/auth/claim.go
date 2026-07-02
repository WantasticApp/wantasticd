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

func FetchClaimConfig(ctx context.Context, portalURL, hashedDeviceID, publicKey string) (*ClaimConfig, error) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	message := ts + ":" + hashedDeviceID
	mac := hmac.New(sha256.New, []byte(SharedSecret))
	mac.Write([]byte(message))
	sig := hex.EncodeToString(mac.Sum(nil))

	endpoint := strings.TrimRight(portalURL, "/") + ClaimConfigPath + "?public_key=" + url.QueryEscape(strings.TrimSpace(publicKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build claim config request: %w", err)
	}
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderDevice, hashedDeviceID)
	req.Header.Set(HeaderSig, sig)

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
