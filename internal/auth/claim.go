package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
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

func WaitClaimConfig(ctx context.Context, portalURL, hashedDeviceID, publicKey string) (*ClaimConfig, error) {
	endpoint, err := claimWaitURL(portalURL, publicKey)
	if err != nil {
		return nil, err
	}

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 15 * time.Second
	if insecureSkipVerify {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	conn, resp, err := dialer.DialContext(ctx, endpoint, signedAgentHeaders(hashedDeviceID))
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("claim wait websocket failed: %w (status %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("claim wait websocket failed: %w", err)
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopCancel()
	conn.SetReadLimit(maxResponseBytes)
	conn.SetPingHandler(func(appData string) error {
		if err := conn.SetReadDeadline(time.Now().Add(90 * time.Second)); err != nil {
			return err
		}
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
	})
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	})
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))

	for {
		var msg claimWaitMessage
		if err := conn.ReadJSON(&msg); err != nil {
			return nil, fmt.Errorf("claim wait websocket read: %w", err)
		}
		claim := msg.claimConfig()
		if claim != nil && claim.Claimed {
			return claim, nil
		}
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	}
}

type claimWaitMessage struct {
	Type                string       `json:"type"`
	Claimed             bool         `json:"claimed"`
	Claim               *ClaimConfig `json:"claim"`
	PublicKey           string       `json:"public_key"`
	AssignedIP          string       `json:"assigned_ip"`
	ServerKey           string       `json:"server_key"`
	Endpoint            string       `json:"endpoint"`
	AllowedIPs          []string     `json:"allowed_ips"`
	DNSServers          []string     `json:"dns_servers"`
	PersistentKeepalive int          `json:"persistent_keepalive"`
	MTU                 int          `json:"mtu"`
	ListenPort          int          `json:"listen_port"`
}

func (m claimWaitMessage) claimConfig() *ClaimConfig {
	if m.Claim != nil {
		return m.Claim
	}
	if !m.Claimed {
		return nil
	}
	return &ClaimConfig{
		Claimed:             m.Claimed,
		PublicKey:           m.PublicKey,
		AssignedIP:          m.AssignedIP,
		ServerKey:           m.ServerKey,
		Endpoint:            m.Endpoint,
		AllowedIPs:          m.AllowedIPs,
		DNSServers:          m.DNSServers,
		PersistentKeepalive: m.PersistentKeepalive,
		MTU:                 m.MTU,
		ListenPort:          m.ListenPort,
	}
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
