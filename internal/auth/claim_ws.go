//go:build !tinygo

package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
)

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
