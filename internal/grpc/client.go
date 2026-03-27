package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"wantastic-agent/internal/cipher"
	pb "wantastic-agent/internal/grpc/proto"
)

// resolveServerURL ensures the server URL has a port, defaulting to 443 if missing.
// It does NOT perform DNS resolution, leaving that to the gRPC client.
func resolveServerURL(serverURL string) (string, error) {
	host, port, err := net.SplitHostPort(serverURL)
	if err != nil {
		// No port — treat entire string as host and use default port 443
		host = serverURL
		port = "443"
	}

	return net.JoinHostPort(host, port), nil
}

type Client struct {
	serverURL string
	deviceID  string
	token     string

	conn   *grpc.ClientConn
	client pb.AuthServiceClient

	mu        sync.RWMutex
	connected bool
}

func New(serverURL, deviceID, token string) (*Client, error) {
	client := &Client{
		serverURL: serverURL,
		deviceID:  deviceID,
		token:     token,
	}

	if err := client.connect(); err != nil {
		return nil, fmt.Errorf("connect to auth server: %w", err)
	}

	return client, nil
}

func (c *Client) connect() error {
	c.mu.Lock()

	if c.connected {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	// Resolve hostname to IP using Cloudflare DNS (1.1.1.1)
	// This ensures DNS works on minimal Alpine/musl systems where
	// grpc.NewClient's internal DNS resolver may fail.
	serverAddr, err := resolveServerURL(c.serverURL)
	if err != nil {
		return fmt.Errorf("resolve server URL: %w", err)
	}

	if serverAddr != c.serverURL {
		// Extract just the hostname for logging
		origHost := c.serverURL
		if h, _, splitErr := net.SplitHostPort(c.serverURL); splitErr == nil {
			origHost = h
		}
		resolvedHost := serverAddr
		if h, _, splitErr := net.SplitHostPort(serverAddr); splitErr == nil {
			resolvedHost = h
		}
		log.Printf("Resolved %s -> %s", origHost, resolvedHost)
	}

	// Determine transport security: use TLS for all non-localhost addresses.
	// The Wantastic gRPC server listens on :52990 with TLS.
	// Local dev servers (e.g. :50051 on 127.0.0.1) use plaintext.
	var transportCreds credentials.TransportCredentials
	host, _, _ := net.SplitHostPort(serverAddr)
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal")
	if !isLocal {
		// Use TLS — skip cert verification for compatibility with self-signed certs
		transportCreds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec
		log.Printf("Using TLS for connection to %s", serverAddr)
	} else {
		transportCreds = insecure.NewCredentials()
		log.Printf("Using insecure (plaintext) connection to %s", serverAddr)
	}

	// Add Cipher Credentials (HMAC Signature)
	cipherCreds := cipher.NewCredentials()

	conn, err := grpc.NewClient(serverAddr,
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithPerRPCCredentials(cipherCreds),
	)
	if err != nil {
		return fmt.Errorf("dial auth server: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn = conn
	c.client = pb.NewAuthServiceClient(conn)
	c.connected = true

	log.Printf("Connected to auth server: %s", serverAddr)
	return nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.connected = false
	}
}

func (c *Client) RegisterDevice(ctx context.Context, nonce uint64, osInfo, arch, hostname, deviceID string) (*pb.RegisterDeviceResponse, error) {
	c.mu.RLock()
	if c.conn == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client not initialized")
	}
	token := c.token
	c.mu.RUnlock()

	// Use raw wire encoding so field numbers match the spec regardless of what
	// the generated auth.pb.go descriptor says. See register_device_wire.go.
	reqBytes := marshalRegisterDeviceRequest(token, hostname, osInfo, arch, deviceID, nonce)

	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
	ctx = metadata.NewOutgoingContext(ctx, md)

	var rawResp rawProtoMessage
	if err := c.conn.Invoke(ctx, "/grpc.AuthService/RegisterDevice",
		rawProtoMessage(reqBytes), &rawResp); err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}

	resp := unmarshalRegisterDeviceResponse(rawResp)

	if resp.Success {
		c.mu.Lock()
		c.token = resp.Token
		c.mu.Unlock()
	}

	return resp, nil
}

func (c *Client) RefreshAuth(ctx context.Context) error {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	req := &pb.RefreshTokenRequest{
		Token: token,
	}

	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := c.client.RefreshToken(ctx, req)
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}

	if resp.Success {
		c.mu.Lock()
		c.token = resp.Token
		c.mu.Unlock()
		log.Println("Token refreshed successfully")
	}

	return nil
}

func (c *Client) GetConfiguration(ctx context.Context) (*pb.GetConfigurationResponse, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	req := &pb.GetConfigurationRequest{
		Token: token,
	}

	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := c.client.GetConfiguration(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get configuration: %w", err)
	}

	return resp, nil
}

// ValidateExportToken verifies an export token with the current server.
func (c *Client) ValidateExportToken(ctx context.Context, token string) (bool, error) {
	c.mu.RLock()
	if c.conn == nil {
		c.mu.RUnlock()
		return false, fmt.Errorf("client not initialized")
	}
	authToken := c.token
	c.mu.RUnlock()

	reqBytes := marshalValidateExportTokenRequest(token)
	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", authToken))
	ctx = metadata.NewOutgoingContext(ctx, md)

	var rawResp rawProtoMessage
	if err := c.conn.Invoke(ctx, "/grpc.AuthService/ValidateExportToken",
		rawProtoMessage(reqBytes), &rawResp); err != nil {
		return false, fmt.Errorf("validate export token: %w", err)
	}

	return unmarshalValidateExportTokenResponse(rawResp), nil
}

// RegisterPeer registers the device as a peer in the target account.
func (c *Client) RegisterPeer(ctx context.Context, accountID, pubKeyHex string) (*ExportPeerInfo, error) {
	c.mu.RLock()
	if c.conn == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client not initialized")
	}
	authToken := c.token
	c.mu.RUnlock()

	reqBytes := marshalRegisterPeerRequest(accountID, pubKeyHex)
	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", authToken))
	ctx = metadata.NewOutgoingContext(ctx, md)

	var rawResp rawProtoMessage
	if err := c.conn.Invoke(ctx, "/grpc.AuthService/RegisterPeer",
		rawProtoMessage(reqBytes), &rawResp); err != nil {
		return nil, fmt.Errorf("register peer: %w", err)
	}

	return unmarshalRegisterPeerResponse(rawResp), nil
}

