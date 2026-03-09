package grpc

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

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
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
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

func (c *Client) RegisterDevice(ctx context.Context, nonce uint64, osInfo, arch, hostname string) (*pb.RegisterDeviceResponse, error) {
	c.mu.RLock()
	if c.conn == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client not initialized")
	}
	token := c.token
	c.mu.RUnlock()

	// Use raw wire encoding so field numbers match the spec regardless of what
	// the generated auth.pb.go descriptor says. See register_device_wire.go.
	reqBytes := marshalRegisterDeviceRequest(token, hostname, osInfo, arch, nonce)

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

func (c *Client) StartDeviceFlow(ctx context.Context) (*pb.RegisterDeviceResponse, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected to auth server")
	}

	req := &pb.StartDeviceFlowRequest{
		DeviceId: c.deviceID,
	}

	resp, err := client.StartDeviceFlow(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("start device flow: %w", err)
	}

	fmt.Printf("\n🚀 Device Authorization Required\n")
	fmt.Printf("-------------------------------\n")
	fmt.Printf("1. Open: %s\n", resp.VerificationUri)
	fmt.Printf("2. Enter Code: %s\n\n", resp.UserCode)
	log.Println("Waiting for authorization...")

	ticker := time.NewTicker(time.Duration(resp.Interval) * time.Second)
	defer ticker.Stop()

	timeout := time.After(time.Duration(resp.ExpiresIn) * time.Second)

	for {
		select {
		case <-ticker.C:
			pollReq := &pb.PollDeviceFlowRequest{
				DeviceCode: resp.DeviceCode,
			}
			pollResp, err := client.PollDeviceFlow(ctx, pollReq)
			if err != nil {
				continue
			}
			if pollResp.Success {
				c.mu.Lock()
				c.token = pollResp.Token
				c.mu.Unlock()

				log.Println("✅ Authorization successful! Registering device...")

				// Gather system information for registration
				hostname, _ := os.Hostname()
				return c.RegisterDevice(ctx, uint64(time.Now().UnixNano()), runtime.GOOS, runtime.GOARCH, hostname)
			}
		case <-timeout:
			return nil, fmt.Errorf("device flow timed out")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// StartDeviceFlowWithCallback starts the gRPC device flow and calls onVerification
// immediately with the user_code and verification_uri before polling begins.
// It returns the Auth0 access token, the nonce used for RegisterDevice, and the
// RegisterDeviceResponse. The access token is the decryption key for EncryptedConfig.
func (c *Client) StartDeviceFlowWithCallback(
	ctx context.Context,
	onVerification func(userCode, verificationURI string),
) (accessToken string, nonce uint64, regResp *pb.RegisterDeviceResponse, err error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return "", 0, nil, fmt.Errorf("not connected to auth server")
	}

	startResp, err := client.StartDeviceFlow(ctx, &pb.StartDeviceFlowRequest{
		DeviceId: c.deviceID,
	})
	if err != nil {
		return "", 0, nil, fmt.Errorf("start device flow: %w", err)
	}

	// Surface the user code to the caller immediately (before blocking poll)
	if onVerification != nil {
		onVerification(startResp.UserCode, startResp.VerificationUri)
	}

	log.Printf("Device flow started — waiting for approval (code: %s)", startResp.UserCode)

	interval := startResp.Interval
	if interval <= 0 {
		interval = 5
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	timeout := time.After(time.Duration(startResp.ExpiresIn) * time.Second)

	for {
		select {
		case <-ticker.C:
			pollResp, pollErr := client.PollDeviceFlow(ctx, &pb.PollDeviceFlowRequest{
				DeviceCode: startResp.DeviceCode,
			})
			if pollErr != nil {
				log.Printf("Poll error (retrying): %v", pollErr)
				continue
			}
			if pollResp.Success {
				c.mu.Lock()
				c.token = pollResp.Token
				c.mu.Unlock()

				log.Println("Device flow approved — registering device…")

				// Generate a cryptographic nonce for config encryption
				var n uint64
				if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
					n = uint64(time.Now().UnixNano())
				}

				hostname, _ := os.Hostname()
				reg, regErr := c.RegisterDevice(ctx, n, runtime.GOOS, runtime.GOARCH, hostname)
				if regErr != nil {
					return "", 0, nil, regErr
				}
				return pollResp.Token, n, reg, nil
			}
		case <-timeout:
			return "", 0, nil, fmt.Errorf("device flow timed out")
		case <-ctx.Done():
			return "", 0, nil, ctx.Err()
		}
	}
}

func (c *Client) SetNodeRouting(ctx context.Context, req *pb.SetNodeRoutingRequest) (*pb.SetNodeRoutingResponse, error) {
	c.mu.RLock()
	token := c.token
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected to auth server")
	}

	req.Token = token

	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
	ctx = metadata.NewOutgoingContext(ctx, md)

	return client.SetNodeRouting(ctx, req)
}
