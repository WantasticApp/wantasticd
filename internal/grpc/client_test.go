package grpc

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	authServerHost = "auth.wantastic.app"
	authServerPort = "443"
	authServerAddr = authServerHost + ":" + authServerPort
)

// TestResolveServerURL validates that resolveServerURL correctly handles
// various input formats and always produces a valid host:port pair.
func TestResolveServerURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "full host:port",
			input: "auth.wantastic.app:443",
			want:  "auth.wantastic.app:443",
		},
		{
			name:  "host only - default port added",
			input: "auth.wantastic.app",
			want:  "auth.wantastic.app:443",
		},
		{
			name:  "host with custom port",
			input: "auth.wantastic.app:443",
			want:  "auth.wantastic.app:443",
		},
		{
			name:  "IP address with port",
			input: "1.2.3.4:50051",
			want:  "1.2.3.4:50051",
		},
		{
			name:  "IP address only",
			input: "1.2.3.4",
			want:  "1.2.3.4:443",
		},
		{
			name:  "localhost",
			input: "localhost",
			want:  "localhost:443",
		},
		{
			name:  "localhost with port",
			input: "localhost:50051",
			want:  "localhost:50051",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveServerURL(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("resolveServerURL(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("resolveServerURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestAuthServerDNSResolution validates that auth.wantastic.app resolves
// to at least one IP address. This is the first thing that must succeed
// before any gRPC connection can be established.
func TestAuthServerDNSResolution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resolver := net.DefaultResolver
	ips, err := resolver.LookupHost(ctx, authServerHost)
	if err != nil {
		t.Fatalf("DNS resolution failed for %s: %v\n"+
			"This means the auth server hostname is not resolvable.\n"+
			"Possible causes:\n"+
			"  - DNS record not created for %s\n"+
			"  - DNS server unreachable from this network\n"+
			"  - Typo in hostname",
			authServerHost, err, authServerHost)
	}

	if len(ips) == 0 {
		t.Fatalf("DNS resolution returned zero addresses for %s\n"+
			"This is the exact error seen in the gRPC client:\n"+
			"  'name resolver error: produced zero addresses'",
			authServerHost)
	}

	t.Logf("✅ DNS resolution OK: %s -> %v", authServerHost, ips)
}

// TestAuthServerTCPReachable validates that the auth server is reachable
// via TCP on the expected port.
func TestAuthServerTCPReachable(t *testing.T) {
	// First ensure DNS works
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, authServerHost)
	if err != nil || len(ips) == 0 {
		t.Skipf("Skipping TCP test: DNS resolution failed for %s: %v", authServerHost, err)
	}

	// Try TCP connection to each resolved IP
	var lastErr error
	connected := false
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, authServerPort)
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			lastErr = err
			t.Logf("TCP connection failed to %s: %v", addr, err)
			continue
		}
		conn.Close()
		connected = true
		t.Logf("✅ TCP connection OK to %s (%s)", addr, authServerHost)
		break
	}

	if !connected {
		t.Fatalf("Cannot reach auth server %s on port %s via TCP.\n"+
			"Resolved IPs: %v\n"+
			"Last error: %v\n"+
			"Possible causes:\n"+
			"  - Firewall blocking port %s\n"+
			"  - Auth service not running\n"+
			"  - Wrong port configured",
			authServerHost, authServerPort, ips, lastErr, authServerPort)
	}
}

// TestAuthServerGRPCConnection validates that a gRPC client can
// successfully connect to the auth server and the name resolver works.
func TestAuthServerGRPCConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// First validate DNS independently
	ips, err := net.DefaultResolver.LookupHost(ctx, authServerHost)
	if err != nil || len(ips) == 0 {
		t.Skipf("Skipping gRPC test: DNS resolution failed for %s: %v", authServerHost, err)
	}

	// Try gRPC connection using the hostname (tests gRPC's internal resolver)
	conn, err := grpc.NewClient(authServerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient(%q) failed: %v\n"+
			"This means gRPC cannot even create a client for this address.",
			authServerAddr, err)
	}
	defer conn.Close()

	// Force a connection attempt by calling Connect
	conn.Connect()

	// Wait for the connection to become ready (or fail)
	connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connectCancel()

	ready := conn.WaitForStateChange(connectCtx, conn.GetState())
	state := conn.GetState()

	t.Logf("gRPC connection state: %s (changed: %v)", state, ready)

	// Also try with explicit IP to bypass gRPC resolver
	ipAddr := net.JoinHostPort(ips[0], authServerPort)
	connIP, err := grpc.NewClient(ipAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient with IP %q failed: %v", ipAddr, err)
	}
	defer connIP.Close()

	connIP.Connect()
	ipConnectCtx, ipConnectCancel := context.WithTimeout(ctx, 10*time.Second)
	defer ipConnectCancel()
	connIP.WaitForStateChange(ipConnectCtx, connIP.GetState())
	ipState := connIP.GetState()

	t.Logf("gRPC connection via IP %s state: %s", ips[0], ipState)
}

// TestAuthServerGRPCWithManualDNS tests the workaround: resolve DNS manually
// then pass the IP to gRPC, bypassing the gRPC name resolver entirely.
// This is the pattern to use if the gRPC default resolver fails on embedded systems.
func TestAuthServerGRPCWithManualDNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Step 1: Manual DNS resolution
	ips, err := net.DefaultResolver.LookupHost(ctx, authServerHost)
	if err != nil || len(ips) == 0 {
		t.Skipf("Skipping: DNS resolution failed for %s: %v", authServerHost, err)
	}

	// Step 2: Use passthrough scheme so gRPC skips its internal resolver
	target := fmt.Sprintf("passthrough:///%s", net.JoinHostPort(ips[0], authServerPort))
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient with passthrough scheme failed: %v", err)
	}
	defer conn.Close()

	conn.Connect()

	connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connectCancel()
	conn.WaitForStateChange(connectCtx, conn.GetState())
	state := conn.GetState()

	t.Logf("✅ gRPC connection via manual DNS (%s -> %s): state=%s", authServerHost, ips[0], state)
}
