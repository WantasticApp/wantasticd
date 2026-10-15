package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/auth"
	"wantastic-agent/internal/claimkey"
	"wantastic-agent/internal/device"
	"wantastic-agent/internal/netprobe"
)

func TestWindowsDesktopManifestIsUnprivileged(t *testing.T) {
	t.Parallel()
	manifest, err := os.ReadFile("build/windows/wails.exe.manifest")
	if err != nil {
		t.Fatal(err)
	}
	text := string(manifest)
	if !strings.Contains(text, `requestedExecutionLevel level="asInvoker" uiAccess="false"`) {
		t.Fatal("desktop manifest must run asInvoker; privileged operations belong in the service")
	}
	if strings.Contains(text, `level="requireAdministrator"`) {
		t.Fatal("desktop UI must not request administrator privileges")
	}
}

func TestPeerConnection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		peer device.PeerInfo
		want string
	}{
		{name: "direct", peer: device.PeerInfo{IsP2P: true, P2PState: "established"}, want: "direct"},
		{name: "trying", peer: device.PeerInfo{IsP2P: true, P2PState: "trying"}, want: "trying"},
		{name: "relay fallback", peer: device.PeerInfo{IsP2P: false, P2PState: "failed"}, want: "relay"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := peerConnection(tt.peer); got != tt.want {
				t.Fatalf("peerConnection() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMagicName(t *testing.T) {
	t.Parallel()
	if got := magicName(device.PeerInfo{Hostname: "Office AP #1", AssignedIP: "10.8.0.7"}); got != "office-ap-1.wantastic" {
		t.Fatalf("magicName(hostname) = %q", got)
	}
	if got := magicName(device.PeerInfo{AssignedIP: "10.8.0.7"}); got != "node-10-8-0-7.wantastic" {
		t.Fatalf("magicName(ip) = %q", got)
	}
}

func TestNativePingRejectsCommandInput(t *testing.T) {
	t.Parallel()
	if _, _, err := netprobe.Ping(context.Background(), "10.8.0.7; open /Applications/Calculator.app"); err == nil {
		t.Fatal("native ping accepted a command-like address")
	}
}

func TestSelectPingTargetAllowsOnlyTenantRoute(t *testing.T) {
	t.Parallel()
	selected, err := selectPingTarget("10.255.255.36", nil, []string{"10.255.255.32/27"})
	if err != nil {
		t.Fatalf("selectPingTarget() error = %v", err)
	}
	if selected.AssignedIP != "10.255.255.36" || selected.MagicName != "node-10-255-255-36.wantastic" {
		t.Fatalf("selectPingTarget() = %#v", selected)
	}
	if _, err := selectPingTarget("1.1.1.1", nil, []string{"10.255.255.32/27"}); err == nil {
		t.Fatal("selectPingTarget() accepted an address outside the tenant route")
	}
}

func TestMakeTrayPresentation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		status     *StatusData
		err        error
		wantStatus string
		wantLabel  string
		wantIP     string
		wantToggle string
		wantTip    string
	}{
		{
			name: "connected",
			status: &StatusData{
				Configured:    true,
				Running:       true,
				DeviceRunning: true,
				IPs:           []string{"10.20.0.7"},
			},
			wantStatus: "Online",
			wantLabel:  "Online",
			wantIP:     "IP: 10.20.0.7",
			wantToggle: "Disconnect",
			wantTip:    "Wantastic — Online — 10.20.0.7",
		},
		{
			name:       "starting",
			status:     &StatusData{Configured: true, Starting: true},
			wantStatus: "Starting",
			wantLabel:  "Starting",
			wantIP:     "IP: –",
			wantToggle: "Starting…",
			wantTip:    "Wantastic — Starting",
		},
		{
			name:       "disconnected",
			status:     &StatusData{Configured: true},
			wantStatus: "Offline",
			wantLabel:  "Offline",
			wantIP:     "IP: –",
			wantToggle: "Connect",
			wantTip:    "Wantastic — Offline",
		},
		{
			name:       "not configured",
			status:     &StatusData{},
			wantStatus: "Offline",
			wantLabel:  "Offline",
			wantIP:     "IP: –",
			wantToggle: "Connect",
			wantTip:    "Wantastic — Offline",
		},
		{
			name:       "unavailable",
			err:        errors.New("status failed"),
			wantStatus: "Offline",
			wantLabel:  "Offline",
			wantIP:     "IP: –",
			wantToggle: "Connect",
			wantTip:    "Wantastic — Offline",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := makeTrayPresentation(tt.status, tt.err)
			if got.trayLabel != tt.wantLabel || got.statusTitle != tt.wantStatus || got.ipTitle != tt.wantIP ||
				got.toggleTitle != tt.wantToggle || got.tooltip != tt.wantTip {
				t.Fatalf("makeTrayPresentation() = %#v", got)
			}
		})
	}
}

func TestGenerateClaimLinkStartsAutomaticConnectionWatcher(t *testing.T) {
	t.Setenv("WANTASTIC_CONFIG_DIR", t.TempDir())
	app := NewApp(nil)
	app.ctx = context.Background()
	app.hashedDeviceID = func() (string, error) { return "desktop-device-id", nil }
	app.waitClaimConfig = func(
		_ context.Context,
		serverURL string,
		deviceID string,
		publicKey string,
	) (*auth.ClaimConfig, error) {
		if serverURL != "https://console.wantastic.app" || deviceID != "desktop-device-id" || publicKey == "" {
			t.Errorf("unexpected claim watcher input: server=%q device=%q key=%q", serverURL, deviceID, publicKey)
		}
		return &auth.ClaimConfig{Claimed: true}, nil
	}
	app.fetchClaimConfig = func(context.Context, string, string, string) (*auth.ClaimConfig, error) {
		return nil, errors.New("polling should not be needed")
	}
	connected := make(chan string, 1)
	app.applyDesktopClaim = func(key *claimkey.File, claim *auth.ClaimConfig) error {
		if !claim.Claimed {
			t.Error("automatic connection received an unclaimed configuration")
		}
		connected <- key.PublicKey
		return nil
	}
	t.Cleanup(app.stopClaimWatcher)

	link, err := app.GenerateClaimLink("https://console.wantastic.app", false)
	if err != nil {
		t.Fatalf("GenerateClaimLink: %v", err)
	}
	select {
	case publicKey := <-connected:
		if publicKey != link.PublicKey {
			t.Fatalf("connected public key=%q want %q", publicKey, link.PublicKey)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("claim watcher did not activate the claimed configuration")
	}
}
