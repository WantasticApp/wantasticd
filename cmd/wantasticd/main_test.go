package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wantastic-agent/internal/config"
)

func TestAutoUpdateFlagsDefaultOnAndExplicitOptOut(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "default enables auto update",
			args: nil,
			want: true,
		},
		{
			name: "legacy enable flag stays accepted",
			args: []string{"--auto-update"},
			want: true,
		},
		{
			name: "explicit false disables auto update",
			args: []string{"--auto-update=false"},
			want: false,
		},
		{
			name: "new opt out flag disables auto update",
			args: []string{"--no-auto-update"},
			want: false,
		},
		{
			name: "opt out wins over enable",
			args: []string{"--auto-update", "--no-auto-update"},
			want: false,
		},
		{
			name: "explicit false opt out keeps default enabled",
			args: []string{"--no-auto-update=false"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			flags := registerAutoUpdateFlags(fs, "Enable automatic self-updates (default on)", "Disable automatic self-updates")
			if err := fs.Parse(tt.args); err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			if got := flags.Enabled(); got != tt.want {
				t.Fatalf("Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLocalAccessFlagIsOptInAndSupportsExplicitDisable(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		configured bool
		want       bool
	}{
		{name: "omitted preserves disabled config", configured: false, want: false},
		{name: "omitted preserves enabled config", configured: true, want: true},
		{name: "bare flag enables", args: []string{"--allow-local-access"}, want: true},
		{name: "explicit false disables", args: []string{"--allow-local-access=false"}, configured: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			localAccess := registerLocalAccessFlag(fs)
			if err := fs.Parse(tt.args); err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			cfg := &config.Config{AllowLocalAccess: tt.configured}
			localAccess.apply(cfg)
			if cfg.AllowLocalAccess != tt.want {
				t.Fatalf("AllowLocalAccess = %v, want %v", cfg.AllowLocalAccess, tt.want)
			}
		})
	}
}

func TestAdvertiseRoutesEnablesLocalAccessAndAcceptsHostRoute(t *testing.T) {
	t.Parallel()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	localAccess := registerLocalAccessFlag(fs)
	if err := fs.Parse([]string{"--advertise-routes=192.168.1.25/32,10.20.4.3/16"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	cfg := &config.Config{}
	localAccess.apply(cfg)
	if !cfg.AllowLocalAccess {
		t.Fatal("--advertise-routes did not enable local access")
	}
	want := []string{"10.20.0.0/16", "192.168.1.25/32"}
	if !reflect.DeepEqual(cfg.LocalAccessRoutes, want) {
		t.Fatalf("LocalAccessRoutes = %v, want %v", cfg.LocalAccessRoutes, want)
	}
}

func TestLoadOrCreateClaimKeyReusesIdentityAndPersistsServerChange(t *testing.T) {
	t.Setenv("WANTASTIC_STATE_DIR", t.TempDir())
	path := filepath.Join(t.TempDir(), "manufacturer-claim.json")

	first, reused, err := loadOrCreateClaimKey(path, "https://console.wantastic.app", false)
	if err != nil {
		t.Fatalf("create claim key: %v", err)
	}
	if reused {
		t.Fatal("first claim key creation reported reuse")
	}
	if !strings.Contains(first.ClaimURL, "claim_public_key=") {
		t.Fatalf("claim URL does not contain public key: %q", first.ClaimURL)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("simulate legacy claim key permissions: %v", err)
	}

	second, reused, err := loadOrCreateClaimKey(path, "beta.wantastic.app", false)
	if err != nil {
		t.Fatalf("reuse claim key: %v", err)
	}
	if !reused {
		t.Fatal("existing manufacturer key was unexpectedly rotated")
	}
	if second.PrivateKey != first.PrivateKey || second.PublicKey != first.PublicKey {
		t.Fatal("reusing a manufacturer claim must preserve its WireGuard identity")
	}
	if second.ServerURL != "https://beta.wantastic.app" {
		t.Fatalf("server URL = %q, want beta origin", second.ServerURL)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted claim key: %v", err)
	}
	var persisted claimKeyFile
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("decode persisted claim key: %v", err)
	}
	if persisted.ServerURL != second.ServerURL || persisted.ClaimURL != second.ClaimURL {
		t.Fatalf("persisted claim metadata = %#v, want server and QR metadata %#v", persisted, second)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat claim key: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("claim key permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestLoadOrCreateClaimKeyForceRotatesIdentity(t *testing.T) {
	t.Setenv("WANTASTIC_STATE_DIR", t.TempDir())
	path := filepath.Join(t.TempDir(), "manufacturer-claim.json")
	first, _, err := loadOrCreateClaimKey(path, "console.wantastic.app", false)
	if err != nil {
		t.Fatalf("create claim key: %v", err)
	}
	rotated, reused, err := loadOrCreateClaimKey(path, "console.wantastic.app", true)
	if err != nil {
		t.Fatalf("rotate claim key: %v", err)
	}
	if reused {
		t.Fatal("forced key generation reported reuse")
	}
	if rotated.PrivateKey == first.PrivateKey || rotated.PublicKey == first.PublicKey {
		t.Fatal("--force did not rotate the manufacturer identity")
	}
}
