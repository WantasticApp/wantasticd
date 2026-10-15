package claimkey

import (
	"path/filepath"
	"testing"

	"wantastic-agent/internal/auth"
)

func TestLoadOrCreateReusesAndRotatesIdentity(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "claim.json")
	first, reused, err := LoadOrCreate(path, "https://console.wantastic.app", false)
	if err != nil || reused {
		t.Fatalf("first LoadOrCreate() = reused %v, err %v", reused, err)
	}
	second, reused, err := LoadOrCreate(path, "console.wantastic.app", false)
	if err != nil || !reused {
		t.Fatalf("second LoadOrCreate() = reused %v, err %v", reused, err)
	}
	if first.PrivateKey != second.PrivateKey || first.PublicKey != second.PublicKey {
		t.Fatal("claim identity changed without rotation")
	}
	third, reused, err := LoadOrCreate(path, "https://console.wantastic.app", true)
	if err != nil || reused {
		t.Fatalf("rotated LoadOrCreate() = reused %v, err %v", reused, err)
	}
	if third.PublicKey == first.PublicKey {
		t.Fatal("rotation preserved the old public key")
	}
	if err := auth.CheckPrivateFilePermissions(path); err != nil {
		t.Fatalf("claim key permissions: %v", err)
	}
}

func TestNormalizeServerURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "hostname", input: "console.wantastic.app", want: "https://console.wantastic.app"},
		{name: "local HTTP", input: "http://localhost:3000/path", want: "http://localhost:3000"},
		{name: "reject remote HTTP", input: "http://example.com", wantErr: true},
		{name: "reject LAN HTTP", input: "http://portal.local", wantErr: true},
		{name: "reject credentials", input: "https://user@example.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeServerURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeServerURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("NormalizeServerURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
