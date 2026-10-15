package config

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestValidateRequiresAuthenticatedServerIdentity(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString(make([]byte, 32))

	tests := []struct {
		name      string
		serverKey string
		wantError string
	}{
		{name: "missing", wantError: "server public key required"},
		{name: "invalid encoding", serverKey: "not-a-wireguard-key", wantError: "base64-encoded 32-byte"},
		{name: "invalid length", serverKey: base64.StdEncoding.EncodeToString([]byte("short")), wantError: "base64-encoded 32-byte"},
		{name: "valid", serverKey: validKey},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &Config{
				PrivateKey: "configured",
				Server: Server{
					Endpoint:  "127.0.0.1",
					PublicKey: test.serverKey,
				},
			}

			err := cfg.Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() returned error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestValidateLocalAccessRoutesSupportsHostRoutes(t *testing.T) {
	t.Parallel()
	want := []string{"10.20.0.0/16", "192.168.1.25/32"}
	got, err := ValidateLocalAccessRoutes([]string{"192.168.1.25/32", "10.20.4.3/16", "192.168.1.25/32"})
	if err != nil {
		t.Fatalf("ValidateLocalAccessRoutes() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ValidateLocalAccessRoutes() = %v, want %v", got, want)
	}
	if _, err := ValidateLocalAccessRoutes([]string{"203.0.113.7/32"}); err == nil {
		t.Fatal("public /32 was accepted")
	}
}

func TestValidateLocalAccessOverlaySeparation(t *testing.T) {
	t.Parallel()
	if err := ValidateLocalAccessOverlaySeparation(
		[]string{"192.168.1.25/32"},
		[]string{"10.255.255.32/27"},
	); err != nil {
		t.Fatalf("ValidateLocalAccessOverlaySeparation() error = %v", err)
	}
	if err := ValidateLocalAccessOverlaySeparation(
		[]string{"10.255.255.36/32"},
		[]string{"10.255.255.32/27"},
	); err == nil || !strings.Contains(err.Error(), "overlaps tenant overlay") {
		t.Fatalf("overlapping local route error = %v", err)
	}
}
