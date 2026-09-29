package config

import (
	"encoding/base64"
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
