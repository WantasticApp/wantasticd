package claimkey

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"wantastic-agent/internal/auth"

	"golang.org/x/crypto/curve25519"
)

type File struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ServerURL  string `json:"server_url"`
	ClaimURL   string `json:"claim_url"`
	CreatedAt  string `json:"created_at"`
}

func DefaultPath() string {
	return auth.PersistentFilePath("device-claim-key.json")
}

func LoadOrCreate(path, serverURL string, rotate bool) (*File, bool, error) {
	serverURL, err := NormalizeServerURL(serverURL)
	if err != nil {
		return nil, false, err
	}
	if !rotate {
		if data, readErr := os.ReadFile(path); readErr == nil {
			var existing File
			if err := json.Unmarshal(data, &existing); err != nil {
				return nil, false, fmt.Errorf("parse existing claim key: %w", err)
			}
			if existing.PrivateKey == "" || existing.PublicKey == "" {
				return nil, false, fmt.Errorf("existing claim key is incomplete")
			}
			existing.ServerURL = serverURL
			existing.ClaimURL = BuildURL(serverURL, existing.PublicKey)
			if err := write(path, &existing); err != nil {
				return nil, false, err
			}
			return &existing, true, nil
		} else if !os.IsNotExist(readErr) {
			return nil, false, fmt.Errorf("read claim key: %w", readErr)
		}
	}

	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return nil, false, fmt.Errorf("generate private key: %w", err)
	}
	privateBytes[0] &= 248
	privateBytes[31] = (privateBytes[31] & 127) | 64
	publicBytes, err := curve25519.X25519(privateBytes, curve25519.Basepoint)
	if err != nil {
		return nil, false, fmt.Errorf("derive public key: %w", err)
	}

	result := &File{
		PrivateKey: base64.StdEncoding.EncodeToString(privateBytes),
		PublicKey:  base64.StdEncoding.EncodeToString(publicBytes),
		ServerURL:  serverURL,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	result.ClaimURL = BuildURL(serverURL, result.PublicKey)
	if err := write(path, result); err != nil {
		return nil, false, err
	}
	return result, false, nil
}

func NormalizeServerURL(raw string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	if base == "" {
		base = "https://" + auth.DefaultOAuth2Domain
	} else if !strings.HasPrefix(strings.ToLower(base), "https://") && !strings.HasPrefix(strings.ToLower(base), "http://") {
		base = "https://" + base
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("invalid Wantastic server URL %q", raw)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLocalHost(parsed.Hostname())) {
		return "", fmt.Errorf("Wantastic server must use HTTPS (HTTP is allowed only for localhost)")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func BuildURL(serverURL, publicKey string) string {
	return serverURL + "/#desktop?claim_public_key=" + url.QueryEscape(strings.TrimSpace(publicKey)) +
		"&wantastic_server=" + url.QueryEscape(serverURL)
}

func isLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func write(path string, value *File) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal claim key: %w", err)
	}
	if err := auth.EnsureParentDir(path, 0o700); err != nil {
		return fmt.Errorf("create claim-key directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write claim key: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure claim key permissions: %w", err)
	}
	return nil
}
