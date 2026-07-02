package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/denisbrodbeck/machineid"
)

// fallbackIDFile is where we persist a generated ID when machineid is
// unavailable, so the fingerprint stays stable across runs.
const fallbackIDFile = ".device-id"

// HashedDeviceID returns a privacy-preserving, stable device fingerprint.
// It computes HMAC-SHA256(SharedSecret, normalized_hardware_id).
//
// Algorithm:
//  1. Try machineid.ID() (platform-native machine identifier)
//  2. If unavailable, load/generate an ID stored at fallbackIDFile
//  3. Normalize: trim whitespace, lowercase
//  4. Hash: HMAC-SHA256(SharedSecret, normalized_id)
//  5. Encode: hex string
func HashedDeviceID() (string, error) {
	raw, err := machineid.ID()
	if err != nil || strings.TrimSpace(raw) == "" {
		raw, err = persistentFallbackID()
		if err != nil {
			return "", fmt.Errorf("device id unavailable: %w", err)
		}
	}
	normalized := strings.ToLower(strings.TrimSpace(raw))
	mac := hmac.New(sha256.New, []byte(SharedSecret))
	mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// persistentFallbackID loads the stored fallback ID or generates and persists
// a new random one.
func persistentFallbackID() (string, error) {
	path := PersistentFilePath(fallbackIDFile)
	if id := strings.TrimSpace(readTextFile(path)); id != "" {
		return id, nil
	}
	if serial, err := PersistentSerialNumber(); err == nil && strings.TrimSpace(serial) != "" {
		id := "serial:" + strings.TrimSpace(serial)
		if writeErr := writePersistentFile(path, id+"\n", 0o600); writeErr == nil {
			return id, nil
		}
		return id, nil
	}

	// Generate 16 random bytes and hex-encode them as a stable identifier.
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate fallback id: %w", err)
	}
	id := hex.EncodeToString(b)

	// Best-effort persist. If the directory or file isn't writable (e.g.
	// non-root), just use the in-memory value for this session.
	_ = writePersistentFile(path, id+"\n", 0o600)
	return id, nil
}
