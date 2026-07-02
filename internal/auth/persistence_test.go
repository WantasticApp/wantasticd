package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistentSerialNumberCreatesAndReusesFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WANTASTIC_STATE_DIR", dir)
	t.Setenv("PATH", "")

	first, err := PersistentSerialNumber()
	if err != nil {
		t.Fatalf("PersistentSerialNumber() error: %v", err)
	}
	if !strings.HasPrefix(first, "WANTASTIC-") {
		t.Fatalf("serial %q missing WANTASTIC- prefix", first)
	}

	second, err := PersistentSerialNumber()
	if err != nil {
		t.Fatalf("PersistentSerialNumber() second error: %v", err)
	}
	if second != first {
		t.Fatalf("serial changed: got %q want %q", second, first)
	}

	data, err := os.ReadFile(filepath.Join(dir, "serial-number"))
	if err != nil {
		t.Fatalf("ReadFile(serial-number): %v", err)
	}
	if strings.TrimSpace(string(data)) != first {
		t.Fatalf("persisted serial=%q want %q", strings.TrimSpace(string(data)), first)
	}
}

func TestPersistPublicKeyCreatesReadableFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WANTASTIC_STATE_DIR", dir)
	t.Setenv("PATH", "")

	const publicKey = "abc123="
	if err := PersistPublicKey(publicKey); err != nil {
		t.Fatalf("PersistPublicKey() error: %v", err)
	}
	if got := ReadPersistedPublicKey(); got != publicKey {
		t.Fatalf("ReadPersistedPublicKey()=%q want %q", got, publicKey)
	}
}
