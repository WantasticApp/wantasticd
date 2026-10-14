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

func TestPersistentFilePathUsesSiblingWhenStateDirIsFile(t *testing.T) {
	root := t.TempDir()
	stateFile := filepath.Join(root, "wantastic")
	if err := os.WriteFile(stateFile, []byte("config"), 0o600); err != nil {
		t.Fatalf("WriteFile(stateFile): %v", err)
	}
	t.Setenv("WANTASTIC_STATE_DIR", stateFile)

	got := PersistentFilePath("device-claim-key.json")
	want := filepath.Join(root, "wantastic-device-claim-key.json")
	if got != want {
		t.Fatalf("PersistentFilePath()=%q want %q", got, want)
	}
}

func TestDefaultConfigPathHonorsEnvironment(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "custom.conf")
	t.Setenv("WANTASTIC_CONFIG", configPath)

	if got := DefaultConfigPath(); got != configPath {
		t.Fatalf("DefaultConfigPath()=%q want %q", got, configPath)
	}
	candidates := ConfigPathCandidates()
	if len(candidates) == 0 || candidates[0] != configPath {
		t.Fatalf("ConfigPathCandidates()[0]=%q want %q", candidates, configPath)
	}
}

func TestEnsureParentDirRejectsFileParent(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "wantastic")
	if err := os.WriteFile(parent, []byte("config"), 0o600); err != nil {
		t.Fatalf("WriteFile(parent): %v", err)
	}

	err := EnsureParentDir(filepath.Join(parent, "config.conf"), 0o700)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("EnsureParentDir()=%v want not-directory error", err)
	}
}
