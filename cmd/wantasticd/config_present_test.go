package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The installer leaves an empty config when login is skipped; the daemon must
// then wait for sign-in instead of failing on it.
func TestConfigPresentTreatsEmptyAsMissing(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"empty": "", "blank": " \n\t\n"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := configPresent(p); !os.IsNotExist(err) {
			t.Errorf("%s config: got %v, want not-exist", name, err)
		}
	}
	if err := configPresent(filepath.Join(dir, "absent")); !os.IsNotExist(err) {
		t.Errorf("absent config: got %v, want not-exist", err)
	}
	p := filepath.Join(dir, "real")
	if err := os.WriteFile(p, []byte("[Interface]\nPrivateKey = x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configPresent(p); err != nil {
		t.Errorf("real config: %v", err)
	}
}
