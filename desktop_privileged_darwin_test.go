//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateOwnedPrivateFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "config.conf")
	if err := os.WriteFile(privatePath, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		prepare func(t *testing.T) string
		wantErr bool
	}{
		{name: "private regular file", prepare: func(*testing.T) string { return privatePath }},
		{name: "relative path", prepare: func(*testing.T) string { return "config.conf" }, wantErr: true},
		{name: "loose permissions", prepare: func(t *testing.T) string {
			path := filepath.Join(dir, "loose.conf")
			if err := os.WriteFile(path, []byte("private"), 0o644); err != nil {
				t.Fatal(err)
			}
			return path
		}, wantErr: true},
		{name: "symbolic link", prepare: func(t *testing.T) string {
			path := filepath.Join(dir, "config-link")
			if err := os.Symlink(privatePath, path); err != nil {
				t.Fatal(err)
			}
			return path
		}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := validateOwnedPrivateFile(tt.prepare(t), 128)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateOwnedPrivateFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateHelperPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".desktop-ipc-test")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	uid, gid, err := validateOwnedPrivateFile(path, 128)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateHelperPath(path, uid, gid); err != nil {
		t.Fatalf("validateHelperPath() error = %v", err)
	}

	unexpected := filepath.Join(dir, "other")
	if err := os.WriteFile(unexpected, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateHelperPath(unexpected, uid, gid); err == nil {
		t.Fatal("validateHelperPath() accepted an unexpected filename")
	}
}
