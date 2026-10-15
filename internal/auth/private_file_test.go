package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePrivateFileReplacesLegacyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-state.json")
	if err := os.WriteFile(path, []byte("legacy"), 0o666); err != nil {
		t.Fatalf("create legacy file: %v", err)
	}

	const want = "protected-state"
	if err := WritePrivateFile(path, []byte(want)); err != nil {
		t.Fatalf("WritePrivateFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read private file: %v", err)
	}
	if string(got) != want {
		t.Fatalf("private file content = %q, want %q", got, want)
	}
	if err := CheckPrivateFilePermissions(path); err != nil {
		t.Fatalf("private file permissions: %v", err)
	}
}
