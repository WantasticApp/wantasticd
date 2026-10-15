//go:build !windows

package auth

import (
	"fmt"
	"os"
)

func writePrivateFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func checkPrivateFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if got := info.Mode().Perm(); got != 0o600 {
		return fmt.Errorf("private file permissions are %o, want 600", got)
	}
	return nil
}
