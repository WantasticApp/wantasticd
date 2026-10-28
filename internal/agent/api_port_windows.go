//go:build windows

package agent

import "os"

// writePortFile writes the port file; on Windows it lives in the service
// account's own temp directory.
func writePortFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

func portFileTrusted(fi os.FileInfo) bool { return fi.Mode().IsRegular() }
