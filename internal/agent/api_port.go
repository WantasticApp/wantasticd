package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ipcPortFile is where the daemon records its IPC port for local clients. On
// Unix it is a fixed path: a root LaunchDaemon's os.TempDir() is /tmp while a
// user shell's on macOS is a per-user /var/folders directory, so the tray and
// CLI would never find the port the daemon wrote.
func ipcPortFile() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.TempDir(), "wantasticd_ipc_port")
	}
	return "/tmp/wantasticd_ipc_port"
}

// GetIPCPort dynamically detects the correct bound port for the IPC API server.
// It checks the WTC_IPC_PORT env first, then reads the port file.
func GetIPCPort() string {
	if p := os.Getenv("WTC_IPC_PORT"); p != "" {
		return p
	}
	path := ipcPortFile()
	if fi, err := os.Lstat(path); err == nil && portFileTrusted(fi) {
		if b, err := os.ReadFile(path); err == nil {
			if p := strings.TrimSpace(string(b)); p != "" {
				return p
			}
		}
	}
	// Fallback to initial port if nothing is found
	return "9034"
}
