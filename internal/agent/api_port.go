package agent

import (
	"os"
	"path/filepath"
)

// GetIPCPort dynamically detects the correct bound port for the IPC API server.
// It checks the WTC_IPC_PORT env first, then reads the temporary cache file.
func GetIPCPort() string {
	if p := os.Getenv("WTC_IPC_PORT"); p != "" {
		return p
	}
	portFile := filepath.Join(os.TempDir(), "wantasticd_ipc_port")
	if b, err := os.ReadFile(portFile); err == nil {
		return string(b)
	}
	// Fallback to initial port if nothing is found
	return "9034"
}
