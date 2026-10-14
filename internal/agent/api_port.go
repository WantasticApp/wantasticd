package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// GetIPCPort dynamically detects the correct bound port for the IPC API server.
// It checks the WTC_IPC_PORT env first, then reads the temporary cache file.
func GetIPCPort() string {
	if p, ok := validIPCPort(os.Getenv("WTC_IPC_PORT")); ok {
		return p
	}
	if discovery, err := readIPCDiscovery(); err == nil {
		if p, ok := validIPCPort(strconv.Itoa(discovery.Port)); ok {
			return p
		}
	}
	// Fallback to initial port if nothing is found
	return "9034"
}

func validIPCPort(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1024 || port > 65535 {
		return "", false
	}
	return strconv.Itoa(port), true
}

func ipcPortFile() string {
	if path := strings.TrimSpace(os.Getenv("WTC_IPC_PORT_FILE")); path != "" {
		return path
	}
	if dir, err := os.UserCacheDir(); err == nil && strings.TrimSpace(dir) != "" {
		return filepath.Join(dir, "Wantastic", "ipc-port")
	}
	return filepath.Join(os.TempDir(), "wantasticd_ipc_port")
}

func readConfiguredIPCToken() (string, error) {
	if token := strings.TrimSpace(os.Getenv("WTC_IPC_TOKEN")); token != "" {
		if len(token) < 32 {
			return "", fmt.Errorf("WTC_IPC_TOKEN must contain at least 32 characters")
		}
		return token, nil
	}
	path := strings.TrimSpace(os.Getenv("WTC_IPC_TOKEN_FILE"))
	if path == "" {
		return "", nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect IPC token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("IPC token path must be a regular file")
	}
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("WTC_IPC_TOKEN_FILE is unsupported on Windows; use a process credential")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("IPC token file permissions must be 0600 or stricter")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open IPC token file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", fmt.Errorf("read IPC token file: %w", err)
	}
	if len(b) > 4096 {
		return "", fmt.Errorf("IPC token file is too large")
	}
	token := strings.TrimSpace(string(b))
	if len(token) < 32 {
		return "", fmt.Errorf("IPC token must contain at least 32 characters")
	}
	return token, nil
}

func readIPCToken() (string, error) {
	token, err := readConfiguredIPCToken()
	if err != nil || token != "" {
		return token, err
	}
	discovery, err := readIPCDiscovery()
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if len(discovery.Token) < 32 {
		return "", fmt.Errorf("IPC discovery credential is invalid")
	}
	return discovery.Token, nil
}

type ipcDiscovery struct {
	Port  int    `json:"port"`
	Token string `json:"token"`
}

func readIPCDiscovery() (ipcDiscovery, error) {
	path := ipcPortFile()
	info, err := os.Lstat(path)
	if err != nil {
		return ipcDiscovery{}, err
	}
	if !info.Mode().IsRegular() {
		return ipcDiscovery{}, fmt.Errorf("IPC discovery path must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return ipcDiscovery{}, fmt.Errorf("IPC discovery permissions must be 0600 or stricter")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ipcDiscovery{}, err
	}
	b, err = unprotectIPCDiscovery(b)
	if err != nil {
		return ipcDiscovery{}, fmt.Errorf("unprotect IPC discovery: %w", err)
	}
	var discovery ipcDiscovery
	if err := json.Unmarshal(b, &discovery); err != nil {
		return ipcDiscovery{}, fmt.Errorf("decode IPC discovery: %w", err)
	}
	return discovery, nil
}

// NewIPCRequest creates a loopback-only request and applies the optional
// bearer credential used when a privileged agent serves an unprivileged UI.
func NewIPCRequest(ctx context.Context, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:"+GetIPCPort()+path, nil)
	if err != nil {
		return nil, err
	}
	token, err := readIPCToken()
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}
