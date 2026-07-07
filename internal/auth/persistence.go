package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	fwEnvPublicKey = "wantastic_public_key"
	fwEnvSerial    = "wantastic_serial_number"
	fwEnvTimeout   = 2 * time.Second
)

// PersistentDir returns the best cross-platform directory for device identity
// material. Embedded Linux/OpenWrt deployments prefer /usrdata so rootfs can
// remain disposable.
func PersistentDir() string {
	if dir := strings.TrimSpace(os.Getenv("WANTASTIC_STATE_DIR")); dir != "" {
		return dir
	}
	switch runtime.GOOS {
	case "windows":
		if dir := strings.TrimSpace(os.Getenv("ProgramData")); dir != "" {
			return filepath.Join(dir, "Wantastic")
		}
	case "darwin":
		if os.Geteuid() == 0 {
			return filepath.Join(string(os.PathSeparator), "Library", "Application Support", "Wantastic")
		}
		if dir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(dir) != "" {
			return filepath.Join(dir, "Wantastic")
		}
	case "linux":
		if os.Geteuid() != 0 {
			if dir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(dir) != "" {
				return filepath.Join(dir, "wantastic")
			}
		}
		if info, err := os.Stat("/usrdata"); err == nil && info.IsDir() {
			return "/usrdata/wantastic/etc"
		}
		return "/etc/wantastic"
	}
	if dir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(dir) != "" {
		return filepath.Join(dir, "wantastic")
	}
	return "."
}

func PersistentFilePath(name string) string {
	return PersistentPath(name)
}

// PersistentPath returns a file path under PersistentDir. If the configured
// persistent location is a flat file such as legacy /etc/wantastic, the file is
// placed beside it as /etc/wantastic-<name> instead of trying to create a child.
func PersistentPath(name string) string {
	dir := PersistentDir()
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		return filepath.Join(filepath.Dir(dir), filepath.Base(dir)+"-"+name)
	}
	return filepath.Join(dir, name)
}

// DefaultConfigPath is the preferred config file for this platform.
func DefaultConfigPath() string {
	if dir := strings.TrimSpace(os.Getenv("WANTASTIC_CONFIG_DIR")); dir != "" {
		return filepath.Join(dir, "config.conf")
	}
	if path := strings.TrimSpace(os.Getenv("WANTASTIC_CONFIG")); path != "" {
		return path
	}
	if runtime.GOOS == "linux" {
		if info, err := os.Stat("/etc/wantastic"); err == nil && !info.IsDir() {
			return "/etc/wantastic"
		}
	}
	return PersistentPath("config.conf")
}

// ConfigPathCandidates returns config paths in read preference order.
func ConfigPathCandidates() []string {
	seen := make(map[string]bool)
	var candidates []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		candidates = append(candidates, path)
	}
	add(os.Getenv("WANTASTIC_CONFIG"))
	add(DefaultConfigPath())
	add(PersistentPath("config.conf"))
	if runtime.GOOS == "linux" {
		add("/usrdata/wantastic/etc/config.conf")
		add("/etc/wantastic/config.conf")
		add("/etc/wantastic")
	}
	add("wantastic.conf")
	return candidates
}

// EnsureParentDir creates the parent directory for path, with a clear error if
// the parent already exists as a file.
func EnsureParentDir(path string, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("parent %s is not a directory", dir)
		}
		return nil
	}
	return os.MkdirAll(dir, perm)
}

// PersistentSerialNumber returns a durable WUSP serial number. It reads
// OpenWrt/U-Boot env first, then the filesystem, then creates a new value and
// mirrors it to both stores where possible.
func PersistentSerialNumber() (string, error) {
	path := PersistentFilePath("serial-number")
	if serial := readFWEnv(fwEnvSerial); serial != "" {
		_ = writePersistentFile(path, serial+"\n", 0o600)
		return serial, nil
	}
	if serial := strings.TrimSpace(readTextFile(path)); serial != "" {
		writeFWEnv(fwEnvSerial, serial)
		return serial, nil
	}

	serial, err := newSerialNumber()
	if err != nil {
		return "", err
	}
	if err := writePersistentFile(path, serial+"\n", 0o600); err != nil {
		return "", err
	}
	writeFWEnv(fwEnvSerial, serial)
	return serial, nil
}

func PersistPublicKey(publicKey string) error {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return fmt.Errorf("public key is empty")
	}
	if err := writePersistentFile(PersistentFilePath("device-public-key"), publicKey+"\n", 0o600); err != nil {
		return err
	}
	writeFWEnv(fwEnvPublicKey, publicKey)
	return nil
}

func ReadPersistedPublicKey() string {
	if publicKey := readFWEnv(fwEnvPublicKey); publicKey != "" {
		_ = writePersistentFile(PersistentFilePath("device-public-key"), publicKey+"\n", 0o600)
		return publicKey
	}
	return strings.TrimSpace(readTextFile(PersistentFilePath("device-public-key")))
}

func newSerialNumber() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate serial number: %w", err)
	}
	return "WANTASTIC-" + strings.ToUpper(hex.EncodeToString(b)), nil
}

func writePersistentFile(path, value string, perm os.FileMode) error {
	if err := EnsureParentDir(path, 0o700); err != nil {
		return fmt.Errorf("create persistent directory: %w", err)
	}
	return os.WriteFile(path, []byte(value), perm)
}

func readTextFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func readFWEnv(name string) string {
	if !fwEnvEnabled() {
		return ""
	}
	tool, err := exec.LookPath("fw_printenv")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), fwEnvTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, tool, "-n", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func writeFWEnv(name, value string) {
	if !fwEnvEnabled() || strings.TrimSpace(value) == "" {
		return
	}
	tool, err := exec.LookPath("fw_setenv")
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fwEnvTimeout)
	defer cancel()
	_ = exec.CommandContext(ctx, tool, name, value).Run()
}

func fwEnvEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WANTASTIC_FWENV"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}
