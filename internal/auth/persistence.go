package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	fwEnvPublicKey = "wantastic_public_key"
	fwEnvSerial    = "wantastic_serial_number"
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
		if dir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(dir) != "" {
			return filepath.Join(dir, "Wantastic")
		}
	case "linux":
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
	return filepath.Join(PersistentDir(), name)
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
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
	if _, err := exec.LookPath("fw_printenv"); err != nil {
		return ""
	}
	out, err := exec.Command("fw_printenv", "-n", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func writeFWEnv(name, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	if _, err := exec.LookPath("fw_setenv"); err != nil {
		return
	}
	_ = exec.Command("fw_setenv", name, value).Run()
}
