package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const darwinLaunchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.wantastic.wantasticd</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>connect</string>
    <string>-config</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>/var/log/wantasticd.err.log</string>
  <key>StandardOutPath</key>
  <string>/var/log/wantasticd.out.log</string>
</dict>
</plist>
`

const sysPlist = "/Library/LaunchDaemons/com.wantastic.wantasticd.plist"
const service = "com.wantastic.wantasticd"

// SetupService installs and starts the service via launchd on macOS
func SetupService(configPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlink for executable: %w", err)
	}

	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for config: %w", err)
	}

	// Always attempt to unload / stop existing service first (ignoring errors if not running)
	_ = exec.Command("launchctl", "bootout", "system", sysPlist).Run()
	_ = exec.Command("launchctl", "unload", sysPlist).Run()

	plistContent := fmt.Sprintf(darwinLaunchdPlist, exePath, absConfigPath)

	fmt.Println("Installing macOS daemon to", sysPlist)
	if err := os.WriteFile(sysPlist, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("failed to write plist file (do you have root privileges?): %w", err)
	}

	fmt.Println("Loading and starting macOS daemon...")
	out, err := exec.Command("launchctl", "load", sysPlist).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load service via launchctl: %v, %s", err, out)
	}

	out, err = exec.Command("launchctl", "start", service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start service via launchctl: %v, %s", err, out)
	}

	return nil
}
