//go:build darwin && !nosystray

package runner

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const trayCanUninstall = true

var errUninstallCanceled = errors.New("uninstall canceled")

// trayUninstall confirms, then runs `wantasticd uninstall` as root through
// the standard macOS administrator prompt. The uninstall unloads this
// menu-bar app last, so on success the process ends on its own.
func trayUninstall() error {
	confirm := exec.Command("osascript",
		"-e", `display dialog "Uninstall Wantastic from this Mac?" & return & return & "The VPN disconnects and the service, menu-bar app and program are removed. Your login is kept for a reinstall." buttons {"Cancel", "Uninstall"} default button "Cancel" cancel button "Cancel" with icon caution with title "Wantastic"`)
	if confirm.Run() != nil {
		return errUninstallCanceled
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	// The path travels as an argument and is quoted by AppleScript itself.
	out, err := exec.Command("osascript",
		"-e", "on run argv",
		"-e", `do shell script (quoted form of item 1 of argv) & " uninstall" with prompt "Wantastic needs your password to uninstall." with administrator privileges`,
		"-e", "end run",
		exe).CombinedOutput()
	if err != nil {
		// AppleScript reports a dismissed password prompt as "User canceled. (-128)".
		if strings.Contains(string(out), "-128") {
			return errUninstallCanceled
		}
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}
