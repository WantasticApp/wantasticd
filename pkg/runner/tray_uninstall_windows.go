//go:build windows && !nosystray

package runner

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const trayCanUninstall = true

// idOK is MessageBox's result for the OK button.
const idOK = 1

var errUninstallCanceled = errors.New("uninstall canceled")

// trayUninstall confirms, then starts `wantasticd uninstall` elevated through
// UAC. The uninstall ends every tray app, this one included, and reports
// the result in a dialog.
func trayUninstall() error {
	text, _ := windows.UTF16PtrFromString("Uninstall Wantastic from this PC?\n\nThe VPN disconnects and the service, tray app and program are removed. Your login is kept for a reinstall.")
	title, _ := windows.UTF16PtrFromString("Wantastic")
	answer, err := windows.MessageBox(0, text, title, windows.MB_OKCANCEL|windows.MB_ICONWARNING|windows.MB_DEFBUTTON2|windows.MB_SETFOREGROUND)
	if err != nil || answer != idOK {
		return errUninstallCanceled
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	args, _ := windows.UTF16PtrFromString("uninstall --from-tray")
	if err := windows.ShellExecute(0, verb, file, args, nil, windows.SW_HIDE); err != nil {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return errUninstallCanceled
		}
		return err
	}
	return nil
}
