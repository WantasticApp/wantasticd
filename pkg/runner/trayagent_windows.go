//go:build windows

package runner

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

const (
	trayRunKey   = `Software\Microsoft\Windows\CurrentVersion\Run`
	trayRunValue = "Wantastic"
	trayMutex    = `Local\WantasticTray`
)

// noTrayMarker is left by an admin opt-out (install.ps1 -NoTray,
// service install --no-tray) so the service does not re-add the tray.
func noTrayMarker() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, "Wantastic", "no-tray")
}

// EnsureTrayAgent registers the tray to start at every logon when the daemon
// runs as the Windows service and the entry is missing: installs from before
// the tray existed, or made with the service command alone, get it on their
// next start. The service runs in session 0, so the tray appears at the next
// logon.
func EnsureTrayAgent() {
	if isService, err := svc.IsWindowsService(); err != nil || !isService {
		return
	}
	if _, err := os.Stat(noTrayMarker()); err == nil {
		return
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, trayRunKey, registry.QUERY_VALUE)
	if err == nil {
		_, _, err = k.GetStringValue(trayRunValue)
		k.Close()
		if err == nil {
			return
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if err := setTrayAutostart(exe); err != nil {
		log.Printf("tray agent: %v", err)
		return
	}
	log.Printf("Registered the tray app to start at logon")
}

// SetTrayAutostart turns the tray's logon entry on (and starts the tray for
// the current user) or off, recording an opt-out the service respects.
func SetTrayAutostart(exe string, on bool) error {
	if !on {
		if err := os.MkdirAll(filepath.Dir(noTrayMarker()), 0o755); err == nil {
			_ = os.WriteFile(noTrayMarker(), nil, 0o644)
		}
		return RemoveTrayAutostart()
	}
	if err := os.Remove(noTrayMarker()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := setTrayAutostart(exe); err != nil {
		return err
	}
	// A second copy for an already-running tray exits on its own (TrayAlreadyRunning).
	cmd := exec.Command(exe, "tray")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.DETACHED_PROCESS}
	if err := cmd.Start(); err != nil {
		return nil // registered; it starts at the next logon
	}
	return cmd.Process.Release()
}

// RemoveTrayAutostart deletes the tray's logon entry.
func RemoveTrayAutostart() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, trayRunKey, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(trayRunValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func setTrayAutostart(exe string) error {
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, trayRunKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(trayRunValue, `"`+exe+`" tray`)
}

// trayInstance is held for the life of the tray so a second copy in the same
// logon session (logon entry plus an installer start) exits instead of
// showing a second icon.
var trayInstance windows.Handle

// TrayAlreadyRunning reports whether another tray runs in this logon session.
func TrayAlreadyRunning() bool {
	name, err := windows.UTF16PtrFromString(trayMutex)
	if err != nil {
		return false
	}
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return true
	}
	if err == nil {
		trayInstance = h
	}
	return false
}
