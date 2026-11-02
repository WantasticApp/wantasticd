//go:build windows

package runner

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

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

// EnsureTrayAgent runs when the service starts: it keeps the tray's logon
// entry in place and starts the tray in every signed-in user's session, so
// the tray is always on while the daemon runs. A copy already running in a
// session exits on its own (TrayAlreadyRunning). The admin opt-out
// (install.ps1 -NoTray, service install --no-tray) is respected.
func EnsureTrayAgent() {
	ensureTrayOnce.Do(ensureTrayAgent)
}

var ensureTrayOnce sync.Once

func ensureTrayAgent() {
	if isService, err := svc.IsWindowsService(); err != nil || !isService {
		return
	}
	if _, err := os.Stat(noTrayMarker()); err == nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	want := `"` + exe + `" tray`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, trayRunKey, registry.QUERY_VALUE)
	current := ""
	if err == nil {
		current, _, _ = k.GetStringValue(trayRunValue)
		k.Close()
	}
	if !strings.EqualFold(current, want) {
		if err := setTrayAutostart(exe); err != nil {
			log.Printf("tray agent: %v", err)
		} else {
			log.Printf("Registered the tray app to start at logon")
		}
	}
	startTrayInUserSessions(exe)
}

// startTrayInUserSessions starts `exe tray` as the user of each active
// session; the service itself runs in session 0, which has no desktop.
func startTrayInUserSessions(exe string) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		log.Printf("tray agent: list sessions: %v", err)
		return
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	for _, session := range unsafe.Slice(sessions, count) {
		if session.State != windows.WTSActive || session.SessionID == 0 {
			continue
		}
		if err := startTrayAs(session.SessionID, exe); err != nil {
			log.Printf("tray agent: session %d: %v", session.SessionID, err)
		}
	}
}

func startTrayAs(sessionID uint32, exe string) error {
	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		return err // no user signed in to this session
	}
	defer token.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, token, false); err != nil {
		return err
	}
	defer windows.DestroyEnvironmentBlock(env)

	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	cmdLine, err := windows.UTF16PtrFromString(`"` + exe + `" tray`)
	if err != nil {
		return err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, app, cmdLine, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, env, nil, &si, &pi); err != nil {
		return err
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	log.Printf("Started the tray app in session %d", sessionID)
	return nil
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
