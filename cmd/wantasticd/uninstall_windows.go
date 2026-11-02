//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const machineEnvKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

// runUninstall removes what install.ps1 installs: the service, firewall
// rules, tray logon entry, running tray apps, the PATH entry and the program
// folder; --purge also the login. --from-tray reports the result in a dialog
// because the tray starts it without a console.
func runUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "Also remove the login, claim key, settings and logs")
	fromTray := fs.Bool("from-tray", false, "Report the result in a dialog (used by the tray app)")
	fs.Parse(args)

	err := uninstallWindows(*purge)
	if *fromTray {
		text, flags := "Wantastic was uninstalled. Your login is kept for a reinstall.", uint32(windows.MB_ICONINFORMATION)
		if err != nil {
			text, flags = "Wantastic could not be fully uninstalled:\n\n"+err.Error(), windows.MB_ICONERROR
		}
		messageBox(text, flags)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "wantasticd uninstall: %v\n", err)
		return 1
	}
	return 0
}

func uninstallWindows(purge bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	fmt.Println("Uninstalling wantasticd...")
	if err := serviceUninstall(); err != nil {
		return err
	}
	stopOtherInstances(exe)
	if err := removeFromMachinePath(windowsInstallDir()); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: system PATH not updated: %v\n", err)
	}

	// A running image cannot be deleted, but it can be moved; Windows deletes
	// the moved copy at the next restart.
	parked := filepath.Join(os.TempDir(), fmt.Sprintf("wantasticd-removed-%d.exe", time.Now().UnixNano()))
	if err := os.Rename(exe, parked); err == nil {
		deleteAtReboot(parked)
	} else {
		deleteAtReboot(exe)
	}
	// Only the installer's own folder is removed wholesale, never a folder a
	// user ran the program from.
	if sameDir(filepath.Dir(exe), windowsInstallDir()) {
		if err := removeAllRetry(windowsInstallDir()); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		} else {
			fmt.Printf("Removed %s.\n", windowsInstallDir())
		}
	}

	configDir := filepath.Join(programData(), "Wantastic")
	if purge {
		if err := removeAllRetry(configDir); err != nil {
			return err
		}
		fmt.Println("Removed the login, claim key and settings.")
	} else {
		fmt.Printf("Kept the login in %s (add --purge to remove it).\n", configDir)
	}
	fmt.Println("wantasticd is uninstalled.")
	return nil
}

func windowsInstallDir() string {
	dir := os.Getenv("ProgramFiles")
	if dir == "" {
		dir = `C:\Program Files`
	}
	return filepath.Join(dir, "Wantastic")
}

func programData() string {
	if dir := os.Getenv("ProgramData"); dir != "" {
		return dir
	}
	return `C:\ProgramData`
}

func sameDir(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// stopOtherInstances ends every other process running this program: the
// tray apps of all signed-in users.
func stopOtherInstances(exe string) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)
	self := uint32(os.Getpid())
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		if entry.ProcessID == self || !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), filepath.Base(exe)) {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, entry.ProcessID)
		if err != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_PATH)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil && strings.EqualFold(windows.UTF16ToString(buf[:n]), exe) {
			if windows.TerminateProcess(h, 0) == nil {
				windows.WaitForSingleObject(h, 5000)
			}
		}
		windows.CloseHandle(h)
	}
}

func removeFromMachinePath(dir string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, machineEnvKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	value, kind, err := k.GetStringValue("Path")
	if err != nil {
		return err
	}
	var kept []string
	for _, entry := range strings.Split(value, ";") {
		if strings.TrimSpace(entry) != "" && !strings.EqualFold(strings.TrimRight(strings.TrimSpace(entry), `\`), dir) {
			kept = append(kept, entry)
		}
	}
	joined := strings.Join(kept, ";")
	if joined == value {
		return nil
	}
	if kind == registry.EXPAND_SZ {
		err = k.SetExpandStringValue("Path", joined)
	} else {
		err = k.SetStringValue("Path", joined)
	}
	if err == nil {
		fmt.Printf("Removed %s from the system PATH.\n", dir)
	}
	return err
}

func deleteAtReboot(path string) {
	p, err := windows.UTF16PtrFromString(path)
	if err == nil {
		_ = windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
}

// removeAllRetry waits out a process that was just stopped and still holds
// a file open.
func removeAllRetry(dir string) error {
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		if err = os.RemoveAll(dir); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("could not remove %s: %w", dir, err)
}

func messageBox(text string, flags uint32) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString("Wantastic")
	_, _ = windows.MessageBox(0, t, c, flags|windows.MB_SETFOREGROUND)
}
