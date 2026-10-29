//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// ensureUpdatePrivileges makes sure this process can replace execPath and
// restart the service. Installs live in root-owned directories, so a plain
// user's `wantasticd update` re-runs itself under sudo when it can prompt.
func ensureUpdatePrivileges(execPath string) error {
	if os.Geteuid() == 0 || unix.Access(filepath.Dir(execPath), unix.W_OK) == nil {
		return nil
	}
	hint := fmt.Errorf("%s is not writable by this user; run: sudo %s update", filepath.Dir(execPath), execPath)
	sudo, err := exec.LookPath("sudo")
	if err != nil || !term.IsTerminal(int(os.Stdin.Fd())) {
		return hint
	}
	fmt.Println("Updating needs administrator rights; re-running with sudo...")
	args := append([]string{"sudo", execPath}, os.Args[1:]...)
	if err := syscall.Exec(sudo, args, os.Environ()); err != nil {
		return fmt.Errorf("sudo: %v; %w", err, hint)
	}
	return nil
}
