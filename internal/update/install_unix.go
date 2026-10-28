//go:build !windows

package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// install runs the embedded self-update.sh on the downloaded archive in its
// own session. The script restarts the service, which stops this process; in
// its own session (and with output to a file, not a pipe we own) it survives
// that and finishes the health check and rollback.
//
// parent is the caller's context: when it ends (the service is stopping,
// usually because the script restarted it) the script is left running.
// attempt bounds the whole update; on expiry the script is killed.
func (m *Manager) install(parent, attempt context.Context, targetVersion, binaryPath, archiveDir, archivePath string) error {
	scriptContent, err := updateScript.ReadFile("self-update.sh")
	if err != nil {
		os.RemoveAll(archiveDir)
		return fmt.Errorf("read embedded script: %w", err)
	}
	scriptPath := filepath.Join(archiveDir, "self-update.sh")
	if err := os.WriteFile(scriptPath, scriptContent, 0o700); err != nil {
		os.RemoveAll(archiveDir)
		return fmt.Errorf("write update script: %w", err)
	}
	logFile, err := os.CreateTemp("", "wantasticd-update-*.log")
	if err != nil {
		os.RemoveAll(archiveDir)
		return fmt.Errorf("create update log: %w", err)
	}
	logPath := logFile.Name()

	log.Printf("Running update script for version %s (target: %s, log: %s)...", targetVersion, binaryPath, logPath)
	cmd := exec.Command("/bin/sh", scriptPath, targetVersion, binaryPath, archivePath)
	cmd.Env = append(os.Environ(), "WANTASTIC_UPDATE_WORKDIR="+archiveDir)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		os.Remove(logPath)
		os.RemoveAll(archiveDir)
		return fmt.Errorf("start update script: %w", err)
	}
	logFile.Close()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		os.RemoveAll(archiveDir)
		m.reportLog(logPath)
		if err != nil {
			return fmt.Errorf("update script failed: %w (log kept at %s)", err, logPath)
		}
		os.Remove(logPath)
		return nil
	case <-attempt.Done():
		if parent.Err() != nil {
			// This process is being stopped; the script carries on alone and
			// removes archiveDir when it exits.
			log.Printf("Update to %s continues in the background (log: %s)", targetVersion, logPath)
			return parent.Err()
		}
		// Negative pid: the whole session the script leads.
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		os.RemoveAll(archiveDir)
		m.reportLog(logPath)
		return fmt.Errorf("update attempt timed out after %s (log kept at %s)", updateAttemptTimeout, logPath)
	}
}

// reportLog copies the script output to m.Output (the interactive CLI) or,
// for the daemon, to the log.
func (m *Manager) reportLog(path string) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}
	if m.Output != nil {
		io.WriteString(m.Output, string(data))
		return
	}
	log.Printf("Update script output:\n%s", data)
}

// Finish is the Windows post-swap restart helper; other platforms restart
// from self-update.sh.
func Finish(args []string) int {
	fmt.Fprintln(os.Stderr, errors.New("update-finish is only used on Windows"))
	return 2
}
