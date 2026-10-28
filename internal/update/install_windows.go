//go:build windows

package update

import (
	"archive/zip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName     = "wantasticd"
	serviceWait     = 30 * time.Second
	stabilityWindow = 10 * time.Second
)

// install swaps the binary in place and hands the service restart to a
// detached copy of the new binary ("update-finish"): stopping the service
// ends this process, so it cannot supervise its own restart.
//
// Windows cannot overwrite a running .exe but can rename it, so the running
// image becomes <exe>.previous (kept for rollback) and the new one takes its
// name.
func (m *Manager) install(_, attempt context.Context, targetVersion, binaryPath, archiveDir, archivePath string) error {
	defer os.RemoveAll(archiveDir)

	newPath := binaryPath + ".new"
	previous := binaryPath + ".previous"
	os.Remove(newPath)
	os.Remove(binaryPath + ".failed")

	if err := extractZipBinary(archivePath, filepath.Base(binaryPath), newPath); err != nil {
		return err
	}
	if err := verifyVersion(attempt, newPath, targetVersion); err != nil {
		os.Remove(newPath)
		return err
	}

	if err := os.Remove(previous); err != nil && !os.IsNotExist(err) {
		os.Remove(newPath)
		return fmt.Errorf("remove old backup %s: %w", previous, err)
	}
	if err := os.Rename(binaryPath, previous); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("back up running binary: %w", err)
	}
	if err := os.Rename(newPath, binaryPath); err != nil {
		os.Rename(previous, binaryPath)
		return fmt.Errorf("install new binary: %w", err)
	}

	cmd := exec.Command(binaryPath, "update-finish", "--version", targetVersion, "--binary", binaryPath)
	if err := startDetached(cmd); err != nil {
		os.Rename(binaryPath, binaryPath+".failed")
		os.Rename(previous, binaryPath)
		return fmt.Errorf("start restart helper: %w", err)
	}
	log.Printf("Installed %s; restart helper (pid %d) is restarting the service", targetVersion, cmd.Process.Pid)
	if m.Output != nil {
		fmt.Fprintf(m.Output, "Installed %s; the service restarts in the background (log: %s)\n", targetVersion, finishLogPath())
	}
	return nil
}

// startDetached starts cmd outside this process's console and, when the
// service's job object allows it, outside the job, so stopping the service
// does not take it down.
func startDetached(cmd *exec.Cmd) error {
	base := uint32(windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: base | windows.CREATE_BREAKAWAY_FROM_JOB}
	if err := cmd.Start(); err == nil {
		cmd.Process.Release()
		return nil
	}
	// Breakaway is refused when the job does not permit it.
	cmd = exec.Command(cmd.Path, cmd.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: base}
	if err := cmd.Start(); err != nil {
		return err
	}
	cmd.Process.Release()
	return nil
}

func extractZipBinary(archivePath, name, dest string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open release archive: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if !strings.EqualFold(filepath.Base(f.Name), name) || f.FileInfo().IsDir() {
			continue
		}
		src, err := f.Open()
		if err != nil {
			return fmt.Errorf("open %s in archive: %w", f.Name, err)
		}
		defer src.Close()
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
		if err != nil {
			return fmt.Errorf("create %s: %w", dest, err)
		}
		_, copyErr := io.Copy(out, io.LimitReader(src, maxReleaseArchiveBytes))
		closeErr := out.Close()
		if copyErr != nil || closeErr != nil {
			os.Remove(dest)
			return fmt.Errorf("extract %s: %v", name, errors.Join(copyErr, closeErr))
		}
		return nil
	}
	return fmt.Errorf("%s not found in release archive", name)
}

// verifyVersion refuses a corrupt, wrong-architecture or mislabelled build
// before anything is swapped.
func verifyVersion(ctx context.Context, path, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("new binary does not run: %w", err)
	}
	if !strings.Contains(string(out), want) {
		return fmt.Errorf("new binary reports %q, want %s", strings.TrimSpace(string(out)), want)
	}
	return nil
}

func finishLogPath() string {
	return filepath.Join(os.TempDir(), "wantasticd-update.log")
}

// Finish restarts the service on the freshly installed binary and rolls back
// to <binary>.previous if it does not stay running. It runs detached from
// the service it restarts. Returns the process exit code.
func Finish(args []string) int {
	fs := flag.NewFlagSet("update-finish", flag.ContinueOnError)
	version := fs.String("version", "", "version that was installed")
	binary := fs.String("binary", "", "installed binary path")
	if err := fs.Parse(args); err != nil || *binary == "" {
		return 2
	}
	if f, err := os.OpenFile(finishLogPath(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
		log.SetOutput(f)
		defer f.Close()
	}

	m, err := mgr.Connect()
	if err != nil {
		log.Printf("update-finish: service manager: %v", err)
		return 1
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		// Not installed as a service (manual run): nothing to restart.
		log.Printf("update-finish: no %s service; binary updated to %s", serviceName, *version)
		return 0
	}
	defer s.Close()

	err = restartService(s)
	if err == nil {
		log.Printf("update-finish: %s running %s", serviceName, *version)
		return 0
	}
	log.Printf("update-finish: %s unhealthy after update to %s: %v; restoring previous binary", serviceName, *version, err)

	stopService(s)
	previous := *binary + ".previous"
	if _, err := os.Stat(previous); err != nil {
		log.Printf("update-finish: no backup at %s: %v", previous, err)
		return 1
	}
	os.Remove(*binary + ".failed")
	if err := os.Rename(*binary, *binary+".failed"); err != nil {
		log.Printf("update-finish: move failed binary aside: %v", err)
		return 1
	}
	if err := os.Rename(previous, *binary); err != nil {
		log.Printf("update-finish: restore backup: %v", err)
		return 1
	}
	if err := restartService(s); err != nil {
		log.Printf("update-finish: previous binary did not start either: %v", err)
	}
	return 1
}

func restartService(s *mgr.Service) error {
	if err := stopService(s); err != nil {
		return err
	}
	// Recovery actions may have restarted it already after the old process
	// exited; that instance runs the new binary too.
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("start: %w", err)
	}
	if err := waitState(s, svc.Running, serviceWait); err != nil {
		return err
	}
	// A binary that crashes after start-up must not count as healthy.
	time.Sleep(stabilityWindow)
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	if st.State != svc.Running {
		return fmt.Errorf("service stopped within %s of starting", stabilityWindow)
	}
	return nil
}

func stopService(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			// The old process may exit on its own between Query and Control.
			if st2, qerr := s.Query(); qerr == nil && st2.State == svc.Stopped {
				return nil
			}
			return fmt.Errorf("stop: %w", err)
		}
	}
	return waitState(s, svc.Stopped, serviceWait)
}

func waitState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("query: %w", err)
		}
		if st.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service state %d, want %d after %s", st.State, want, timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
