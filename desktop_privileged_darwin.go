//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/auth"
	"wantastic-agent/internal/config"

	"golang.org/x/sys/unix"
)

const privilegedAgentFlag = "--wantastic-privileged-agent"

func runPrivilegedAgentMode() (bool, error) {
	if len(os.Args) < 2 || os.Args[1] != privilegedAgentFlag {
		return false, nil
	}
	if len(os.Args) != 6 {
		return true, errors.New("invalid privileged helper arguments")
	}
	if os.Geteuid() != 0 {
		return true, errors.New("privileged helper must run as root")
	}
	parentPID, err := strconv.Atoi(os.Args[3])
	if err != nil || parentPID < 2 {
		return true, errors.New("invalid desktop process identifier")
	}

	configData, uid, gid, err := readOwnedPrivateFile(os.Args[2], 1<<20)
	if err != nil {
		return true, fmt.Errorf("validate tunnel configuration: %w", err)
	}
	if err := validateHelperPath(os.Args[4], uid, gid); err != nil {
		return true, fmt.Errorf("validate IPC path: %w", err)
	}
	if err := validateOwnedPrivateFileForUser(os.Args[5], uid, gid, 128); err != nil {
		return true, fmt.Errorf("validate lifecycle marker: %w", err)
	}

	discoveryPath := filepath.Clean(os.Args[4])
	markerPath := filepath.Clean(os.Args[5])
	if err := os.Setenv("WTC_IPC_PORT_FILE", discoveryPath); err != nil {
		return true, err
	}
	_ = os.Unsetenv("WTC_IPC_PORT")
	_ = os.Unsetenv("WTC_IPC_TOKEN")
	_ = os.Unsetenv("WTC_IPC_TOKEN_FILE")

	cfg, err := config.Parse(configData)
	if err != nil {
		return true, fmt.Errorf("load tunnel configuration: %w", err)
	}
	cfg.Interface.TUNMode = true
	cfg.Interface.TUNName = config.DefaultTunName()

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	agt, err := agent.New(cfg)
	if err != nil {
		return true, fmt.Errorf("create tunnel agent: %w", err)
	}
	if err := agt.Start(ctx); err != nil {
		return true, fmt.Errorf("start tunnel agent: %w", err)
	}
	defer agt.Stop()
	defer removeOwnedHelperFile(discoveryPath, uid)
	if err := os.Chown(discoveryPath, int(uid), int(gid)); err != nil {
		return true, fmt.Errorf("publish IPC credential ownership: %w", err)
	}
	if err := os.Chmod(discoveryPath, 0o600); err != nil {
		return true, fmt.Errorf("protect IPC credential: %w", err)
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return true, nil
		case <-agt.ShutdownRequested():
			return true, nil
		case <-ticker.C:
			if syscall.Kill(parentPID, 0) != nil {
				return true, nil
			}
			if err := validateOwnedPrivateFileForUser(markerPath, uid, gid, 128); err != nil {
				return true, nil
			}
		}
	}
}

func (a *App) startPrivilegedAgentIfNeeded(cfg *config.Config) (bool, error) {
	if os.Geteuid() == 0 || os.Getenv("WANTASTIC_DESKTOP_EXTERNAL_AGENT") == "1" {
		return false, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return true, fmt.Errorf("locate desktop executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return true, fmt.Errorf("resolve desktop executable: %w", err)
	}
	configPath, err := filepath.Abs(auth.DefaultConfigPath())
	if err != nil {
		return true, fmt.Errorf("resolve desktop configuration: %w", err)
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return true, fmt.Errorf("resolve user cache: %w", err)
	}
	cacheDir = filepath.Join(cacheDir, "Wantastic")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return true, fmt.Errorf("create helper cache: %w", err)
	}
	if err := os.Chmod(cacheDir, 0o700); err != nil {
		return true, fmt.Errorf("protect helper cache: %w", err)
	}

	discovery, err := os.CreateTemp(cacheDir, ".desktop-ipc-*")
	if err != nil {
		return true, fmt.Errorf("create IPC discovery path: %w", err)
	}
	discoveryPath := discovery.Name()
	if closeErr := discovery.Close(); closeErr != nil {
		_ = os.Remove(discoveryPath)
		return true, closeErr
	}
	if err := os.Chmod(discoveryPath, 0o600); err != nil {
		_ = os.Remove(discoveryPath)
		return true, err
	}
	marker, err := os.CreateTemp(cacheDir, ".desktop-session-*")
	if err != nil {
		_ = os.Remove(discoveryPath)
		return true, fmt.Errorf("create helper lifecycle marker: %w", err)
	}
	markerPath := marker.Name()
	if closeErr := marker.Close(); closeErr != nil {
		_ = os.Remove(discoveryPath)
		_ = os.Remove(markerPath)
		return true, closeErr
	}
	if err := os.Chmod(markerPath, 0o600); err != nil {
		_ = os.Remove(discoveryPath)
		_ = os.Remove(markerPath)
		return true, err
	}
	if err := os.Setenv("WTC_IPC_PORT_FILE", discoveryPath); err != nil {
		_ = os.Remove(discoveryPath)
		_ = os.Remove(markerPath)
		return true, err
	}
	_ = os.Unsetenv("WTC_IPC_PORT")
	_ = os.Unsetenv("WTC_IPC_TOKEN")
	_ = os.Unsetenv("WTC_IPC_TOKEN_FILE")

	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.helperEpoch++
	epoch := a.helperEpoch
	a.agt = nil
	a.agentCancel = cancel
	a.cfg = cfg
	a.configured = true
	a.starting = true
	a.externalOwned = true
	a.helperMarker = markerPath
	a.mu.Unlock()

	args := []string{executable, privilegedAgentFlag, configPath, strconv.Itoa(os.Getpid()), discoveryPath, markerPath}
	go a.runPrivilegedAgentCommand(ctx, epoch, args, discoveryPath, markerPath)
	return true, nil
}

func (a *App) runPrivilegedAgentCommand(ctx context.Context, epoch uint64, args []string, discoveryPath, markerPath string) {
	defer os.Remove(discoveryPath)
	defer os.Remove(markerPath)
	script := `on run argv
set commandLine to quoted form of item 1 of argv
repeat with argumentValue in items 2 thru -1 of argv
set commandLine to commandLine & " " & quoted form of argumentValue
end repeat
do shell script commandLine with administrator privileges
end run`
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", append([]string{"-e", script}, args...)...)
	result := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		a.finishPrivilegedStart(epoch, err)
		return
	}
	go func() { result <- cmd.Wait() }()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	ready := false
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-result:
			if ctx.Err() == nil {
				a.finishPrivilegedStart(epoch, normalizeHelperError(err))
			}
			return
		case <-ticker.C:
			if ready {
				continue
			}
			var status agent.StatusResponse
			if err := ipcGet("/api/status", &status); err == nil {
				ready = true
				a.markPrivilegedReady(epoch)
			}
		}
	}
}

func (a *App) markPrivilegedReady(epoch uint64) {
	a.mu.Lock()
	if epoch != a.helperEpoch || !a.externalOwned {
		a.mu.Unlock()
		return
	}
	a.starting = false
	pendingClaim := a.claimConnectPending
	a.claimConnectPending = false
	a.mu.Unlock()
	status, err := a.GetStatus()
	if err == nil && a.desktop != nil {
		a.desktop.Event.Emit("service:ready", true)
		a.desktop.Event.Emit("status:update", status)
		if pendingClaim {
			a.desktop.Event.Emit("claim:connected", true)
		}
	}
	a.updateTray(status, err)
}

func (a *App) finishPrivilegedStart(epoch uint64, err error) {
	a.mu.Lock()
	if epoch != a.helperEpoch {
		a.mu.Unlock()
		return
	}
	a.starting = false
	a.externalOwned = false
	a.agentCancel = nil
	a.helperMarker = ""
	a.mu.Unlock()
	if err != nil {
		a.emitError(err)
	}
	status, statusErr := a.GetStatus()
	if a.desktop != nil {
		a.desktop.Event.Emit("status:update", status)
	}
	a.updateTray(status, statusErr)
}

func normalizeHelperError(err error) error {
	if err == nil {
		return errors.New("privileged tunnel helper stopped")
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "canceled") || strings.Contains(text, "cancelled") || strings.Contains(text, "-128") {
		return errors.New("administrator authorization was cancelled")
	}
	return errors.New("privileged tunnel helper could not start")
}

func validateOwnedPrivateFile(path string, maxSize int64) (uint32, uint32, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return 0, 0, errors.New("path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return 0, 0, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return 0, 0, errors.New("path must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Size() > maxSize {
		return 0, 0, errors.New("file permissions or size are unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid == 0 {
		return 0, 0, errors.New("file must belong to the desktop user")
	}
	return stat.Uid, stat.Gid, nil
}

func readOwnedPrivateFile(path string, maxSize int64) ([]byte, uint32, uint32, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, 0, 0, errors.New("path must be absolute and clean")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, 0, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, 0, 0, errors.New("open private file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, 0, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxSize {
		return nil, 0, 0, errors.New("file permissions or size are unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid == 0 {
		return nil, 0, 0, errors.New("file must belong to the desktop user")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, 0, 0, err
	}
	if int64(len(data)) > maxSize {
		return nil, 0, 0, errors.New("file is too large")
	}
	return data, stat.Uid, stat.Gid, nil
}

func validateOwnedPrivateFileForUser(path string, uid, gid uint32, maxSize int64) error {
	fileUID, fileGID, err := validateOwnedPrivateFile(path, maxSize)
	if err != nil {
		return err
	}
	if fileUID != uid || fileGID != gid {
		return errors.New("file owner does not match the desktop user")
	}
	return nil
}

func validateHelperPath(path string, uid, gid uint32) error {
	if err := validateOwnedPrivateFileForUser(path, uid, gid, 128); err != nil {
		return err
	}
	base := filepath.Base(path)
	if !strings.HasPrefix(base, ".desktop-ipc-") {
		return errors.New("unexpected IPC filename")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("IPC directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid {
		return errors.New("IPC directory owner does not match the desktop user")
	}
	return nil
}

func removeOwnedHelperFile(path string, uid uint32) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid == uid {
		_ = os.Remove(path)
	}
}
