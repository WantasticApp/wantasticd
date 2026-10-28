//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// trayLaunchdLabel is the per-user LaunchAgent the installer registers.
const trayLaunchdLabel = "com.wantastic.tray"

// binaryWatch notices when an update replaced the tray's own binary.
type binaryWatch struct {
	path    string // resolved at start: on Windows the running image is renamed aside
	started time.Time
}

func newBinaryWatch() *binaryWatch {
	path, err := os.Executable()
	if err == nil {
		if resolved, rerr := filepath.EvalSymlinks(path); rerr == nil {
			path = resolved
		}
	}
	return &binaryWatch{path: path, started: time.Now()}
}

// replaced reports whether a newer file now sits at the tray's path. Updates
// always write a fresh file (never touch mtimes back), so a later mtime means
// a swap happened after this process started.
func (w *binaryWatch) replaced() bool {
	if w.path == "" {
		return false
	}
	fi, err := os.Stat(w.path)
	return err == nil && fi.ModTime().After(w.started)
}

// restart replaces this tray process with one running the new binary.
func (w *binaryWatch) restart() {
	// Under launchd (KeepAlive SuccessfulExit=false) a failing exit is the
	// restart; spawning a child would escape the job.
	if os.Getenv("XPC_SERVICE_NAME") == trayLaunchdLabel {
		os.Exit(1)
	}
	cmd := exec.Command(w.path, "tray")
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		log.Printf("tray: restart on updated binary failed: %v", err)
		return
	}
	cmd.Process.Release()
	os.Exit(0)
}
