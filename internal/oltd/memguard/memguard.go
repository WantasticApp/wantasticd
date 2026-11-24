// Package memguard keeps the Go garbage collector from ever completing a
// cycle in wantastic-oltd.
//
// Why: on Linux every runtime timer starts the network poller
// (runtime.(*timers).addHeap -> netpollGenericInit), and the OLT kernel has
// no epoll, so starting it is a fatal throw. Our code arms no timers, but
// the runtime's background scavenger does: after a GC cycle that leaves
// more memory retained than its goal, bgscavenge releases pages and then
// sleeps on a timer (mgcscavenge.go scavengerState.sleep). There is no knob
// to disable it. Reproduced under a seccomp profile that fails
// epoll_create/epoll_create1 with ENOSYS: "runtime: epollcreate failed with
// 38 / fatal error: runtime: netpollinit failed" in goroutine 4
// (runtime.bgscavenge).
//
// The scavenger's goals stay "infinite" until the first GC cycle completes
// (gcPaceScavenger: lastHeapGoal == 0) and the memory limit is unset, so a
// process that never completes a GC never wakes it. memguard therefore runs
// the process with GOGC=off and no GOMEMLIMIT (re-executing itself if the
// environment says otherwise, so the setting is in force before the first
// allocation), and the server bounds memory by re-executing itself at a
// heap ceiling (see server.Config.MaxHeap) instead of collecting.
//
// Never call runtime.GC or debug.FreeOSMemory in this binary.
package memguard

import (
	"errors"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
)

// Environment variables used across a re-exec.
const (
	EnvListenFD = "WANTASTIC_OLTD_LISTEN_FD"
	EnvRestarts = "WANTASTIC_OLTD_RESTARTS"
)

// NeedsReexec reports whether env (KEY=VALUE list) lacks GOGC=off or sets
// GOMEMLIMIT, i.e. whether the GC could run in a process started with it.
func NeedsReexec(env []string) bool {
	gogcOff := false
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "GOGC":
			gogcOff = v == "off"
		case "GOMEMLIMIT":
			if v != "" && v != "off" {
				return true
			}
		}
	}
	return !gogcOff
}

// FixEnv returns env with GOGC=off, without GOMEMLIMIT, and with extra
// (KEY=VALUE) applied, replacing earlier values of the same keys.
func FixEnv(env []string, extra ...string) []string {
	drop := map[string]bool{"GOGC": true, "GOMEMLIMIT": true}
	for _, kv := range extra {
		k, _, _ := strings.Cut(kv, "=")
		drop[k] = true
	}
	out := make([]string, 0, len(env)+len(extra)+1)
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			out = append(out, kv)
		}
	}
	out = append(out, "GOGC=off")
	return append(out, extra...)
}

// Self is the path used to re-execute this program.
func Self() (string, error) {
	if runtime.GOOS == "linux" {
		return "/proc/self/exe", nil
	}
	return os.Executable()
}

// Exec replaces the process with a fresh copy of itself (same argv) using
// the fixed environment plus extra.
func Exec(extra ...string) error { return ExecArgs(os.Args, extra...) }

// ExecArgs is Exec with a different argv.
func ExecArgs(argv []string, extra ...string) error {
	self, err := Self()
	if err != nil {
		return err
	}
	return syscall.Exec(self, argv, FixEnv(os.Environ(), extra...))
}

// Ensure must be the first thing main does. If the GC could run in this
// process it re-executes itself with GOGC=off (and returns only on exec
// failure). Otherwise it double-checks that no GC cycle has completed.
func Ensure() error {
	if NeedsReexec(os.Environ()) {
		if err := Exec(); err != nil {
			return errors.New("memguard: cannot re-exec with GOGC=off: " + err.Error())
		}
	}
	if prev := debug.SetGCPercent(-1); prev != -1 {
		return errors.New("memguard: GC was enabled despite GOGC=off")
	}
	if NumGC() != 0 {
		return errors.New("memguard: a GC cycle already completed")
	}
	return nil
}

// Stats returns the bytes allocated on the heap (never freed while the GC
// is off) and the number of completed GC cycles (must stay 0).
func Stats() (heapAlloc uint64, numGC uint32) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc, m.NumGC
}

// NumGC returns the number of completed GC cycles.
func NumGC() uint32 {
	_, n := Stats()
	return n
}
