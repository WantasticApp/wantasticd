//go:build !windows
// +build !windows

package runner

import (
	"context"
	"syscall"
)

func RunServiceHook(runFunc func(context.Context)) {
	runFunc(context.Background())
}

// detachedProcAttr starts a child in its own session so it outlives this
// process and its terminal.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
