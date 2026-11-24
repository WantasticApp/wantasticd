// Package netpollguard holds the startup self-probe for the Go network
// poller. On the OLT (Linux 3.6.5, CONFIG_EPOLL off) runtime.netpollinit
// throws fatally the first time anything needs the poller (package net,
// os.Open/NewFile/Pipe, os/exec, or any Go timer: time.Sleep/After/
// NewTimer/Ticker, context deadlines). The helper never uses those; this
// package makes the kernel's capability explicit at startup and gives any
// future poller-dependent feature a clean abort instead of a runtime throw.
package netpollguard

import "sync/atomic"

var probed atomic.Int32 // 0 unknown, 1 epoll present, 2 epoll missing

// HasEpoll reports the probe result (Probe must have run).
func HasEpoll() bool { return probed.Load() == 1 }

// Probe runs the EpollCreate1 self-probe once and returns whether the
// kernel has epoll and a human readable detail.
func Probe() (bool, string) {
	ok, detail := probe()
	if ok {
		probed.Store(1)
	} else {
		probed.Store(2)
	}
	return ok, detail
}

// Require must be called before any code path that would start the Go
// network poller. On a kernel without epoll it aborts the process cleanly
// (exit status 3, message on stderr) instead of letting the runtime throw.
func Require(feature string, abort func(msg string)) {
	if probed.Load() == 2 {
		abort("wantastic-oltd: " + feature + " needs the Go network poller, but this kernel has no epoll; refusing to start it")
	}
}
