//go:build !linux || android

// Android's app sandbox (seccomp) kills a process that calls adjtimex, so
// apps report the clock's sync state as unknown.

package platforms

func readKernelClockSync() (bool, bool) { return false, false }
