//go:build !linux

package platforms

func readKernelClockSync() (bool, bool) { return false, false }
