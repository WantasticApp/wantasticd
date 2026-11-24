//go:build !linux

package netpollguard

func probe() (bool, string) { return true, "non-Linux build (kqueue): probe not applicable" }
