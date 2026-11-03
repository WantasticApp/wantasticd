//go:build !windows && !darwin && !linux

package device

// No unprivileged ping here; the userspace exit does not answer pings.
func newICMPEchoer() icmpEchoer { return nil }
