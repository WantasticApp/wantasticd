//go:build !windows

package device

// The userspace exit is used only on Windows; elsewhere the kernel NAT
// carries ICMP.
func newICMPEchoer() icmpEchoer { return nil }
