//go:build !darwin
// +build !darwin

package device

// allowInboundThroughAppFirewall is a no-op: only macOS has a per-application
// firewall that drops the first inbound hole-punch packets.
func allowInboundThroughAppFirewall() {}
