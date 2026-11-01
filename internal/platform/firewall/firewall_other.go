//go:build !windows

package firewall

import "net/netip"

func AllowApp(exePath string) error           { return nil }
func AllowOverlay(addrs []netip.Prefix) error { return nil }
func Remove() error                           { return nil }
