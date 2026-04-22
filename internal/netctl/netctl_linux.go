//go:build linux && !netctl
// +build linux,!netctl

// Pure-Go Linux controller (no CGo). Uses raw netlink + sysfs.
// For CGo-accelerated nl80211 WiFi, build with: -tags netctl

package netctl

func newController() Controller { return &linuxController{} }
