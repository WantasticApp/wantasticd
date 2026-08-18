//go:build windows
// +build windows

package netctl

import (
	"fmt"
	"net/netip"
	"os/exec"
)

// windowsController uses netsh and WinAPI for network control.
// WiFi uses wlanapi.dll when built with -tags netctl.
type windowsController struct{}

func newController() Controller { return &windowsController{} }

func (c *windowsController) Close() error { return nil }

func (c *windowsController) LinkSetUp(ifname string) error {
	return exec.Command("netsh", "interface", "set", "interface", ifname, "admin=enable").Run()
}

func (c *windowsController) LinkSetDown(ifname string) error {
	return exec.Command("netsh", "interface", "set", "interface", ifname, "admin=disable").Run()
}

func (c *windowsController) LinkSetMTU(ifname string, mtu int) error {
	return exec.Command("netsh", "interface", "ipv4", "set", "subinterface", ifname, fmt.Sprintf("mtu=%d", mtu), "store=active").Run()
}

func (c *windowsController) AddrAdd(ifname string, addr netip.Prefix) error {
	family := "ipv4"
	if addr.Addr().Is6() {
		family = "ipv6"
	}
	return exec.Command("netsh", "interface", family, "add", "address", ifname, addr.String()).Run()
}

func (c *windowsController) AddrDel(ifname string, addr netip.Prefix) error {
	family := "ipv4"
	if addr.Addr().Is6() {
		family = "ipv6"
	}
	return exec.Command("netsh", "interface", family, "delete", "address", ifname, addr.Addr().String()).Run()
}

func (c *windowsController) RouteReplace(ifname string, dst netip.Prefix) error {
	family := "ipv4"
	if dst.Addr().Is6() {
		family = "ipv6"
	}
	// Delete first (idempotent)
	exec.Command("netsh", "interface", family, "delete", "route", dst.String(), ifname).Run()
	return exec.Command("netsh", "interface", family, "add", "route", dst.String(), ifname).Run()
}

func (c *windowsController) RouteDel(ifname string, dst netip.Prefix) error {
	family := "ipv4"
	if dst.Addr().Is6() {
		family = "ipv6"
	}
	return exec.Command("netsh", "interface", family, "delete", "route", dst.String(), ifname).Run()
}

func (c *windowsController) RouteGetDefault() (string, netip.Addr, error) {
	return "", netip.Addr{}, fmt.Errorf("not implemented on Windows")
}

func (c *windowsController) WiFiGetCapabilities(ifname string) (*WiFiCapabilities, error) {
	return nil, fmt.Errorf("WiFi capabilities not implemented on Windows (build with -tags netctl for wlanapi)")
}

func (c *windowsController) WiFiGetStations(ifname string) ([]WiFiStationInfo, error) {
	return nil, fmt.Errorf("WiFi stations not implemented on Windows")
}

func (c *windowsController) FirewallEnsureRule(rule FirewallRule) error {
	return fmt.Errorf("Windows firewall not implemented")
}

func (c *windowsController) FirewallDeleteRule(rule FirewallRule) error {
	return fmt.Errorf("Windows firewall not implemented")
}

func (c *windowsController) IPForwardingSet(enabled bool) error {
	val := "enabled"
	if !enabled {
		val = "disabled"
	}
	return exec.Command("netsh", "interface", "ipv4", "set", "global", "ipforwarding="+val).Run()
}
