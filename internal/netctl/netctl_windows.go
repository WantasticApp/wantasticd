//go:build windows
// +build windows

package netctl

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
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

func (c *windowsController) TenantFirewallSet(rules []TenantFirewallRule) error {
	var script strings.Builder
	script.WriteString("$ErrorActionPreference = 'Stop'\n")
	for _, rule := range rules {
		name := tenantFirewallRuleName(rule)
		remote := make([]string, 0, len(rule.Remote))
		for _, prefix := range rule.Remote {
			remote = append(remote, powershellQuote(prefix.String()))
		}
		fmt.Fprintf(&script, "$old = Get-NetFirewallRule -Name %s -ErrorAction SilentlyContinue; if ($old) { $old | Remove-NetFirewallRule };\n", powershellQuote(name))
		fmt.Fprintf(&script,
			"New-NetFirewallRule -Name %s -DisplayName %s -Group 'Wantastic Agent' -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol Any -LocalAddress %s -RemoteAddress @(%s) -InterfaceAlias %s | Out-Null\n",
			powershellQuote(name), powershellQuote("Wantastic tenant access "+rule.Local.String()),
			powershellQuote(rule.Local.String()), strings.Join(remote, ","), powershellQuote(rule.Interface),
		)
	}
	if script.Len() == 0 {
		return nil
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script.String())
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("configure Windows Defender Firewall: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (c *windowsController) TenantFirewallClear(rules []TenantFirewallRule) error {
	var script strings.Builder
	script.WriteString("$ErrorActionPreference = 'Stop'\n")
	for _, rule := range rules {
		fmt.Fprintf(&script, "$old = Get-NetFirewallRule -Name %s -ErrorAction SilentlyContinue; if ($old) { $old | Remove-NetFirewallRule };\n", powershellQuote(tenantFirewallRuleName(rule)))
	}
	if script.Len() == 0 {
		return nil
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script.String())
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("remove Windows Defender Firewall rules: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func tenantFirewallRuleName(rule TenantFirewallRule) string {
	sum := sha256.Sum256([]byte(rule.Interface + "\x00" + rule.Local.String()))
	return "WantasticTenant_" + hex.EncodeToString(sum[:8])
}

func powershellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func (c *windowsController) IPForwardingSet(enabled bool) error {
	val := "enabled"
	if !enabled {
		val = "disabled"
	}
	return exec.Command("netsh", "interface", "ipv4", "set", "global", "ipforwarding="+val).Run()
}
