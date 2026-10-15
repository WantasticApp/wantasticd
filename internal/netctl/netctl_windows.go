//go:build windows

package netctl

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// windowsController uses the Windows IP Helper API directly. Wintun adapter
// lifetime controls link state, so no command interpreter or netsh fallback is
// used anywhere in the desktop tunnel path.
type windowsController struct{}

func newController() Controller { return &windowsController{} }

func (c *windowsController) Close() error { return nil }

func interfaceLUID(ifname string) (winipcfg.LUID, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return 0, fmt.Errorf("find interface %q: %w", ifname, err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return 0, fmt.Errorf("resolve interface %q LUID: %w", ifname, err)
	}
	return luid, nil
}

func (c *windowsController) LinkSetUp(ifname string) error {
	_, err := interfaceLUID(ifname)
	return err
}

func (c *windowsController) LinkSetDown(ifname string) error {
	_, err := interfaceLUID(ifname)
	return err
}

func (c *windowsController) LinkSetMTU(ifname string, mtu int) error {
	if mtu < 576 || mtu > 65535 {
		return fmt.Errorf("invalid MTU %d", mtu)
	}
	luid, err := interfaceLUID(ifname)
	if err != nil {
		return err
	}
	var setErrs []error
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, rowErr := luid.IPInterface(family)
		if rowErr != nil {
			setErrs = append(setErrs, rowErr)
			continue
		}
		row.NLMTU = uint32(mtu)
		if rowErr = row.Set(); rowErr != nil {
			setErrs = append(setErrs, rowErr)
		}
	}
	return errors.Join(setErrs...)
}

func (c *windowsController) AddrAdd(ifname string, addr netip.Prefix) error {
	luid, err := interfaceLUID(ifname)
	if err != nil {
		return err
	}
	if err := luid.AddIPAddress(addr); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("add %s to %s: %w", addr, ifname, err)
	}
	return nil
}

func (c *windowsController) AddrDel(ifname string, addr netip.Prefix) error {
	luid, err := interfaceLUID(ifname)
	if err != nil {
		return err
	}
	if err := luid.DeleteIPAddress(addr); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("delete %s from %s: %w", addr, ifname, err)
	}
	return nil
}

func routeNextHop(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

func (c *windowsController) RouteReplace(ifname string, dst netip.Prefix) error {
	luid, err := interfaceLUID(ifname)
	if err != nil {
		return err
	}
	dst = dst.Masked()
	nextHop := routeNextHop(dst)
	if _, err = luid.Route(dst, nextHop); err == nil {
		return nil
	}
	if err := luid.AddRoute(dst, nextHop, 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("add route %s on %s: %w", dst, ifname, err)
	}
	return nil
}

func (c *windowsController) RouteDel(ifname string, dst netip.Prefix) error {
	luid, err := interfaceLUID(ifname)
	if err != nil {
		return err
	}
	dst = dst.Masked()
	if err := luid.DeleteRoute(dst, routeNextHop(dst)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("delete route %s on %s: %w", dst, ifname, err)
	}
	return nil
}

func (c *windowsController) RouteGetDefault() (string, netip.Addr, error) {
	return "", netip.Addr{}, fmt.Errorf("default route query is not required by the Windows tunnel service")
}

func (c *windowsController) WiFiGetCapabilities(string) (*WiFiCapabilities, error) {
	return nil, fmt.Errorf("Wi-Fi capabilities require the native WLAN API adapter")
}

func (c *windowsController) WiFiGetStations(string) ([]WiFiStationInfo, error) {
	return nil, fmt.Errorf("Wi-Fi station enumeration is unavailable on Windows clients")
}

func (c *windowsController) FirewallEnsureRule(FirewallRule) error {
	return fmt.Errorf("Windows Firewall policy must be installed by the privileged service")
}

func (c *windowsController) FirewallDeleteRule(FirewallRule) error {
	return fmt.Errorf("Windows Firewall policy must be removed by the privileged service")
}

func (c *windowsController) IPForwardingSet(bool) error {
	return fmt.Errorf("Windows forwarding must be configured per interface by the privileged service")
}
