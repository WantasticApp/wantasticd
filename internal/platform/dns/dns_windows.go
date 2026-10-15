//go:build windows

package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func Apply(ctx context.Context, req Request) (Result, error) {
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	default:
	}
	if strings.TrimSpace(req.InterfaceName) == "" {
		return Result{}, fmt.Errorf("native Windows DNS requires a tunnel interface name")
	}
	iface, err := net.InterfaceByName(req.InterfaceName)
	if err != nil {
		return Result{}, fmt.Errorf("find DNS interface %q: %w", req.InterfaceName, err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return Result{}, fmt.Errorf("resolve DNS interface %q: %w", req.InterfaceName, err)
	}

	existingAddrs, _ := luid.DNS()
	existing := make([]string, 0, len(existingAddrs))
	for _, addr := range existingAddrs {
		existing = append(existing, addr.String())
	}
	servers := desiredServers(req, existing)
	if len(servers) == 0 {
		return Result{Skipped: true, Method: "windows-ip-helper", Reason: "no DNS servers requested"}, nil
	}

	var v4, v6 []netip.Addr
	for _, server := range servers {
		addr, parseErr := netip.ParseAddr(server)
		if parseErr != nil {
			return Result{}, fmt.Errorf("invalid DNS server %q: %w", server, parseErr)
		}
		if addr.Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	if len(v4) != 0 {
		if err := luid.SetDNS(windows.AF_INET, v4, []string{"wantastic"}); err != nil {
			return Result{}, fmt.Errorf("set IPv4 DNS on %q: %w", req.InterfaceName, err)
		}
	}
	if len(v6) != 0 {
		if err := luid.SetDNS(windows.AF_INET6, v6, []string{"wantastic"}); err != nil {
			return Result{}, fmt.Errorf("set IPv6 DNS on %q: %w", req.InterfaceName, err)
		}
	}
	return Result{Changed: true, Method: "windows-ip-helper", Reason: req.Reason, Servers: servers}, nil
}

func removeTunnel(interfaceName string) error {
	if strings.TrimSpace(interfaceName) == "" {
		return nil
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("find DNS interface %q for cleanup: %w", interfaceName, err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return fmt.Errorf("resolve DNS interface %q for cleanup: %w", interfaceName, err)
	}
	if err := luid.SetDNS(windows.AF_INET, nil, nil); err != nil {
		return fmt.Errorf("clear IPv4 DNS on %q: %w", interfaceName, err)
	}
	if err := luid.SetDNS(windows.AF_INET6, nil, nil); err != nil {
		return fmt.Errorf("clear IPv6 DNS on %q: %w", interfaceName, err)
	}
	return nil
}
