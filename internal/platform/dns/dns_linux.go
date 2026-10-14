//go:build linux
// +build linux

package dns

import (
	"context"
	"fmt"
	"os"
)

func Apply(ctx context.Context, req Request) (Result, error) {
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	default:
	}

	mode := dnsMode()
	if mode == "off" || mode == "disabled" || mode == "0" {
		return Result{Skipped: true, Method: "disabled", Reason: "WANTASTIC_DNS_MODE disables DNS writes"}, nil
	}

	existing := readResolvNameservers(resolvConfPath)
	servers := desiredServers(req, existing)
	if len(servers) == 0 {
		return Result{Skipped: true, Method: "none", Reason: "no DNS servers requested"}, nil
	}
	if mode == "force-file" {
		return writeResolvFile(resolvConfPath, servers, req.Reason)
	}

	manager := detectLinuxDNSManager()
	if manager != "plain-file" {
		return Result{
			Skipped: true,
			Method:  manager,
			Reason:  fmt.Sprintf("%s manages DNS; set WANTASTIC_DNS_MODE=force-file to override", manager),
			Servers: servers,
		}, nil
	}
	return writeResolvFile(resolvConfPath, servers, req.Reason)
}

func detectLinuxDNSManager() string {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return "openwrt-uci"
	}
	if commandAvailable("resolvectl") || commandAvailable("systemd-resolve") {
		if fi, err := lstatPath(resolvConfPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Readlink(resolvConfPath); err == nil && isManagedResolvTarget(target) {
				return "systemd-resolved"
			}
		}
	}
	if commandAvailable("nmcli") {
		return "networkmanager"
	}
	if commandAvailable("resolvconf") {
		return "resolvconf"
	}
	if fi, err := lstatPath(resolvConfPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(resolvConfPath); err == nil && isManagedResolvTarget(target) {
			return "managed-resolv.conf"
		}
	}
	return "plain-file"
}
