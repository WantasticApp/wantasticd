//go:build linux
// +build linux

package dns

import (
	"context"
	"fmt"
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

	// Plain and symlinked-volatile files are written (through the link); a
	// local dnsmasq stub file is too, as before, and IncludeExisting keeps the
	// stub in the list. Managers that regenerate the file are left alone.
	manager := detectLinuxDNSManager()
	if manager != managerPlainFile && manager != managerVolatileFile && manager != managerDnsmasq {
		return Result{
			Skipped: true,
			Method:  manager,
			Reason:  fmt.Sprintf("%s manages /etc/resolv.conf; device DNS is controlled through it (Device.WUSP_DNS), set WANTASTIC_DNS_MODE=force-file to override", manager),
			Servers: servers,
		}, nil
	}
	return writeResolvFile(resolvConfPath, servers, req.Reason)
}
