//go:build linux

package dns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"wantastic-agent/internal/platform/systemd"
)

var (
	resolvedDropIn     = "/etc/systemd/resolved.conf.d/90-wantastic-dns.conf"
	resolvBackupSuffix = ".wantastic-auto"
	// legacyResolvBackup is where agents before the symlink-aware writer
	// kept the automatic copy.
	legacyResolvBackup = "/etc/resolv.conf.wantastic-auto"
	resolvconfIface    = "lo.wantastic"
	procNetRoute       = "/proc/net/route"
	errOpenWrtExternal = errors.New("OpenWrt DNS is managed by the OpenWrt backend")
)

// ReadControl reports the resolver configuration (OpenWrt is handled by the
// OpenWrt backend through dnsmasq and reported unsupported here).
func ReadControl(ctx context.Context) ControlState {
	switch manager := detectLinuxDNSManager(); manager {
	case managerOpenWrt:
		return ControlState{Method: "unsupported", Reason: errOpenWrtExternal.Error()}
	case managerResolved:
		st := ControlState{Supported: true, Method: "systemd-resolved", Effective: readResolvNameservers(resolvedUpstreamPath)}
		if data, err := readFile(resolvedDropIn); err == nil {
			st.Servers = parseResolvedDNS(string(data))
			st.Manual = len(st.Servers) > 0
		}
		return st
	case managerNetworkManager:
		dev, conn, err := nmDefaultConnection(ctx)
		if err != nil {
			return ControlState{Method: "networkmanager", Reason: err.Error(), Effective: readResolvNameservers(resolvConfPath)}
		}
		st := ControlState{Supported: true, Method: "networkmanager"}
		out, _ := runCommand(ctx, "", "nmcli", "-g", "ipv4.dns,ipv4.ignore-auto-dns,ipv6.dns,ipv6.ignore-auto-dns", "connection", "show", conn)
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		get := func(i int) string {
			if i < len(lines) {
				return strings.TrimSpace(lines[i])
			}
			return ""
		}
		manual4, manual6 := splitList(get(0)), splitList(get(2))
		st.Manual = (get(1) == "yes" && len(manual4) > 0) || (get(3) == "yes" && len(manual6) > 0)
		if st.Manual {
			st.Servers = append(manual4, manual6...)
		}
		eff, _ := runCommand(ctx, "", "nmcli", "-g", "IP4.DNS,IP6.DNS", "device", "show", dev)
		st.Effective = splitList(strings.ReplaceAll(eff, "\n", "|"))
		return st
	case managerResolvconf:
		st := ControlState{Supported: true, Method: "resolvconf", Effective: readResolvNameservers(resolvConfPath)}
		if out, err := runCommand(ctx, "", "resolvconf", "-l", resolvconfIface); err == nil {
			st.Servers = parseNameserverLines(out)
			st.Manual = len(st.Servers) > 0
		}
		return st
	case managerPlainFile, managerVolatileFile:
		// Mode follows the marker in the file in effect, not a side file:
		// a DHCP client or vendor daemon that rewrote resolv.conf has
		// really returned the device to automatic resolvers.
		st := ControlState{Supported: true, Method: "resolv.conf", Effective: readResolvNameservers(resolvConfPath)}
		if manual := readManualMarker(resolvConfPath); len(manual) > 0 {
			st.Manual, st.Servers = true, manual
		}
		return st
	case managerDnsmasq:
		// A local dnsmasq (QCMAP on QTI modules, or a distro service)
		// answers for the device and its LAN; its upstreams are rewritten by
		// the connection manager. Pointing resolv.conf elsewhere would
		// bypass it, so report what it uses instead of writing.
		effective := dnsmasqUpstreams()
		if len(effective) == 0 {
			effective = readResolvNameservers(resolvConfPath)
		}
		return ControlState{
			Method:    "unsupported",
			Effective: effective,
			Reason:    "a local dnsmasq resolves for this device and its LAN and its upstream servers are set by the connection manager; DNS cannot be changed safely here",
		}
	default:
		return ControlState{Method: "unsupported", Reason: manager + " owns /etc/resolv.conf", Effective: readResolvNameservers(resolvConfPath)}
	}
}

// SetServers applies a manual resolver list; an empty list restores the
// automatic (DHCP/ISP) resolvers.
func SetServers(ctx context.Context, servers []string) error {
	servers, err := NormalizeServers(servers)
	if err != nil {
		return err
	}
	switch manager := detectLinuxDNSManager(); manager {
	case managerOpenWrt:
		return errOpenWrtExternal
	case managerResolved:
		if len(servers) == 0 {
			if err := removePath(resolvedDropIn); err != nil && !os.IsNotExist(err) {
				return err
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(resolvedDropIn), 0o755); err != nil {
				return describeWriteError(filepath.Dir(resolvedDropIn), err)
			}
			body := "# Managed by wantasticd (DNS control from the console)\n[Resolve]\nDNS=" + strings.Join(servers, " ") + "\nDomains=~.\n"
			if err := writeFile(resolvedDropIn, []byte(body), 0o644); err != nil {
				return describeWriteError(resolvedDropIn, err)
			}
		}
		if err := systemd.ReloadOrTryRestartUnit(ctx, "systemd-resolved.service"); err == nil {
			return nil
		}
		if _, err := runCommand(ctx, "", "systemctl", "try-reload-or-restart", "systemd-resolved"); err != nil {
			_, err = runCommand(ctx, "", "systemctl", "restart", "systemd-resolved")
			return err
		}
		return nil
	case managerNetworkManager:
		dev, conn, err := nmDefaultConnection(ctx)
		if err != nil {
			return err
		}
		v4, v6 := splitFamilies(servers)
		ignore := map[bool]string{true: "yes", false: "no"}
		args := []string{"connection", "modify", conn,
			"ipv4.dns", strings.Join(v4, ","), "ipv4.ignore-auto-dns", ignore[len(servers) > 0 && len(v4) > 0],
			"ipv6.dns", strings.Join(v6, ","), "ipv6.ignore-auto-dns", ignore[len(servers) > 0 && len(v6) > 0]}
		if _, err := runCommand(ctx, "", "nmcli", args...); err != nil {
			return err
		}
		// reapply updates the live device without bringing it down.
		_, err = runCommand(ctx, "", "nmcli", "device", "reapply", dev)
		return err
	case managerResolvconf:
		if len(servers) == 0 {
			_, err := runCommand(ctx, "", "resolvconf", "-d", resolvconfIface)
			return err
		}
		var b strings.Builder
		for _, s := range servers {
			fmt.Fprintf(&b, "nameserver %s\n", s)
		}
		_, err := runCommand(ctx, b.String(), "resolvconf", "-a", resolvconfIface)
		return err
	case managerPlainFile, managerVolatileFile:
		return setResolvFileServers(servers)
	case managerDnsmasq:
		return errors.New("a local dnsmasq resolves for this device and its LAN and its upstream servers are set by the connection manager; DNS cannot be changed safely here")
	default:
		return fmt.Errorf("%s owns /etc/resolv.conf; DNS cannot be changed safely", manager)
	}
}

// setResolvFileServers writes a manual list to resolv.conf (through its
// symlink when it has one), keeping the automatic content beside the file in
// effect so an empty list can restore it.
func setResolvFileServers(servers []string) error {
	target := resolvWriteTarget(resolvConfPath)
	backup := target + resolvBackupSuffix
	if len(servers) == 0 {
		data, err := readFile(backup)
		if err != nil {
			backup = legacyResolvBackup
			data, err = readFile(backup)
		}
		if err != nil {
			if len(readManualMarker(resolvConfPath)) == 0 {
				return nil // already automatic
			}
			return errors.New("no saved automatic resolver list to restore; renew the WAN DHCP lease or reconnect the modem")
		}
		if err := writeFile(target, data, 0o644); err != nil {
			return describeWriteError(target, err)
		}
		_ = removePath(backup)
		return nil
	}
	// Refresh the automatic copy unless the file in effect is already the
	// console's: DHCP may have rewritten it since the last manual set.
	if len(readManualMarker(resolvConfPath)) == 0 {
		if data, err := readFile(resolvConfPath); err == nil {
			if err := writeFile(backup, data, 0o644); err != nil {
				return describeWriteError(backup, err)
			}
		}
	}
	_, err := writeResolvFileManual(resolvConfPath, servers, controlReason, servers)
	return err
}

func parseResolvedDNS(conf string) []string {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DNS=") {
			return strings.Fields(strings.TrimPrefix(line, "DNS="))
		}
	}
	return nil
}

func splitList(value string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '|' || r == ' ' }) {
		if part = strings.TrimSpace(part); part != "" && part != "--" {
			out = append(out, part)
		}
	}
	return out
}

// nmDefaultConnection returns the device carrying the IPv4 default route and
// its active NetworkManager connection.
func nmDefaultConnection(ctx context.Context) (string, string, error) {
	data, err := readFile(procNetRoute)
	if err != nil {
		return "", "", err
	}
	dev := ""
	for i, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 2 {
			continue
		}
		if fields[1] == "00000000" {
			dev = fields[0]
			break
		}
	}
	if dev == "" {
		return "", "", errors.New("no default route")
	}
	out, err := runCommand(ctx, "", "nmcli", "-g", "GENERAL.CONNECTION", "device", "show", dev)
	conn := strings.TrimSpace(out)
	if err != nil || conn == "" || conn == "--" {
		return "", "", fmt.Errorf("%s is not managed by NetworkManager", dev)
	}
	return dev, conn, nil
}
