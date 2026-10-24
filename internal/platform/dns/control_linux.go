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
	resolvedUpstream   = "/run/systemd/resolve/resolv.conf"
	resolvBackupPath   = "/etc/resolv.conf.wantastic-auto"
	resolvconfIface    = "lo.wantastic"
	procNetRoute       = "/proc/net/route"
	errOpenWrtExternal = errors.New("OpenWrt DNS is managed by the OpenWrt backend")
)

// ReadControl reports the resolver configuration (OpenWrt is handled by the
// OpenWrt backend through dnsmasq and reported unsupported here).
func ReadControl(ctx context.Context) ControlState {
	switch manager := detectLinuxDNSManager(); manager {
	case "openwrt-uci":
		return ControlState{Method: "unsupported", Reason: errOpenWrtExternal.Error()}
	case "systemd-resolved":
		st := ControlState{Supported: true, Method: "systemd-resolved", Effective: readResolvNameservers(resolvedUpstream)}
		if data, err := readFile(resolvedDropIn); err == nil {
			st.Servers = parseResolvedDNS(string(data))
			st.Manual = len(st.Servers) > 0
		}
		return st
	case "networkmanager":
		dev, conn, err := nmDefaultConnection(ctx)
		if err != nil {
			return ControlState{Method: "networkmanager", Reason: err.Error()}
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
	case "resolvconf":
		st := ControlState{Supported: true, Method: "resolvconf", Effective: readResolvNameservers(resolvConfPath)}
		if out, err := runCommand(context.Background(), "", "resolvconf", "-l", resolvconfIface); err == nil {
			st.Servers = parseNameserverLines(out)
			st.Manual = len(st.Servers) > 0
		}
		return st
	case "plain-file":
		st := ControlState{Supported: true, Method: "resolv.conf", Effective: readResolvNameservers(resolvConfPath)}
		if _, err := os.Stat(resolvBackupPath); err == nil {
			st.Manual, st.Servers = true, st.Effective
		}
		return st
	default:
		return ControlState{Method: "unsupported", Reason: manager + " owns /etc/resolv.conf"}
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
	case "openwrt-uci":
		return errOpenWrtExternal
	case "systemd-resolved":
		if len(servers) == 0 {
			if err := removePath(resolvedDropIn); err != nil && !os.IsNotExist(err) {
				return err
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(resolvedDropIn), 0o755); err != nil {
				return err
			}
			body := "# Managed by wantasticd (DNS control from the console)\n[Resolve]\nDNS=" + strings.Join(servers, " ") + "\nDomains=~.\n"
			if err := writeFile(resolvedDropIn, []byte(body), 0o644); err != nil {
				return err
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
	case "networkmanager":
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
	case "resolvconf":
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
	case "plain-file":
		if len(servers) == 0 {
			data, err := readFile(resolvBackupPath)
			if err != nil {
				return nil // nothing to restore: already automatic
			}
			if err := writeFile(resolvConfPath, data, 0o644); err != nil {
				return err
			}
			return removePath(resolvBackupPath)
		}
		if _, err := os.Stat(resolvBackupPath); os.IsNotExist(err) {
			if data, readErr := readFile(resolvConfPath); readErr == nil {
				_ = writeFile(resolvBackupPath, data, 0o644)
			}
		}
		_, err := writeResolvFile(resolvConfPath, servers, "DNS control")
		return err
	default:
		return fmt.Errorf("%s owns /etc/resolv.conf; DNS cannot be changed safely", manager)
	}
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
