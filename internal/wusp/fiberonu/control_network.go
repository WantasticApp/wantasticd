package fiberonu

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// SetONUNetworkParam handles Device.WUSP_ONU.Network.* setters that change
// network configuration on the ONU's Linux layer.
func SetONUNetworkParam(ctx context.Context, opts Options, path string, value wusp.Value) error {
	const prefix = wusp.WUSPONUPrefix + "Network."
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}

	switch {
	case rest == "DNS.Server.1.Address" || rest == "DNS.Server.2.Address":
		return setDNSServer(rest, wusp.ValueToString(value))
	case strings.HasPrefix(rest, "Firewall.") && strings.HasSuffix(rest, ".Enabled"):
		return toggleFirewallChain(ctx, rest, value.AsBool())
	case strings.HasPrefix(rest, "DHCP.") && strings.HasSuffix(rest, ".Enable"):
		return toggleDHCPServer(ctx, opts, value.AsBool())
	case strings.HasPrefix(rest, "Radio.") && strings.HasSuffix(rest, ".Enable"):
		return toggleRadio(ctx, rest, value.AsBool())
	case strings.HasPrefix(rest, "Interface.") && strings.HasSuffix(rest, ".Enable"):
		return toggleInterface(ctx, rest, value.AsBool())
	case strings.HasPrefix(rest, "WAN.") && strings.HasSuffix(rest, ".VLANID"):
		return setWANVLAN(ctx, opts, rest, wusp.ValueToString(value))
	case strings.HasPrefix(rest, "WAN.") && strings.HasSuffix(rest, ".VLANMode"):
		return setWANVLANMode(ctx, opts, rest, wusp.ValueToString(value))
	case strings.HasPrefix(rest, "WAN.") && strings.HasSuffix(rest, ".Mode"):
		return setWANMode(ctx, opts, rest, wusp.ValueToString(value))
	}
	return wusp.ErrUSPPathUnsupported
}

// ONUNetworkOperate runs Device.WUSP_ONU.Network.* Operate commands.
func ONUNetworkOperate(ctx context.Context, opts Options, cmd string, input *wusp.Message) error {
	const prefix = wusp.WUSPONUPrefix + "Network."
	rest, ok := strings.CutPrefix(cmd, prefix)
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}

	switch rest {
	case "Firewall.FlushChain()":
		chain := OperateInputString(input, "Chain")
		table := OperateInputString(input, "Table")
		if table == "" {
			table = "filter"
		}
		return flushIPTablesChain(ctx, table, chain)
	case "Firewall.AddRule()":
		return addIPTablesRule(ctx, input)
	case "Firewall.DeleteRule()":
		return deleteIPTablesRule(ctx, input)
	case "Route.Add()":
		return addRoute(ctx, input)
	case "Route.Delete()":
		return deleteRoute(ctx, input)
	case "DHCP.Restart()":
		return restartDHCP(ctx)
	case "DNS.Restart()":
		return restartDNS(ctx)
	case "WLAN.Restart()":
		return restartWLAN(ctx, opts)
	case "WLAN.KickStation()":
		return kickStation(ctx, input)
	case "BackupNetworkConfig()":
		return backupNetworkConfig(ctx, input)
	}
	return wusp.ErrUSPPathUnsupported
}

// ---- DNS setter -----------------------------------------------------------

func setDNSServer(rest, addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return fmt.Errorf("onu: DNS server address is empty")
	}
	for _, path := range []string{"/tmp/resolv.conf", "/tmp/etc/resolv.conf", "/usr/etc/resolv.conf"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		var out []string
		nsIdx := 0
		targetIdx := 1
		if strings.HasSuffix(rest, "2.Address") {
			targetIdx = 2
		}
		found := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "nameserver") {
				nsIdx++
				if nsIdx == targetIdx {
					out = append(out, "nameserver "+addr)
					found = true
					continue
				}
			}
			out = append(out, line)
		}
		if !found {
			out = append(out, "nameserver "+addr)
		}
		if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0644); err != nil {
			return fmt.Errorf("onu: write resolv.conf: %w", err)
		}
		return nil
	}
	return fmt.Errorf("onu: resolv.conf not found")
}

// ---- Firewall toggle ------------------------------------------------------

func toggleFirewallChain(ctx context.Context, rest string, enable bool) error {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	parts := strings.Split(rest, ".")
	if len(parts) < 3 {
		return wusp.ErrUSPPathUnsupported
	}
	table := parts[1]
	chain := parts[2]
	policy := "ACCEPT"
	if enable {
		policy = "DROP"
	}
	return exec.CommandContext(tctx, "iptables", "-t", table, "-P", chain, policy).Run()
}

func flushIPTablesChain(ctx context.Context, table, chain string) error {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := []string{"-t", table, "-F"}
	if chain != "" {
		args = append(args, chain)
	}
	return exec.CommandContext(tctx, "iptables", args...).Run()
}

func addIPTablesRule(ctx context.Context, input *wusp.Message) error {
	raw := OperateInputString(input, "Rule")
	if raw == "" {
		return fmt.Errorf("onu: AddRule() requires a Rule input (iptables args)")
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := strings.Fields(raw)
	return exec.CommandContext(tctx, "iptables", args...).Run()
}

func deleteIPTablesRule(ctx context.Context, input *wusp.Message) error {
	raw := OperateInputString(input, "Rule")
	if raw == "" {
		return fmt.Errorf("onu: DeleteRule() requires a Rule input (iptables args)")
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := strings.Fields(raw)
	return exec.CommandContext(tctx, "iptables", args...).Run()
}

// ---- Route operations -----------------------------------------------------

func addRoute(ctx context.Context, input *wusp.Message) error {
	dest := OperateInputString(input, "Destination")
	gw := OperateInputString(input, "Gateway")
	iface := OperateInputString(input, "Interface")
	metric := OperateInputString(input, "Metric")
	if dest == "" {
		return fmt.Errorf("onu: Route.Add() requires a Destination")
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := []string{"add"}
	if dest == "default" {
		args = append(args, "default")
	} else {
		args = append(args, "-net", dest)
	}
	if gw != "" {
		args = append(args, "gw", gw)
	}
	if iface != "" {
		args = append(args, "dev", iface)
	}
	if metric != "" {
		args = append(args, "metric", metric)
	}
	return exec.CommandContext(tctx, "route", args...).Run()
}

func deleteRoute(ctx context.Context, input *wusp.Message) error {
	dest := OperateInputString(input, "Destination")
	gw := OperateInputString(input, "Gateway")
	if dest == "" {
		return fmt.Errorf("onu: Route.Delete() requires a Destination")
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := []string{"del"}
	if dest == "default" {
		args = append(args, "default")
	} else {
		args = append(args, "-net", dest)
	}
	if gw != "" {
		args = append(args, "gw", gw)
	}
	return exec.CommandContext(tctx, "route", args...).Run()
}

// ---- DHCP toggle + restart ------------------------------------------------

func toggleDHCPServer(ctx context.Context, opts Options, enable bool) error {
	if enable {
		return postCGIForm(ctx, opts, "net-dhcp.asp", url.Values{"dhcps_enable": {"1"}})
	}
	return postCGIForm(ctx, opts, "net-dhcp.asp", url.Values{"dhcps_enable": {"0"}})
}

func restartDHCP(ctx context.Context) error {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, svc := range []string{"dnsmasq", "udhcpd"} {
		if path, err := exec.LookPath(svc); err == nil {
			_ = exec.CommandContext(tctx, "killall", svc).Run()
			time.Sleep(500 * time.Millisecond)
			return exec.CommandContext(tctx, path).Start()
		}
	}
	return fmt.Errorf("onu: no DHCP server found")
}

// ---- DNS restart ----------------------------------------------------------

func restartDNS(ctx context.Context) error {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(tctx, "killall", "dnsmasq").Run()
	time.Sleep(500 * time.Millisecond)
	if path, err := exec.LookPath("dnsmasq"); err == nil {
		return exec.CommandContext(tctx, path).Start()
	}
	return fmt.Errorf("onu: dnsmasq not found")
}

// ---- WLAN operations ------------------------------------------------------

func toggleRadio(ctx context.Context, rest string, enable bool) error {
	parts := strings.Split(rest, ".")
	if len(parts) < 2 {
		return wusp.ErrUSPPathUnsupported
	}
	idx, err := strconv.Atoi(parts[1])
	if err != nil || idx < 1 {
		return wusp.ErrUSPPathUnsupported
	}
	ifaces := wlanInterfaces()
	if idx > len(ifaces) {
		return wusp.ErrUSPPathNotFound
	}
	iface := ifaces[idx-1]
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if enable {
		return exec.CommandContext(tctx, "ifconfig", iface, "up").Run()
	}
	return exec.CommandContext(tctx, "ifconfig", iface, "down").Run()
}

func restartWLAN(ctx context.Context, opts Options) error {
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, svc := range []string{"hostapd", "wlan"} {
		_ = exec.CommandContext(tctx, "killall", svc).Run()
	}
	time.Sleep(time.Second)
	if path, err := exec.LookPath("hostapd"); err == nil {
		for _, conf := range []string{"/etc/hostapd.conf", "/tmp/hostapd.conf", "/var/run/hostapd.conf"} {
			if _, err := os.Stat(conf); err == nil {
				return exec.CommandContext(tctx, path, "-B", conf).Start()
			}
		}
	}
	return postCGIForm(ctx, opts, "net-wlan.asp", url.Values{"wlan_restart": {"1"}})
}

func kickStation(ctx context.Context, input *wusp.Message) error {
	mac := OperateInputString(input, "MACAddress")
	iface := OperateInputString(input, "Interface")
	if mac == "" {
		return fmt.Errorf("onu: KickStation() requires a MACAddress input")
	}
	if iface == "" {
		ifaces := wlanInterfaces()
		if len(ifaces) > 0 {
			iface = ifaces[0]
		} else {
			return fmt.Errorf("onu: no wireless interface found")
		}
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Try iw first, fall back to iwpriv (Ralink/MediaTek EN7528).
	if err := exec.CommandContext(tctx, "iw", "dev", iface, "station", "del", mac).Run(); err != nil {
		return exec.CommandContext(tctx, "iwpriv", iface, "set", "DisConnectSta="+mac).Run()
	}
	return nil
}

// ---- Interface toggle -----------------------------------------------------

func toggleInterface(ctx context.Context, rest string, enable bool) error {
	parts := strings.Split(rest, ".")
	if len(parts) < 2 {
		return wusp.ErrUSPPathUnsupported
	}
	idx, err := strconv.Atoi(parts[1])
	if err != nil || idx < 1 {
		return wusp.ErrUSPPathUnsupported
	}
	name := resolveIfaceByIndex(idx)
	if name == "" {
		return wusp.ErrUSPPathNotFound
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if enable {
		return exec.CommandContext(tctx, "ifconfig", name, "up").Run()
	}
	return exec.CommandContext(tctx, "ifconfig", name, "down").Run()
}

func resolveIfaceByIndex(idx int) string {
	data := readFile("/proc/net/dev")
	if data == "" {
		return ""
	}
	lines := strings.Split(data, "\n")
	cur := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") || strings.HasPrefix(line, "Inter") || strings.HasPrefix(line, "face") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		cur++
		if cur == idx {
			return strings.TrimSpace(parts[0])
		}
	}
	return ""
}

// ---- WAN VLAN configuration -----------------------------------------------

func setWANVLAN(ctx context.Context, opts Options, rest, vlanID string) error {
	return postCGIForm(ctx, opts, "net-wanset.asp", url.Values{
		"Wan_Flag": {"1"},
		"VLANMode": {"TAG"},
		"vlan":     {vlanID},
	})
}

func setWANVLANMode(ctx context.Context, opts Options, rest, mode string) error {
	return postCGIForm(ctx, opts, "net-wanset.asp", url.Values{
		"Wan_Flag": {"1"},
		"VLANMode": {mode},
	})
}

func setWANMode(ctx context.Context, opts Options, rest, mode string) error {
	return postCGIForm(ctx, opts, "net-wanset.asp", url.Values{
		"Wan_Flag": {"1"},
		"wanMode":  {mode},
	})
}

// ---- Network config backup ------------------------------------------------

func backupNetworkConfig(ctx context.Context, input *wusp.Message) error {
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var sb strings.Builder
	sb.WriteString("# ONU Network Configuration Backup\n")
	sb.WriteString("# Generated: " + time.Now().UTC().Format(time.RFC3339) + "\n\n")

	// resolv.conf
	for _, path := range []string{"/tmp/resolv.conf", "/tmp/etc/resolv.conf", "/usr/etc/resolv.conf", "/etc/resolv.conf"} {
		if data := readFile(path); data != "" {
			sb.WriteString("## DNS (" + path + ")\n")
			sb.WriteString(data + "\n\n")
			break
		}
	}

	// Routes
	if out, err := exec.CommandContext(tctx, "route", "-n").Output(); err == nil {
		sb.WriteString("## Routes\n")
		sb.WriteString(string(out) + "\n")
	}

	// iptables: try iptables-save, fall back to iptables -S
	for _, table := range []string{"filter", "nat", "mangle"} {
		out, err := exec.CommandContext(tctx, "iptables-save", "-t", table).Output()
		if err != nil {
			out, err = exec.CommandContext(tctx, "iptables", "-t", table, "-S").Output()
		}
		if err == nil {
			sb.WriteString("## iptables " + table + "\n")
			sb.WriteString(string(out) + "\n")
		}
	}

	// Network interfaces
	if out, err := exec.CommandContext(tctx, "ifconfig", "-a").Output(); err == nil {
		sb.WriteString("## Interfaces\n")
		sb.WriteString(string(out) + "\n")
	}

	if input != nil {
		input.Set(wusp.WUSPONUPrefix+"Network.Config", wusp.String(sb.String()))
	}
	return nil
}
