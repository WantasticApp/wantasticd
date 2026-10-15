//go:build darwin
// +build darwin

package netctl

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// darwinController uses BSD route sockets and ifconfig for network control.
// WiFi uses CoreWLAN when built with -tags netctl, otherwise falls back to
// system_profiler / airport CLI parsing.
type darwinController struct{}

const (
	darwinIfconfigPath = "/sbin/ifconfig"
	darwinRoutePath    = "/sbin/route"
	darwinSysctlPath   = "/usr/sbin/sysctl"
)

func newController() Controller { return &darwinController{} }

func (c *darwinController) Close() error { return nil }

func (c *darwinController) LinkSetUp(ifname string) error {
	_, err := runDarwinAdmin(darwinIfconfigPath, ifname, "up")
	return err
}

func (c *darwinController) LinkSetDown(ifname string) error {
	_, err := runDarwinAdmin(darwinIfconfigPath, ifname, "down")
	return err
}

func (c *darwinController) LinkSetMTU(ifname string, mtu int) error {
	_, err := runDarwinAdmin(darwinIfconfigPath, ifname, "mtu", fmt.Sprintf("%d", mtu))
	return err
}

func (c *darwinController) AddrAdd(ifname string, addr netip.Prefix) error {
	ip := addr.Addr().String()
	if addr.Addr().Is4() {
		_, err := runDarwinAdmin(
			darwinIfconfigPath,
			ifname,
			"inet",
			ip,
			ip,
			"netmask",
			"255.255.255.255",
			"up",
		)
		return err
	}
	bits := fmt.Sprintf("%d", addr.Bits())
	_, err := runDarwinAdmin(darwinIfconfigPath, ifname, "inet6", ip, bits, "up")
	return err
}

func (c *darwinController) AddrDel(ifname string, addr netip.Prefix) error {
	ip := addr.Addr().String()
	if addr.Addr().Is4() {
		_, err := runDarwinAdmin(darwinIfconfigPath, ifname, "inet", ip, "delete")
		return err
	}
	_, err := runDarwinAdmin(darwinIfconfigPath, ifname, "inet6", ip, "delete")
	return err
}

func (c *darwinController) RouteReplace(ifname string, dst netip.Prefix) error {
	network := dst.String()
	family := "-inet"
	if dst.Addr().Is6() {
		family = "-inet6"
	}
	// Never delete an existing route owned by another VPN. The caller tracks
	// routes it successfully adds and removes only those during shutdown.
	out, err := runDarwinAdmin(darwinRoutePath, "-n", "add", family, network, "-interface", ifname)
	if err != nil {
		return fmt.Errorf("route add: %v: %s", err, out)
	}
	return nil
}

func (c *darwinController) RouteDel(ifname string, dst netip.Prefix) error {
	network := dst.String()
	family := "-inet"
	if dst.Addr().Is6() {
		family = "-inet6"
	}
	_, err := runDarwinAdmin(darwinRoutePath, "-n", "delete", family, network, "-interface", ifname)
	return err
}

func (c *darwinController) RouteGetDefault() (string, netip.Addr, error) {
	out, err := exec.Command(darwinRoutePath, "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", netip.Addr{}, err
	}
	var ifname string
	var gateway netip.Addr
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "interface:"); ok {
			ifname = strings.TrimSpace(after)
		}
		if after, ok := strings.CutPrefix(line, "gateway:"); ok {
			gw := strings.TrimSpace(after)
			gateway, _ = netip.ParseAddr(gw)
		}
	}
	return ifname, gateway, nil
}

func (c *darwinController) WiFiGetCapabilities(ifname string) (*WiFiCapabilities, error) {
	out, err := exec.Command("/usr/sbin/system_profiler", "SPAirPortDataType").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("system_profiler: %w", err)
	}
	return parseDarwinAirportCaps(string(out))
}

// parseDarwinAirportCaps extracts WiFi capabilities from system_profiler output.
// Shared parser — iwinfo_darwin.go delegates here via netctl.
func parseDarwinAirportCaps(data string) (*WiFiCapabilities, error) {
	caps := &WiFiCapabilities{}
	if strings.Contains(data, "802.11be") || strings.Contains(data, "Wi-Fi 7") {
		caps.EHT = true
		caps.SupportedHTModes = append(caps.SupportedHTModes, "EHT20", "EHT40", "EHT80", "EHT160", "EHT320")
	}
	if strings.Contains(data, "802.11ax") || strings.Contains(data, "Wi-Fi 6") {
		caps.HE = true
		caps.SupportedHTModes = append(caps.SupportedHTModes, "HE20", "HE40", "HE80", "HE160")
	}
	if strings.Contains(data, "802.11ac") {
		caps.VHT = true
		caps.SupportedHTModes = append(caps.SupportedHTModes, "VHT20", "VHT40", "VHT80")
	}
	if strings.Contains(data, "802.11n") {
		caps.HT = true
		caps.SupportedHTModes = append(caps.SupportedHTModes, "HT20", "HT40")
	}
	if len(caps.SupportedHTModes) == 0 {
		return nil, fmt.Errorf("no WiFi capabilities found")
	}
	return caps, nil
}

func (c *darwinController) WiFiGetStations(ifname string) ([]WiFiStationInfo, error) {
	// macOS doesn't expose station info the same way — only via private frameworks
	return nil, nil
}

func (c *darwinController) FirewallEnsureRule(rule FirewallRule) error {
	// macOS uses pf, not iptables — not implemented in base controller
	return fmt.Errorf("pf firewall rules not implemented")
}

func (c *darwinController) FirewallDeleteRule(rule FirewallRule) error {
	return fmt.Errorf("pf firewall rules not implemented")
}

func (c *darwinController) IPForwardingSet(enabled bool) error {
	val := "0"
	if enabled {
		val = "1"
	}
	if out, err := runDarwinAdmin(darwinSysctlPath, "-w", "net.inet.ip.forwarding="+val); err != nil {
		return fmt.Errorf("sysctl ipv4: %s", out)
	}
	_, err := runDarwinAdmin(darwinSysctlPath, "-w", "net.inet6.ip6.forwarding="+val)
	return err
}

func runDarwinAdmin(path string, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return exec.Command(path, args...).CombinedOutput()
	}
	command := shellQuote(path)
	for _, arg := range args {
		command += " " + shellQuote(arg)
	}
	return exec.Command(
		"/usr/bin/osascript",
		"-e", "on run argv",
		"-e", "do shell script (item 1 of argv) with administrator privileges",
		"-e", "end run",
		command,
	).CombinedOutput()
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// Helpers
func findInterfaceByMAC(mac net.HardwareAddr) string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.HardwareAddr.String() == mac.String() {
			return iface.Name
		}
	}
	return ""
}
