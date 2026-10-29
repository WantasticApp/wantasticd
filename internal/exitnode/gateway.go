package exitnode

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// DarwinDefaultGatewayCmd asks for the default route entry. "default" means
// destination 0.0.0.0 with mask 0, an exact lookup that the 0/1 + 128/1
// split routes do not shadow.
func DarwinDefaultGatewayCmd() Cmd {
	return Cmd{Name: "/sbin/route", Args: []string{"-n", "get", "default"}}
}

// ParseDarwinRouteGet parses `route -n get default`.
func ParseDarwinRouteGet(out string) (Gateway, error) {
	var gw Gateway
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "interface:"); ok {
			gw.Interface = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "gateway:"); ok {
			if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				gw.Addr = a
			}
		}
	}
	if gw.Interface == "" {
		return gw, fmt.Errorf("no default route")
	}
	return gw, nil
}

// ParseLinuxProcRoute picks the lowest-metric IPv4 default route from
// /proc/net/route, ignoring the tunnel interface.
func ParseLinuxProcRoute(data, tun string) (Gateway, error) {
	best := -1
	var gw Gateway
	sc := bufio.NewScanner(strings.NewReader(data))
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" || f[0] == tun {
			continue
		}
		flags, _ := strconv.ParseUint(f[3], 16, 32)
		if flags&0x1 == 0 { // RTF_UP
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		if best >= 0 && metric >= best {
			continue
		}
		raw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		best = metric
		gw = Gateway{Interface: f[0]}
		if raw != 0 {
			gw.Addr = netip.AddrFrom4([4]byte{byte(raw), byte(raw >> 8), byte(raw >> 16), byte(raw >> 24)})
		}
	}
	if best < 0 {
		return Gateway{}, fmt.Errorf("no IPv4 default route")
	}
	return gw, nil
}

// WindowsDefaultGatewayCmd prints "ifIndex nexthop alias" for the preferred
// IPv4 default route.
func WindowsDefaultGatewayCmd() Cmd {
	return Cmd{Name: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-Command",
		"Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 | ForEach-Object { \"$($_.ifIndex) $($_.NextHop) $($_.InterfaceAlias)\" }"}}
}

// ParseWindowsGateway parses WindowsDefaultGatewayCmd output.
func ParseWindowsGateway(out string) (Gateway, error) {
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) < 2 {
		return Gateway{}, fmt.Errorf("no IPv4 default route")
	}
	idx, err := strconv.Atoi(f[0])
	if err != nil || idx <= 0 {
		return Gateway{}, fmt.Errorf("bad interface index %q", f[0])
	}
	a, err := netip.ParseAddr(f[1])
	if err != nil {
		return Gateway{}, fmt.Errorf("bad next hop %q", f[1])
	}
	return Gateway{IfIndex: idx, Addr: a, Interface: strings.Join(f[2:], " ")}, nil
}

// DefaultGateway returns the current IPv4 default route outside the tunnel.
func DefaultGateway(h Host, tun string) (Gateway, error) {
	switch h.OS {
	case "darwin":
		out, err := h.Run(DarwinDefaultGatewayCmd())
		if err != nil {
			return Gateway{}, err
		}
		gw, err := ParseDarwinRouteGet(string(out))
		if err == nil && gw.Interface == tun {
			return Gateway{}, fmt.Errorf("default route points into the tunnel")
		}
		return gw, err
	case "linux":
		data, err := h.ReadFile("/proc/net/route")
		if err != nil {
			return Gateway{}, err
		}
		return ParseLinuxProcRoute(string(data), tun)
	case "windows":
		out, err := h.Run(WindowsDefaultGatewayCmd())
		if err != nil {
			return Gateway{}, err
		}
		return ParseWindowsGateway(string(out))
	}
	return Gateway{}, fmt.Errorf("default gateway lookup not supported on %s", h.OS)
}
