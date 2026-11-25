package fiberonu

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

const netPrefix = wusp.WUSPONUPrefix + "Network."

// CollectNetwork fills Device.WUSP_ONU.Network.* from the ONU: interfaces
// and routes from the kernel, the Wi-Fi radios, SSIDs and the firewall
// configuration from the firmware's config tree (tcapi), stations from the
// Wi-Fi driver, DHCP, DNS and WAN. Every source is a read; nothing here
// scans, sets or runs on its own timer.
func CollectNetwork(ctx context.Context, opts Options, msg *wusp.Message) {
	collectNetwork(ctx, opts, msg)
}

// collectNetwork is CollectNetwork returning the MediaTek WLAN reads (nil on
// a mac80211 build), which CollectONU republishes as TR-181 Device.WiFi.
func collectNetwork(ctx context.Context, opts Options, msg *wusp.Message) *wlanSnapshot {
	routeText := readFile(filepath.Join(opts.procNetDir(), "route"))
	collectInterfaces(opts, routeText, msg)
	collectRoutes(routeText, msg)
	tc, done := newTcapi(ctx, opts)
	defer done()
	collectFirewall(ctx, opts, tc, msg)
	collectDHCP(msg)
	collectDNS(msg)
	wlan := collectWLAN(ctx, opts, tc, msg)
	collectWAN(ctx, opts, msg)
	return wlan
}

// ---- Interfaces -----------------------------------------------------------
//
// One row per /proc/net/dev line, in that order: Interface.{i}.Enable
// resolves its interface by the same enumeration (resolveIfaceByIndex), so
// the console's row and the setter always mean the same interface. The
// console sorts and groups by Role; the agent never reorders.

// Interface roles. An ECNT ONU lists ~30 interfaces; only a handful carry
// subscriber traffic.
const (
	roleUplink    = "uplink"     // nas*/ppp* WAN connections, and whatever holds the default route
	roleLANBridge = "lan_bridge" // br*: the LAN bridge (management address lives here)
	roleLANPort   = "lan_port"   // eth0.N: one physical LAN port per VLAN sub-interface
	roleWiFi      = "wifi"       // ra*/rai*: one interface per SSID (MediaTek/Ralink driver)
	roleInternal  = "internal"   // lo, omci, oam, pon, sit0, imq*, wds*, wan_int*/lan_int*, eth0 ...
)

type ifaceCounters struct {
	name                         string
	rxBytes, rxPackets, rxErrors uint64
	txBytes, txPackets, txErrors uint64
	counters                     bool
}

// parseProcNetDev returns the interfaces of /proc/net/dev in file order.
// Each line is "name: rx bytes packets errs drop fifo frame compressed
// multicast tx bytes packets errs drop fifo colls carrier compressed".
func parseProcNetDev(text string) []ifaceCounters {
	var out []ifaceCounters
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") || strings.HasPrefix(line, "Inter") || strings.HasPrefix(line, "face") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		row := ifaceCounters{name: name}
		fields := strings.Fields(parts[1])
		if len(fields) >= 11 {
			vals := make([]uint64, 11)
			ok := true
			for i := range vals {
				v, err := strconv.ParseUint(fields[i], 10, 64)
				if err != nil {
					ok = false
					break
				}
				vals[i] = v
			}
			if ok {
				row.rxBytes, row.rxPackets, row.rxErrors = vals[0], vals[1], vals[2]
				row.txBytes, row.txPackets, row.txErrors = vals[8], vals[9], vals[10]
				row.counters = true
			}
		}
		out = append(out, row)
	}
	return out
}

// defaultRouteIfaces names the interfaces carrying a default route in
// /proc/net/route (destination and mask 00000000).
func defaultRouteIfaces(routeText string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(routeText, "\n") {
		f := strings.Fields(line)
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			out[f[0]] = true
		}
	}
	return out
}

// interfaceRole classifies an ECNT ONU interface name. The names come from
// the firmware: rcS creates br0 over eth0/eth1, eth0.1..eth0.8 per LAN
// port, nas0_0/nas10 and ppp%d for WAN connections (libcfg_clisvc
// "nas%d_%d", "ppp%d"), and libwlan_svc brings up ra%d (2.4 GHz SSIDs) and
// rai%d (5 GHz SSIDs).
func interfaceRole(name string, defaultRoute bool) string {
	switch {
	case defaultRoute:
		return roleUplink
	case reUplink.MatchString(name):
		return roleUplink
	case reBridge.MatchString(name):
		return roleLANBridge
	case reLANPort.MatchString(name):
		return roleLANPort
	case reWiFi.MatchString(name):
		return roleWiFi
	default:
		return roleInternal
	}
}

var (
	reUplink  = regexp.MustCompile(`^(nas\d+(_\d+)?(\.\d+)?|ppp\d+)$`)
	reBridge  = regexp.MustCompile(`^br\d+$`)
	reLANPort = regexp.MustCompile(`^eth\d+\.(\d+)$`)
	reWiFi    = regexp.MustCompile(`^(ra|rai|apcli|apclii)\d+$`)
)

// lanPortNumber is N of eth0.N, the LAN port the VLAN sub-interface serves.
func lanPortNumber(name string) (uint64, bool) {
	m := reLANPort.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	return n, err == nil
}

// ifaceControllable says whether the console may offer an up/down switch.
// Only LAN ports and Wi-Fi interfaces qualify: turning off lo, omci, the
// management bridge or the uplink cuts the ONU (and this agent) off.
func ifaceControllable(role string, defaultRoute bool) bool {
	return !defaultRoute && (role == roleLANPort || role == roleWiFi)
}

// netlinkIPv4 returns each interface's IPv4 addresses in CIDR form, asking
// the kernel over netlink (RTM_GETADDR) instead of guessing from
// /proc/net/fib_trie, which never names interfaces.
func netlinkIPv4() (map[string][]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				out[ifc.Name] = append(out[ifc.Name], ipnet.String())
			}
		}
	}
	return out, nil
}

func (o Options) ifaceAddrs() map[string][]string {
	src := o.IfaceAddrs
	if src == nil {
		src = netlinkIPv4
	}
	addrs, err := src()
	if err != nil {
		return nil
	}
	return addrs
}

func collectInterfaces(opts Options, routeText string, msg *wusp.Message) {
	data := readFile(filepath.Join(opts.procNetDir(), "dev"))
	if data == "" {
		return
	}
	addrs := opts.ifaceAddrs()
	defaults := defaultRouteIfaces(routeText)
	sys := opts.sysClassNetDir()
	rows := parseProcNetDev(data)
	for i, r := range rows {
		row := netPrefix + "Interface." + strconv.Itoa(i+1) + "."
		msg.Set(row+"Name", wusp.String(r.name))
		if r.counters {
			msg.Set(row+"RxBytes", wusp.Uint(r.rxBytes))
			msg.Set(row+"RxPackets", wusp.Uint(r.rxPackets))
			msg.Set(row+"RxErrors", wusp.Uint(r.rxErrors))
			msg.Set(row+"TxBytes", wusp.Uint(r.txBytes))
			msg.Set(row+"TxPackets", wusp.Uint(r.txPackets))
			msg.Set(row+"TxErrors", wusp.Uint(r.txErrors))
		}
		if cidrs := addrs[r.name]; len(cidrs) > 0 {
			ip, bits, _ := strings.Cut(cidrs[0], "/")
			msg.Set(row+"IPv4Address", wusp.String(ip))
			if n, err := strconv.ParseUint(bits, 10, 64); err == nil {
				msg.Set(row+"IPv4PrefixLength", wusp.Uint(n))
			}
			msg.Set(row+"IPv4Addresses", wusp.String(strings.Join(cidrs, ",")))
		}
		dir := filepath.Join(sys, r.name)
		if mac := strings.TrimSpace(readFile(filepath.Join(dir, "address"))); mac != "" && mac != "00:00:00:00:00:00" {
			msg.Set(row+"MACAddress", wusp.String(mac))
		}
		if state := strings.TrimSpace(readFile(filepath.Join(dir, "operstate"))); state != "" {
			msg.Set(row+"OperState", wusp.String(state))
		}
		if v, err := strconv.ParseUint(strings.TrimSpace(readFile(filepath.Join(dir, "mtu"))), 10, 64); err == nil {
			msg.Set(row+"MTU", wusp.Uint(v))
		}
		// IFF_UP from the flags word: the Ralink driver reports operstate
		// "unknown" even while its interfaces pass traffic.
		if v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(readFile(filepath.Join(dir, "flags"))), "0x"), 16, 64); err == nil {
			msg.Set(row+"Up", wusp.Bool(v&0x1 != 0))
		}
		if bridge := bridgeOf(dir); bridge != "" {
			msg.Set(row+"Bridge", wusp.String(bridge))
		}
		role := interfaceRole(r.name, defaults[r.name])
		msg.Set(row+"Role", wusp.String(role))
		if n, ok := lanPortNumber(r.name); ok {
			msg.Set(row+"LANPort", wusp.Uint(n))
		}
		msg.Set(row+"DefaultRoute", wusp.Bool(defaults[r.name]))
		msg.Set(row+"Controllable", wusp.Bool(ifaceControllable(role, defaults[r.name])))
	}
	msg.Set(netPrefix+"InterfaceNumberOfEntries", wusp.Uint(uint64(len(rows))))
}

// bridgeOf names the bridge an interface is a port of (sysfs brport/bridge
// or master link), "" when it is not bridged.
func bridgeOf(dir string) string {
	for _, link := range []string{"brport/bridge", "master"} {
		if target, err := os.Readlink(filepath.Join(dir, link)); err == nil {
			return filepath.Base(target)
		}
	}
	return ""
}

// ---- Routing table --------------------------------------------------------

func collectRoutes(data string, msg *wusp.Message) {
	if data == "" {
		return
	}
	lines := strings.Split(data, "\n")
	idx := 1
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		row := netPrefix + "Route." + strconv.Itoa(idx) + "."
		msg.Set(row+"Interface", wusp.String(fields[0]))
		msg.Set(row+"Destination", wusp.String(hexToIP(fields[1])))
		msg.Set(row+"Gateway", wusp.String(hexToIP(fields[2])))
		if flags, err := strconv.ParseUint(fields[3], 16, 32); err == nil {
			msg.Set(row+"Flags", wusp.Uint(flags))
		}
		msg.Set(row+"Mask", wusp.String(hexToIP(fields[7])))
		if metric, err := strconv.ParseUint(fields[6], 10, 64); err == nil {
			msg.Set(row+"Metric", wusp.Uint(metric))
		}
		idx++
	}
	msg.Set(netPrefix+"RouteNumberOfEntries", wusp.Uint(uint64(idx-1)))
}

func hexToIP(h string) string {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return h
	}
	return fmt.Sprintf("%d.%d.%d.%d", v&0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff)
}

// ---- DHCP leases ----------------------------------------------------------

func collectDHCP(msg *wusp.Message) {
	for _, path := range []string{"/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases", "/tmp/dnsmasq.leases"} {
		if data := readFile(path); data != "" {
			parseDHCPLeases(msg, data)
			return
		}
	}
	// Try udhcpd leases
	if data := readFile("/tmp/udhcpd.leases"); data != "" {
		msg.Set(netPrefix+"DHCP.LeasesFile", wusp.String("/tmp/udhcpd.leases"))
		msg.Set(netPrefix+"DHCP.LeaseCount", wusp.Uint(0))
	}
}

func parseDHCPLeases(msg *wusp.Message, data string) {
	lines := strings.Split(strings.TrimSpace(data), "\n")
	idx := 1
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		row := netPrefix + "DHCP.Lease." + strconv.Itoa(idx) + "."
		msg.Set(row+"Expires", wusp.String(fields[0]))
		msg.Set(row+"MACAddress", wusp.String(fields[1]))
		msg.Set(row+"IPAddress", wusp.String(fields[2]))
		msg.Set(row+"Hostname", wusp.String(fields[3]))
		if len(fields) >= 5 {
			msg.Set(row+"ClientID", wusp.String(fields[4]))
		}
		idx++
	}
	msg.Set(netPrefix+"DHCP.LeaseNumberOfEntries", wusp.Uint(uint64(idx-1)))
}

// ---- DNS ------------------------------------------------------------------

func collectDNS(msg *wusp.Message) {
	data := readFile("/etc/resolv.conf")
	if data == "" {
		data = readFile("/tmp/resolv.conf")
	}
	if data == "" {
		data = readFile("/tmp/etc/resolv.conf")
	}
	if data == "" {
		data = readFile("/usr/etc/resolv.conf")
	}
	if data == "" {
		return
	}
	lines := strings.Split(data, "\n")
	idx := 1
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				msg.Set(netPrefix+"DNS.Server."+strconv.Itoa(idx)+".Address", wusp.String(fields[1]))
				idx++
			}
		} else if strings.HasPrefix(line, "search") || strings.HasPrefix(line, "domain") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				msg.Set(netPrefix+"DNS.SearchDomain", wusp.String(strings.Join(fields[1:], " ")))
			}
		}
	}
	msg.Set(netPrefix+"DNS.ServerNumberOfEntries", wusp.Uint(uint64(idx-1)))
}

// ---- WAN interfaces (uplink VLAN config, e.g. VLAN4000) ------------------

func collectWAN(ctx context.Context, opts Options, msg *wusp.Message) {
	wans := readWANInterfaces(ctx, opts)
	for i, w := range wans {
		row := netPrefix + "WAN." + strconv.Itoa(i+1) + "."
		msg.Set(row+"Name", wusp.String(w.name))
		msg.Set(row+"Active", wusp.Bool(w.active))
		msg.Set(row+"VLANMode", wusp.String(w.vlanMode))
		msg.Set(row+"VLANID", wusp.String(w.vlanID))
		msg.Set(row+"Priority", wusp.String(w.priority))
		msg.Set(row+"Mode", wusp.String(w.wanMode))
		msg.Set(row+"LinkMode", wusp.String(w.linkMode))
		msg.Set(row+"ServiceList", wusp.String(w.serviceList))
		msg.Set(row+"IPAddress", wusp.String(w.ipAddress))
		msg.Set(row+"Status", wusp.String(w.status))
		msg.Set(row+"Encapsulation", wusp.String(w.encap))
	}
	msg.Set(netPrefix+"WANNumberOfEntries", wusp.Uint(uint64(len(wans))))
}

type wanEntry struct {
	name        string
	active      bool
	vlanMode    string
	vlanID      string
	priority    string
	wanMode     string
	linkMode    string
	serviceList string
	ipAddress   string
	status      string
	encap       string
}

func readWANInterfaces(ctx context.Context, opts Options) []wanEntry {
	// Try reading WAN interfaces from ifconfig output (look for nas* or ppp* interfaces
	// which are the WAN-side interfaces on EN7528). The VLAN ID is embedded in the
	// interface name (e.g. nas0_4000 for VLAN 4000) or in /proc/tc3162/wan_info.
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var wans []wanEntry

	// Method 1: Parse ifconfig for nas*/ppp* interfaces (WAN uplinks)
	out, err := exec.CommandContext(tctx, "ifconfig", "-a").Output()
	if err != nil {
		return wans
	}

	var current *wanEntry
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				name := strings.TrimSuffix(fields[0], ":")
				if strings.HasPrefix(name, "nas") || strings.HasPrefix(name, "ppp") {
					wans = append(wans, wanEntry{name: name, active: true})
					current = &wans[len(wans)-1]
					if parts := strings.SplitN(name, "_", 2); len(parts) == 2 {
						current.vlanID = parts[1]
						current.vlanMode = "TAG"
					}
					if strings.HasPrefix(name, "ppp") {
						current.linkMode = "linkPPP"
					} else {
						current.linkMode = "linkIP"
					}
				} else {
					current = nil
				}
			}
		}
		if current == nil {
			continue
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet addr:") {
			if addr := strings.TrimPrefix(line, "inet addr:"); addr != "" {
				if f := strings.Fields(addr); len(f) > 0 {
					current.ipAddress = f[0]
				}
			}
		} else if strings.Contains(line, "inet ") {
			for _, f := range strings.Fields(line) {
				if strings.Count(f, ".") == 3 && !strings.HasPrefix(f, "255.") {
					current.ipAddress = f
					break
				}
			}
		}
		if strings.Contains(line, "UP") {
			current.status = "up"
		}
	}

	// Method 2: Try reading /proc/tc3162/wan_info for VLAN details
	if data := readFile("/proc/tc3162/wan_info"); data != "" {
		parseWANProc(data, wans)
	}

	return wans
}

func parseWANProc(data string, wans []wanEntry) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		for i := range wans {
			if wans[i].name == name {
				for _, f := range fields[1:] {
					if k, v, ok := splitKV(f); ok {
						switch strings.ToLower(k) {
						case "vlanid", "vid":
							wans[i].vlanID = v
						case "vlanmode":
							wans[i].vlanMode = v
						case "pri", "priority":
							wans[i].priority = v
						case "mode":
							wans[i].wanMode = v
						case "service":
							wans[i].serviceList = v
						case "encap":
							wans[i].encap = v
						}
					}
				}
				break
			}
		}
	}
}
