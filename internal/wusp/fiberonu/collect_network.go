package fiberonu

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

const netPrefix = wusp.WUSPONUPrefix + "Network."

// CollectNetwork fills Device.WUSP_ONU.Network.* from the ONU's Linux layer:
// interfaces, routes, iptables, DHCP, DNS, WLAN radios, stations.
func CollectNetwork(ctx context.Context, opts Options, msg *wusp.Message) {
	collectInterfaces(msg)
	collectRoutes(ctx, msg)
	collectIPTables(ctx, msg)
	collectDHCP(msg)
	collectDNS(msg)
	collectWLAN(ctx, msg)
	collectWAN(ctx, opts, msg)
}

// ---- Interfaces -----------------------------------------------------------

func collectInterfaces(msg *wusp.Message) {
	data := readFile("/proc/net/dev")
	if data == "" {
		return
	}
	lines := strings.Split(data, "\n")
	idx := 1
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") || strings.HasPrefix(line, "Inter") || strings.HasPrefix(line, "face") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		row := netPrefix + "Interface." + strconv.Itoa(idx) + "."
		msg.Set(row+"Name", wusp.String(name))
		fields := strings.Fields(parts[1])
		if len(fields) >= 10 {
			if v, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
				msg.Set(row+"RxBytes", wusp.Uint(v))
			}
			if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				msg.Set(row+"RxPackets", wusp.Uint(v))
			}
			if v, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
				msg.Set(row+"RxErrors", wusp.Uint(v))
			}
			if v, err := strconv.ParseUint(fields[8], 10, 64); err == nil {
				msg.Set(row+"TxBytes", wusp.Uint(v))
			}
			if v, err := strconv.ParseUint(fields[9], 10, 64); err == nil {
				msg.Set(row+"TxPackets", wusp.Uint(v))
			}
			if v, err := strconv.ParseUint(fields[10], 10, 64); err == nil {
				msg.Set(row+"TxErrors", wusp.Uint(v))
			}
		}
		ip := ifaceIPv4(name)
		if ip != "" {
			msg.Set(row+"IPv4Address", wusp.String(ip))
		}
		mac := readFile("/sys/class/net/" + name + "/address")
		mac = strings.TrimSpace(mac)
		if mac != "" && mac != "00:00:00:00:00:00" {
			msg.Set(row+"MACAddress", wusp.String(mac))
		}
		operState := strings.TrimSpace(readFile("/sys/class/net/" + name + "/operstate"))
		if operState != "" {
			msg.Set(row+"OperState", wusp.String(operState))
		}
		mtu := strings.TrimSpace(readFile("/sys/class/net/" + name + "/mtu"))
		if v, err := strconv.ParseUint(mtu, 10, 64); err == nil {
			msg.Set(row+"MTU", wusp.Uint(v))
		}
		idx++
	}
	msg.Set(netPrefix+"InterfaceNumberOfEntries", wusp.Uint(uint64(idx-1)))
}

func ifaceIPv4(name string) string {
	data := readFile("/proc/net/fib_trie")
	if data == "" {
		return ""
	}
	lines := strings.Split(data, "\n")
	inDevice := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "/"+name) {
			inDevice = true
			continue
		}
		if inDevice && strings.HasPrefix(trimmed, "/") {
			inDevice = false
		}
		if inDevice && strings.Contains(trimmed, "/32 host LOCAL") {
			parts := strings.Fields(trimmed)
			if len(parts) > 0 {
				ip := strings.TrimPrefix(parts[0], "|--")
				ip = strings.TrimPrefix(ip, "+--")
				ip = strings.TrimSpace(ip)
				if ip != "" && !strings.HasPrefix(ip, "127.") {
					return ip
				}
			}
		}
	}
	return ""
}

// ---- Routing table --------------------------------------------------------

func collectRoutes(_ context.Context, msg *wusp.Message) {
	data := readFile("/proc/net/route")
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

// ---- iptables rules -------------------------------------------------------

func collectIPTables(ctx context.Context, msg *wusp.Message) {
	idx := 1
	for _, table := range []string{"filter", "nat", "mangle"} {
		idx = collectOneIPTable(ctx, msg, table, idx)
	}
	msg.Set(netPrefix+"Firewall.RuleNumberOfEntries", wusp.Uint(uint64(idx-1)))
}

func collectOneIPTable(ctx context.Context, msg *wusp.Message, table string, idx int) int {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Try iptables-save first; fall back to iptables -S which is available
	// on EN7528 BusyBox-based builds that ship iptables but not iptables-save.
	out, err := exec.CommandContext(tctx, "iptables-save", "-t", table).Output()
	if err != nil {
		out, err = exec.CommandContext(tctx, "iptables", "-t", table, "-S").Output()
		if err != nil {
			return idx
		}
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*") || line == "COMMIT" {
			continue
		}
		row := netPrefix + "Firewall.Rule." + strconv.Itoa(idx) + "."
		msg.Set(row+"Table", wusp.String(table))
		if strings.HasPrefix(line, ":") {
			parts := strings.Fields(line[1:])
			if len(parts) >= 2 {
				msg.Set(row+"Chain", wusp.String(parts[0]))
				msg.Set(row+"Policy", wusp.String(parts[1]))
				msg.Set(row+"Type", wusp.String("policy"))
			}
		} else if strings.HasPrefix(line, "-A") || strings.HasPrefix(line, "-P") {
			msg.Set(row+"Raw", wusp.String(line))
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				msg.Set(row+"Chain", wusp.String(parts[1]))
			}
			if strings.HasPrefix(line, "-P") {
				msg.Set(row+"Type", wusp.String("policy"))
				if len(parts) >= 3 {
					msg.Set(row+"Policy", wusp.String(parts[2]))
				}
			} else {
				msg.Set(row+"Type", wusp.String("rule"))
			}
		} else {
			continue
		}
		idx++
	}
	return idx
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

// ---- WLAN radios + stations -----------------------------------------------

func collectWLAN(ctx context.Context, msg *wusp.Message) {
	collectWLANRadios(msg)
	collectWLANStations(ctx, msg)
}

func collectWLANRadios(msg *wusp.Message) {
	entries, err := os.ReadDir("/sys/class/ieee80211")
	if err != nil {
		return
	}
	idx := 1
	for _, entry := range entries {
		name := entry.Name()
		row := netPrefix + "Radio." + strconv.Itoa(idx) + "."
		msg.Set(row+"Phy", wusp.String(name))

		phyDir := "/sys/class/ieee80211/" + name
		if ifaces, err := os.ReadDir(phyDir + "/device/net"); err == nil {
			var names []string
			for _, iface := range ifaces {
				names = append(names, iface.Name())
			}
			msg.Set(row+"Interfaces", wusp.String(strings.Join(names, ",")))
		}
		if band := readFile(phyDir + "/band"); strings.TrimSpace(band) != "" {
			msg.Set(row+"Band", wusp.String(strings.TrimSpace(band)))
		}
		idx++
	}
	msg.Set(netPrefix+"RadioNumberOfEntries", wusp.Uint(uint64(idx-1)))

	// Also enumerate wireless interfaces from /proc/net/wireless
	if data := readFile("/proc/net/wireless"); data != "" {
		lines := strings.Split(data, "\n")
		widx := 1
		for _, line := range lines[2:] {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			ifname := strings.TrimSpace(parts[0])
			row := netPrefix + "WirelessInterface." + strconv.Itoa(widx) + "."
			msg.Set(row+"Name", wusp.String(ifname))
			fields := strings.Fields(parts[1])
			if len(fields) >= 4 {
				msg.Set(row+"LinkQuality", wusp.String(fields[1]))
				msg.Set(row+"SignalLevel", wusp.String(fields[2]))
				msg.Set(row+"NoiseLevel", wusp.String(fields[3]))
			}
			widx++
		}
		msg.Set(netPrefix+"WirelessInterfaceNumberOfEntries", wusp.Uint(uint64(widx-1)))
	}
}

func collectWLANStations(ctx context.Context, msg *wusp.Message) {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ifaces := wlanInterfaces()
	stationIdx := 1
	for _, iface := range ifaces {
		// Try iw first, fall back to iwpriv (Ralink/MediaTek EN7528).
		out, err := exec.CommandContext(tctx, "iw", "dev", iface, "station", "dump").Output()
		if err != nil {
			out, err = exec.CommandContext(tctx, "iwpriv", iface, "show", "stainfo").Output()
			if err != nil {
				continue
			}
		}
		for _, block := range parseStationDump(string(out)) {
			row := netPrefix + "Station." + strconv.Itoa(stationIdx) + "."
			msg.Set(row+"Interface", wusp.String(iface))
			msg.Set(row+"MACAddress", wusp.String(block.mac))
			if block.signal != "" {
				msg.Set(row+"Signal", wusp.String(block.signal))
			}
			if block.rxRate != "" {
				msg.Set(row+"RxBitrate", wusp.String(block.rxRate))
			}
			if block.txRate != "" {
				msg.Set(row+"TxBitrate", wusp.String(block.txRate))
			}
			if block.rxBytes != 0 {
				msg.Set(row+"RxBytes", wusp.Uint(block.rxBytes))
			}
			if block.txBytes != 0 {
				msg.Set(row+"TxBytes", wusp.Uint(block.txBytes))
			}
			if block.connected != "" {
				msg.Set(row+"ConnectedTime", wusp.String(block.connected))
			}
			if block.inactive != "" {
				msg.Set(row+"InactiveTime", wusp.String(block.inactive))
			}
			stationIdx++
		}
	}
	msg.Set(netPrefix+"StationNumberOfEntries", wusp.Uint(uint64(stationIdx-1)))
}

func wlanInterfaces() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var ifaces []string
	for _, e := range entries {
		name := e.Name()
		if _, err := os.Stat("/sys/class/net/" + name + "/wireless"); err == nil {
			ifaces = append(ifaces, name)
		}
	}
	return ifaces
}

type stationInfo struct {
	mac       string
	signal    string
	rxRate    string
	txRate    string
	rxBytes   uint64
	txBytes   uint64
	connected string
	inactive  string
}

func parseStationDump(text string) []stationInfo {
	var stations []stationInfo
	var cur *stationInfo
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Station") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				stations = append(stations, stationInfo{mac: fields[1]})
				cur = &stations[len(stations)-1]
			}
			continue
		}
		if cur == nil {
			continue
		}
		if k, v, ok := splitKV(line); ok {
			switch k {
			case "signal":
				cur.signal = v
			case "signal avg":
				if cur.signal == "" {
					cur.signal = v
				}
			case "rx bitrate":
				cur.rxRate = v
			case "tx bitrate":
				cur.txRate = v
			case "rx bytes":
				cur.rxBytes, _ = strconv.ParseUint(v, 10, 64)
			case "tx bytes":
				cur.txBytes, _ = strconv.ParseUint(v, 10, 64)
			case "connected time":
				cur.connected = v
			case "inactive time":
				cur.inactive = v
			}
		}
	}
	return stations
}

func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
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
