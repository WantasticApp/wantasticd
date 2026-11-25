package fiberonu

import (
	"context"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// ---- Firewall ---------------------------------------------------------------
//
// The ONU's firewall is its own configuration, set on the web pages
// sec-firewall / sec-macfilter / sec-portfilter / sec-urlfilter /
// sec-protocolfilter, and read here from the same config tree:
//
//	Firewall_Entry               firewall_status, firewall_level, spi_status
//	Firewall_DoSEntry            Enable (Yes/No)
//	Firewall_PortScanEntry       Enable (Yes/No)
//	Firewall_IPv6SessionEntry    Enable (Yes/No)
//	IpMacFilter_Common           ActiveMac, ListTypeMac, ActivePortIn,
//	                             ActivePortOut, ListTypeIpDown, ListTypeIpUp
//	UrlFilter_Common             Activate, Filter_Policy (0 black, 1 white)
//	IpMacFilter_EtherTypeFilter  P0..P11 (LAN1-4, SSID1-8: blocked protocols)
//
// The rule lists come the way the firmware's own list pages get them:
// reading IpMacFilter mac_num / ipup_num / ipdown_num and UrlFilter Url_num
// makes cfg_manager write /tmp/macvalid, /tmp/ipupvalid, /tmp/ipdownvalid
// and /tmp/urladdr (one field per line), which sec_macfilterlist.cgi,
// sec_portfilteroutlist.cgi, sec_portfilterinlist.cgi and
// sec_urlfilterlist.cgi then parse. The record layouts below are those
// scripts' layouts. The iptables listing stays as a secondary raw view.

// macFilterFields is sec_macfilterlist.cgi's record: index, MacName,
// MacAddr, Active (Yes/No), Interface.
const macFilterFields = 5

// Port filter records (sec_portfilter*list.cgi): 11 lines, or 15 when
// WebCustom_Entry isCMCCSupported is Yes (adds the range ends).
const (
	portFilterFields     = 11
	portFilterFieldsCMCC = 15
)

// protocolFilterPorts maps IpMacFilter_EtherTypeFilter P<n> to its port, as
// sec-protocolfilter.asp's getEntryIndex does (LAN1-4 → P0-3, SSIDn → Pn+3).
var protocolFilterPorts = []string{"LAN1", "LAN2", "LAN3", "LAN4", "SSID1", "SSID2", "SSID3", "SSID4", "SSID5", "SSID6", "SSID7", "SSID8"}

func collectFirewall(ctx context.Context, opts Options, tc *tcapiReader, msg *wusp.Message) {
	if tc != nil {
		collectFirewallConfig(opts, tc, msg)
	}
	collectIPTables(ctx, opts, msg)
}

func yesNo(v string) (bool, bool) {
	switch strings.ToLower(v) {
	case "yes", "1", "true":
		return true, true
	case "no", "0", "false":
		return false, true
	}
	return false, false
}

func setFlag(msg *wusp.Message, path, v string) {
	if b, ok := yesNo(v); ok {
		msg.Set(path, wusp.Bool(b))
	}
}

// listMode turns Black/White (any case) into black/white.
func listMode(v string) string {
	switch strings.ToLower(v) {
	case "black":
		return "black"
	case "white":
		return "white"
	}
	return ""
}

func collectFirewallConfig(opts Options, tc *tcapiReader, msg *wusp.Message) {
	fw := netPrefix + "Firewall."
	setFlag(msg, fw+"Enable", tc.get("Firewall_Entry", "firewall_status"))
	if v := strings.ToLower(tc.get("Firewall_Entry", "firewall_level")); v == "low" || v == "medium" || v == "high" {
		msg.Set(fw+"Level", wusp.String(v))
	}
	setFlag(msg, fw+"SPIEnable", tc.get("Firewall_Entry", "spi_status"))
	setFlag(msg, fw+"DoSProtection", tc.get("Firewall_DoSEntry", "Enable"))
	setFlag(msg, fw+"PortScanProtection", tc.get("Firewall_PortScanEntry", "Enable"))
	setFlag(msg, fw+"IPv6SessionProtection", tc.get("Firewall_IPv6SessionEntry", "Enable"))

	// MAC filter.
	setFlag(msg, fw+"MACFilter.Enable", tc.get("IpMacFilter_Common", "ActiveMac"))
	if m := listMode(tc.get("IpMacFilter_Common", "ListTypeMac")); m != "" {
		msg.Set(fw+"MACFilter.Mode", wusp.String(m))
	}
	asked := time.Now()
	macNum := tc.get("IpMacFilter", "mac_num")
	if lines, ok := readListFile(opts.tmpDir(), "macvalid", asked); ok || macNum == "0" {
		rules := parseMACFilterList(lines)
		for i, r := range rules {
			row := fw + "MACFilter.Rule." + strconv.Itoa(i+1) + "."
			msg.Set(row+"EntryIndex", wusp.String(r.index))
			msg.Set(row+"Name", wusp.String(r.name))
			msg.Set(row+"MACAddress", wusp.String(r.mac))
			setFlag(msg, row+"Enable", r.active)
			if r.iface != "" {
				msg.Set(row+"Interface", wusp.String(r.iface))
			}
		}
		msg.Set(fw+"MACFilter.RuleNumberOfEntries", wusp.Uint(uint64(len(rules))))
	}

	// IP/port filter: "in" is the downlink list, "out" the uplink list
	// (sec-portfilter.asp: ActivePortIn/ListTypeIpDown, ActivePortOut/
	// ListTypeIpUp; the in-list page reads /tmp/ipdownvalid).
	setFlag(msg, fw+"PortFilter.InboundEnable", tc.get("IpMacFilter_Common", "ActivePortIn"))
	if m := listMode(tc.get("IpMacFilter_Common", "ListTypeIpDown")); m != "" {
		msg.Set(fw+"PortFilter.InboundMode", wusp.String(m))
	}
	setFlag(msg, fw+"PortFilter.OutboundEnable", tc.get("IpMacFilter_Common", "ActivePortOut"))
	if m := listMode(tc.get("IpMacFilter_Common", "ListTypeIpUp")); m != "" {
		msg.Set(fw+"PortFilter.OutboundMode", wusp.String(m))
	}
	cmcc := tc.get("WebCustom_Entry", "isCMCCSupported") == "Yes"
	var portRules []portFilterRule
	portListRead := false
	for _, dir := range []struct{ direction, attr, file string }{
		{"inbound", "ipdown_num", "ipdownvalid"},
		{"outbound", "ipup_num", "ipupvalid"},
	} {
		asked := time.Now()
		num := tc.get("IpMacFilter", dir.attr)
		lines, ok := readListFile(opts.tmpDir(), dir.file, asked)
		if !ok && num != "0" {
			continue
		}
		portListRead = true
		count, _ := strconv.Atoi(num)
		portRules = append(portRules, parsePortFilterList(lines, dir.direction, count, cmcc)...)
	}
	if portListRead {
		for i, r := range portRules {
			row := fw + "PortFilter.Rule." + strconv.Itoa(i+1) + "."
			msg.Set(row+"EntryIndex", wusp.String(r.index))
			msg.Set(row+"Direction", wusp.String(r.direction))
			msg.Set(row+"Name", wusp.String(r.name))
			setFlag(msg, row+"Enable", r.active)
			for _, kv := range [][2]string{
				{"Interface", r.iface}, {"Protocol", r.protocol},
				{"SourceIP", r.srcIP}, {"SourceIPEnd", r.srcIPEnd}, {"SourceMask", r.srcMask},
				{"SourcePort", r.srcPort}, {"SourcePortEnd", r.srcPortEnd},
				{"DestIP", r.dstIP}, {"DestIPEnd", r.dstIPEnd}, {"DestMask", r.dstMask},
				{"DestPort", r.dstPort}, {"DestPortEnd", r.dstPortEnd},
			} {
				if kv[1] != "" {
					msg.Set(row+kv[0], wusp.String(kv[1]))
				}
			}
		}
		msg.Set(fw+"PortFilter.RuleNumberOfEntries", wusp.Uint(uint64(len(portRules))))
	}

	// URL filter.
	setFlag(msg, fw+"URLFilter.Enable", tc.get("UrlFilter_Common", "Activate"))
	switch tc.get("UrlFilter_Common", "Filter_Policy") {
	case "0":
		msg.Set(fw+"URLFilter.Mode", wusp.String("black"))
	case "1":
		msg.Set(fw+"URLFilter.Mode", wusp.String("white"))
	}
	asked = time.Now()
	urlNum := tc.get("UrlFilter", "Url_num")
	if lines, ok := readListFile(opts.tmpDir(), "urladdr", asked); ok || urlNum == "0" {
		urls := parseURLFilterList(lines)
		for i, u := range urls {
			row := fw + "URLFilter.Rule." + strconv.Itoa(i+1) + "."
			msg.Set(row+"EntryIndex", wusp.String(u[0]))
			msg.Set(row+"URL", wusp.String(u[1]))
		}
		msg.Set(fw+"URLFilter.RuleNumberOfEntries", wusp.Uint(uint64(len(urls))))
	}

	// Protocol (ethertype) filter per LAN port / SSID; only ports with a
	// blocked protocol are listed.
	n := 0
	for i, port := range protocolFilterPorts {
		blocked := tc.get("IpMacFilter_EtherTypeFilter", "P"+strconv.Itoa(i))
		if blocked == "" {
			continue
		}
		n++
		row := fw + "ProtocolFilter.Rule." + strconv.Itoa(n) + "."
		msg.Set(row+"Port", wusp.String(port))
		msg.Set(row+"Blocked", wusp.String(blocked))
	}
	msg.Set(fw+"ProtocolFilter.RuleNumberOfEntries", wusp.Uint(uint64(n)))

	collectFirewallCapabilities(opts, tc, cmcc, msg)
}

type macFilterRule struct{ index, name, mac, active, iface string }

func parseMACFilterList(lines []string) []macFilterRule {
	var out []macFilterRule
	for i := 0; i+macFilterFields <= len(lines); i += macFilterFields {
		r := lines[i : i+macFilterFields]
		out = append(out, macFilterRule{index: r[0], name: r[1], mac: r[2], active: r[3], iface: r[4]})
	}
	return out
}

type portFilterRule struct {
	index, direction, name, active, iface, protocol string
	srcIP, srcIPEnd, srcMask, srcPort, srcPortEnd   string
	dstIP, dstIPEnd, dstMask, dstPort, dstPortEnd   string
}

// parsePortFilterList splits a port-filter list file. The record is 11 or
// 15 lines; the reported count decides when it divides the file exactly,
// isCMCCSupported (what the cgi scripts test) otherwise.
func parsePortFilterList(lines []string, direction string, count int, cmcc bool) []portFilterRule {
	size := portFilterFields
	if cmcc {
		size = portFilterFieldsCMCC
	}
	if count > 0 {
		switch len(lines) {
		case count * portFilterFields:
			size = portFilterFields
		case count * portFilterFieldsCMCC:
			size = portFilterFieldsCMCC
		}
	}
	var out []portFilterRule
	for i := 0; i+size <= len(lines); i += size {
		r := lines[i : i+size]
		rule := portFilterRule{
			index: r[0], direction: direction, active: r[1], iface: r[2], name: r[3], protocol: r[4],
			srcIP: r[5], srcMask: r[6], srcPort: r[7], dstIP: r[8], dstMask: r[9], dstPort: r[10],
		}
		if size == portFilterFieldsCMCC {
			// sec_portfilterinlist.cgi: 11 SrcIPEndAddr, 12 DesIPEndAddr,
			// 13 SrcPortEnd, 14 DesPortEnd.
			rule.srcIPEnd, rule.dstIPEnd, rule.srcPortEnd, rule.dstPortEnd = r[11], r[12], r[13], r[14]
		}
		out = append(out, rule)
	}
	return out
}

// parseURLFilterList splits /tmp/urladdr: index then URL per entry.
func parseURLFilterList(lines []string) [][2]string {
	var out [][2]string
	for i := 0; i+2 <= len(lines); i += 2 {
		if lines[i+1] == "" {
			continue
		}
		out = append(out, [2]string{lines[i], lines[i+1]})
	}
	return out
}

// ---- iptables (raw view) ------------------------------------------------------
//
// The firmware ships /usr/bin/iptables (with --list-rules/-S) but no
// iptables-save, so -S is tried first.

func collectIPTables(ctx context.Context, opts Options, msg *wusp.Message) {
	idx := 1
	ran := false
	for _, table := range []string{"filter", "nat", "mangle"} {
		out, err := opts.run(ctx, "iptables", "-t", table, "-S")
		if err != nil {
			out, err = opts.run(ctx, "iptables-save", "-t", table)
			if err != nil {
				continue
			}
		}
		ran = true
		idx = parseIPTablesRules(msg, table, string(out), idx)
	}
	if ran {
		msg.Set(netPrefix+"Firewall.RuleNumberOfEntries", wusp.Uint(uint64(idx-1)))
	}
}

// parseIPTablesRules reads `iptables -S` or iptables-save output for one
// table into Firewall.Rule rows starting at idx, and returns the next idx.
func parseIPTablesRules(msg *wusp.Message, table, text string, idx int) int {
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*") || line == "COMMIT" {
			continue
		}
		row := netPrefix + "Firewall.Rule." + strconv.Itoa(idx) + "."
		switch {
		case strings.HasPrefix(line, ":"):
			parts := strings.Fields(line[1:])
			if len(parts) < 2 {
				continue
			}
			msg.Set(row+"Chain", wusp.String(parts[0]))
			msg.Set(row+"Policy", wusp.String(parts[1]))
			msg.Set(row+"Type", wusp.String("policy"))
		case strings.HasPrefix(line, "-P "):
			parts := strings.Fields(line)
			if len(parts) < 3 {
				continue
			}
			msg.Set(row+"Chain", wusp.String(parts[1]))
			msg.Set(row+"Policy", wusp.String(parts[2]))
			msg.Set(row+"Type", wusp.String("policy"))
		case strings.HasPrefix(line, "-A "):
			parts := strings.Fields(line)
			msg.Set(row+"Chain", wusp.String(parts[1]))
			msg.Set(row+"Raw", wusp.String(line))
			msg.Set(row+"Type", wusp.String("rule"))
		default:
			continue // -N user chains carry no rule of their own
		}
		msg.Set(row+"Table", wusp.String(table))
		idx++
	}
	return idx
}
