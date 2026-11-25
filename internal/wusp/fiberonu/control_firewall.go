package fiberonu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// ---- Firewall configuration writes ---------------------------------------------
//
// Every write mirrors what the firmware's own pages post, read from the
// extracted image (boaroot/cgi-bin/sec-firewall.asp, sec-macfilter.asp,
// sec-addmacfilter.asp, sec-portfilter.asp, sec-addportfilter.asp,
// sec-urlfilter.asp, the sec_*list.cgi scripts, lib/libcfg_clisvc.so,
// lib/libwan_related_svc.so, usr/bin/firewallcmd):
//
//   - The pages write an entry through the un-indexed node name
//     ("IpMacFilter_Entry", "UrlFilter_Entry") after storing the slot in
//     WebCurSet_Entry (ipfilter_id / url_filter_id). The config library
//     resolves the name itself (cfg_parse_entry_pvc_number reads
//     root.webcurset.entry when the name carries no number), so the same
//     strings work from the tcapi client.
//   - Slots come from the firmware: IpMacFilter add_macnum / add_ipupnum /
//     add_ipdownnum and UrlFilter add_num return the first free entry
//     (cfg_type_ipmacfilter_entry_func_get: MAC rules use entries 0-39,
//     outbound 40-79, inbound 80-119; URL entries 0-99).
//   - Deleting is not an unset: the page sets Common Action=Del and
//     DeleteIndex="<n>," and commits; the commit handler removes the listed
//     entries (DeleteFilterIndex / unset_action) and rebuilds the rules.
//   - commit IpMacFilter_Entry runs svc_wan_related_ipmacfilter_write, which
//     reads Common IpMacType (Mac / IpUp / IpDown) to pick the list to
//     rebuild, so each list is committed on its own.
//
// Only what a change names is written; the firewall page's own habit of
// clearing Firewall_Entry and re-posting every switch (including spi_status
// = 0 and the WAN web/telnet access rights) is not copied.
//
// What each setting touches, and so what can reach the agent's own path to
// the hub (an outbound connection from the ONU, replies ESTABLISHED):
//
//   - MAC, IP/port and URL filters live in macfilter_chain, ipupfilter_chain,
//     ipdownfilter_chain and url_filter_chain, which filter_forward_start.sh
//     hooks in FORWARD only (plus LAN-side ebtables rules). They filter what
//     the ONU forwards, never its own traffic.
//   - The firewall level (firewallcmd: INPUT_SPIFIREWALL) and port-scan
//     protection (INPUT_PORTSCAN) drop NEW and INVALID packets arriving on
//     any interface that is not br+. Replies to the agent's outbound tunnel
//     are ESTABLISHED and pass. A system tunnel interface is "not br+" too:
//     connections the hub opens to the ONU through it would be dropped, and
//     the firmware cannot tell them apart, so those two are refused while
//     the ONU has a TUN interface.
//
// Left out because the firmware does not prove them: SPI (spi_status has no
// reader left: its only use is commented out in wan_start.sh), per-rule
// enable (the pages always post Active=Yes), IPv6 addresses in port rules,
// the EtherType filter, port forwarding and DMZ (app-natset.asp).

const fwErr = "onu firewall: "

// Firmware limits, from the pages' own checks.
const (
	macFilterMaxRules    = 40 // sec-macfilter.asp addClick; 32 when isNPUSupported
	macFilterMaxRulesNPU = 32
	portFilterMaxRules   = 40  // sec-portfilter.asp addClick, per direction
	urlFilterMaxRules    = 100 // sec-urlfilter.asp btnAdd
	filterNameMaxLength  = 31
	urlMaxLength         = 31
)

// Entry ranges of IpMacFilter_Entry<n> (cfg_type_ipmacfilter_entry_func_get).
var filterSlotRange = map[string][2]int{"mac": {0, 40}, "outbound": {40, 80}, "inbound": {80, 120}}

// Protocol values of sec-addportfilter.asp's select; "" is its blank choice.
var portFilterProtocols = []string{"TCP/UDP", "TCP", "UDP", "ICMP", "All"}

var firewallLevels = []string{"low", "medium", "high"}

// firewallWritable is what this agent can change, reported as
// Network.Firewall.Writable.
var firewallWritable = []string{
	"Enable", "Level", "DoSProtection", "PortScanProtection", "IPv6SessionProtection",
	"MACFilter.Enable", "MACFilter.Mode", "MACFilter.Rule",
	"PortFilter.InboundEnable", "PortFilter.InboundMode", "PortFilter.OutboundEnable", "PortFilter.OutboundMode", "PortFilter.Rule",
	"URLFilter.Enable", "URLFilter.Mode", "URLFilter.Rule",
}

// firewallGuarded are the leaves refused while a system tunnel interface
// exists (see the header).
var firewallGuarded = []string{"Enable", "Level", "PortScanProtection"}

// wanIfaceName is a WAN interface name the firmware resolves itself
// (get_wanindex_by_name: sscanf "nas%1s_%1s", or ppp<n>).
var wanIfaceName = regexp.MustCompile(`^(nas[0-9]_[0-9]|ppp[0-9]{1,3})$`)

// wanInterfaces lists the WAN interfaces present on the device: the choices
// of an inbound rule's Interface.
func wanInterfaces(opts Options) []string {
	entries, err := os.ReadDir(opts.sysClassNetDir())
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if wanIfaceName.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// tunnelInterfaces lists system TUN/TAP interfaces (the kernel exposes
// tun_flags for them only).
func tunnelInterfaces(opts Options) []string {
	entries, err := os.ReadDir(opts.sysClassNetDir())
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(opts.sysClassNetDir(), e.Name(), "tun_flags")); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func macFilterLimit(tc *tcapiReader) int {
	if tc.get("WebCustom_Entry", "isNPUSupported") == "Yes" {
		return macFilterMaxRulesNPU
	}
	return macFilterMaxRules
}

// collectFirewallCapabilities reports what this agent can change and the
// limits the pages enforce. Read-only.
func collectFirewallCapabilities(opts Options, tc *tcapiReader, cmcc bool, msg *wusp.Message) {
	fw := netPrefix + "Firewall."
	msg.Set(fw+"Writable", wusp.String(strings.Join(firewallWritable, ",")))
	msg.Set(fw+"LevelsAvailable", wusp.String(strings.Join(firewallLevels, ",")))
	if len(tunnelInterfaces(opts)) > 0 {
		msg.Set(fw+"Guarded", wusp.String(strings.Join(firewallGuarded, ",")))
	}
	msg.Set(fw+"MACFilter.MaxRules", wusp.Uint(uint64(macFilterLimit(tc))))
	msg.Set(fw+"PortFilter.MaxRules", wusp.Uint(portFilterMaxRules))
	msg.Set(fw+"PortFilter.ProtocolsAvailable", wusp.String(strings.Join(portFilterProtocols, ",")))
	form := "mask"
	if cmcc {
		form = "range"
	}
	msg.Set(fw+"PortFilter.AddressForm", wusp.String(form))
	if list := wanInterfaces(opts); len(list) > 0 {
		msg.Set(fw+"PortFilter.InterfacesAvailable", wusp.String(strings.Join(list, ",")))
	}
	msg.Set(fw+"URLFilter.MaxRules", wusp.Uint(urlFilterMaxRules))
}

// ---- settings change set -----------------------------------------------------

// firewallLeaves are the Network.* relative paths Firewall.Apply() and Set
// accept.
var firewallLeaves = map[string]bool{
	"Firewall.Enable": true, "Firewall.Level": true, "Firewall.DoSProtection": true,
	"Firewall.PortScanProtection": true, "Firewall.IPv6SessionProtection": true,
	"Firewall.MACFilter.Enable": true, "Firewall.MACFilter.Mode": true,
	"Firewall.PortFilter.InboundEnable": true, "Firewall.PortFilter.InboundMode": true,
	"Firewall.PortFilter.OutboundEnable": true, "Firewall.PortFilter.OutboundMode": true,
	"Firewall.URLFilter.Enable": true, "Firewall.URLFilter.Mode": true,
}

func isFirewallConfigLeaf(rest string) bool { return firewallLeaves[rest] }

type firewallChange struct {
	bools map[string]bool
	texts map[string]string
}

func (c *firewallChange) add(rest, text string) error {
	if !firewallLeaves[rest] {
		return wusp.ErrUSPPathUnsupported
	}
	leaf := strings.TrimPrefix(rest, "Firewall.")
	if c.bools == nil {
		c.bools, c.texts = map[string]bool{}, map[string]string{}
	}
	text = strings.TrimSpace(text)
	switch {
	case leaf == "Level":
		if !contains(firewallLevels, text) {
			return fmt.Errorf(fwErr+"level %q is not offered; choose one of %s", text, strings.Join(firewallLevels, ", "))
		}
		c.texts[leaf] = text
	case strings.HasSuffix(leaf, "Mode"):
		if text != "black" && text != "white" {
			return fmt.Errorf(fwErr+"%s must be black (block the listed) or white (allow only the listed)", leaf)
		}
		c.texts[leaf] = text
	default:
		v, err := parseBoolValue(leaf, text)
		if err != nil {
			return fmt.Errorf(fwErr+"%s must be true or false", leaf)
		}
		c.bools[leaf] = *v
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// fwStep is one page submit: its sets, then its commits.
type fwStep struct {
	sets    []tcapiWrite
	commits []string
}

func onOff(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func yesNoAttr(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

// plan turns the change set into the pages' submits. Nothing is written
// here.
func (c *firewallChange) plan(opts Options, tc *tcapiReader) ([]fwStep, error) {
	if len(c.bools) == 0 && len(c.texts) == 0 {
		return nil, errors.New(fwErr + "nothing to change")
	}
	var steps []fwStep
	common := func(attr, value string) tcapiWrite {
		return tcapiWrite{node: "IpMacFilter_Common", attr: attr, value: value}
	}

	// Protection (sec-firewall.asp).
	enable, hasEnable := c.bools["Enable"]
	level, hasLevel := c.texts["Level"]
	scan, hasScan := c.bools["PortScanProtection"]
	if hasEnable || hasLevel || hasScan {
		on, _ := yesNo(tc.get("Firewall_Entry", "firewall_status"))
		if hasEnable {
			on = enable
		}
		turnsOn := (hasEnable && enable) || (hasLevel && on) || (hasScan && scan)
		if tunnels := tunnelInterfaces(opts); turnsOn && len(tunnels) > 0 {
			return nil, fmt.Errorf(fwErr+"refused: the firewall level and port-scan protection drop new connections arriving on any interface that is not the LAN bridge, and this ONU has a tunnel interface (%s) the hub may reach it through. Nothing was changed", strings.Join(tunnels, ", "))
		}
	}
	var prot fwStep
	if hasEnable {
		prot.sets = append(prot.sets, tcapiWrite{node: "Firewall_Entry", attr: "firewall_status", value: onOff(enable)})
	}
	if hasLevel {
		prot.sets = append(prot.sets, tcapiWrite{node: "Firewall_Entry", attr: "firewall_level", value: level})
	}
	if hasEnable || hasLevel {
		prot.commits = append(prot.commits, "Firewall_Entry")
	}
	for _, p := range []struct{ leaf, node string }{
		{"DoSProtection", "Firewall_DoSEntry"},
		{"PortScanProtection", "Firewall_PortScanEntry"},
		{"IPv6SessionProtection", "Firewall_IPv6SessionEntry"},
	} {
		if v, ok := c.bools[p.leaf]; ok {
			prot.sets = append(prot.sets, tcapiWrite{node: p.node, attr: "Enable", value: yesNoAttr(v)})
			prot.commits = append(prot.commits, p.node)
		}
	}
	if len(prot.sets) > 0 {
		steps = append(steps, prot)
	}

	// The three IpMacFilter lists: enable posts the switch with the list
	// type (sec-macfilter.asp Mac_Flag 2, sec-portfilter.asp Port_Flag 5/6);
	// a mode change alone posts Action=Mod with the list type (Mac_Flag 4,
	// Port_Flag 3/4).
	for _, l := range []struct {
		enableLeaf, modeLeaf, ipMacType, activeAttr, typeAttr, enableAction string
		capital                                                             bool
	}{
		{"MACFilter.Enable", "MACFilter.Mode", "Mac", "ActiveMac", "ListTypeMac", "Add", true},
		{"PortFilter.OutboundEnable", "PortFilter.OutboundMode", "IpUp", "ActivePortOut", "ListTypeIpUp", "Mod", false},
		{"PortFilter.InboundEnable", "PortFilter.InboundMode", "IpDown", "ActivePortIn", "ListTypeIpDown", "Mod", false},
	} {
		en, hasEn := c.bools[l.enableLeaf]
		mode, hasMode := c.texts[l.modeLeaf]
		if !hasEn && !hasMode {
			continue
		}
		listType := tc.get("IpMacFilter_Common", l.typeAttr)
		if hasMode {
			listType = mode
			if l.capital {
				listType = strings.ToUpper(mode[:1]) + mode[1:]
			}
		}
		var s fwStep
		switch {
		case hasEn:
			if listMode(listType) == "" {
				return nil, fmt.Errorf(fwErr+"%s: this ONU has no list mode stored; choose block-list or allow-list in the same change", l.enableLeaf)
			}
			s.sets = []tcapiWrite{
				common("IpMacType", l.ipMacType), common("Action", l.enableAction),
				common(l.activeAttr, onOff(en)), common(l.typeAttr, listType),
			}
		case l.ipMacType == "Mac":
			s.sets = []tcapiWrite{common("IpMacType", l.ipMacType), common("Action", "Mod"), common(l.typeAttr, listType)}
		default:
			s.sets = []tcapiWrite{common("Action", "Mod"), common("IpMacType", l.ipMacType), common(l.typeAttr, listType)}
		}
		s.commits = []string{"IpMacFilter_Entry"}
		steps = append(steps, s)
	}

	// URL filter (sec-urlfilter.asp Save_Flag 4 then 2).
	urlCommon := func(attr, value string) tcapiWrite {
		return tcapiWrite{node: "UrlFilter_Common", attr: attr, value: value}
	}
	if mode, ok := c.texts["URLFilter.Mode"]; ok {
		policy := "0"
		if mode == "white" {
			policy = "1"
		}
		steps = append(steps, fwStep{sets: []tcapiWrite{urlCommon("Action", "Filter"), urlCommon("Filter_Policy", policy)}, commits: []string{"UrlFilter"}})
	}
	if en, ok := c.bools["URLFilter.Enable"]; ok {
		steps = append(steps, fwStep{sets: []tcapiWrite{urlCommon("Action", "Status"), urlCommon("Activate", onOff(en))}, commits: []string{"UrlFilter"}})
	}
	return steps, nil
}

// setFirewallParam applies one firewall leaf as its own change set.
func setFirewallParam(ctx context.Context, opts Options, rest string, value wusp.Value) error {
	var change firewallChange
	if err := change.add(rest, wusp.ValueToString(value)); err != nil {
		return err
	}
	return applyFirewall(ctx, opts, &change)
}

// applyFirewallOperate runs Network.Firewall.Apply(): the input carries the
// changed settings by their own parameter paths, validated together, each
// page's group committed once, saved once.
func applyFirewallOperate(ctx context.Context, opts Options, input *wusp.Message) error {
	if input == nil || len(input.Fields) == 0 {
		return errors.New(fwErr + "Apply() needs the changed settings as input")
	}
	const prefix = wusp.WUSPONUPrefix + "Network."
	var change firewallChange
	for _, field := range input.Fields {
		rest, ok := strings.CutPrefix(strings.TrimSpace(field.Path), prefix)
		if !ok || !firewallLeaves[rest] {
			return fmt.Errorf(fwErr+"Apply() does not accept input %q", fieldPathForError(field.Path))
		}
		if err := change.add(rest, wusp.ValueToString(field.Val)); err != nil {
			return err
		}
	}
	return applyFirewall(ctx, opts, &change)
}

func applyFirewall(ctx context.Context, opts Options, change *firewallChange) error {
	tc, cancel, err := firewallTcapi(ctx, opts)
	if err != nil {
		return err
	}
	defer cancel()
	steps, err := change.plan(opts, tc)
	if err != nil {
		return err
	}
	return runFirewallSteps(ctx, opts, tc, steps)
}

func firewallTcapi(ctx context.Context, opts Options) (*tcapiReader, context.CancelFunc, error) {
	tc, cancel := newTcapi(ctx, opts)
	if tc == nil {
		cancel()
		return nil, nil, errors.New(fwErr + "the firmware configuration tool (tcapi) is not available")
	}
	return tc, cancel, nil
}

// runFirewallSteps writes validated steps: each step's sets then its
// commits, and one save at the end.
func runFirewallSteps(ctx context.Context, opts Options, tc *tcapiReader, steps []fwStep) error {
	if tc.ctx.Err() != nil {
		return errors.New(fwErr + "reading the current configuration timed out; nothing was changed")
	}
	w := &fwWriter{ctx: ctx, opts: opts}
	for _, s := range steps {
		for _, c := range s.sets {
			if err := w.run("set", c.node, c.attr, c.value); err != nil {
				return err
			}
		}
		for _, node := range s.commits {
			if err := w.run("commit", node); err != nil {
				return err
			}
		}
	}
	return w.run("save")
}

type fwWriter struct {
	ctx  context.Context
	opts Options
}

func (w *fwWriter) run(args ...string) error {
	cctx, cancel := context.WithTimeout(w.ctx, wlanCommandTimeout)
	defer cancel()
	var out []byte
	var err error
	if w.opts.Exec != nil {
		out, err = w.opts.Exec(cctx, w.opts.tcapiPath(), args...)
	} else {
		out, err = exec.CommandContext(cctx, w.opts.tcapiPath(), args...).CombinedOutput()
	}
	shown := strings.Join(args, " ")
	text := strings.TrimSpace(string(out))
	if err != nil {
		return fmt.Errorf(fwErr+"tcapi %s failed: %v: %s", shown, err, text)
	}
	for _, failure := range tcapiFailures {
		if strings.Contains(text, failure) {
			return fmt.Errorf(fwErr+"tcapi %s failed: %s", shown, text)
		}
	}
	return nil
}

// ---- rule input ----------------------------------------------------------------

// ruleInput reads an Operate input as leaf name → value. A field is named by
// the last segment of its path; a leaf outside allowed is refused.
func ruleInput(input *wusp.Message, command string, allowed ...string) (map[string]string, error) {
	out := map[string]string{}
	if input == nil {
		return out, nil
	}
	for _, f := range input.Fields {
		leaf := strings.TrimSuffix(strings.TrimSpace(f.Path), ".")
		if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
			leaf = leaf[i+1:]
		}
		if !contains(allowed, leaf) {
			return nil, fmt.Errorf(fwErr+"%s does not accept input %q", command, fieldPathForError(f.Path))
		}
		out[leaf] = strings.TrimSpace(wusp.ValueToString(f.Val))
	}
	return out, nil
}

// validFilterName is isValidName() of the pages' util.js with their length
// limit: printable ASCII above space and below '{', without the characters
// util.js lists as unsafe (quotes, angle brackets, % \ ^ [ ] ` + $ , = # & :).
func validFilterName(name string) error {
	if name == "" || len(name) > filterNameMaxLength {
		return fmt.Errorf(fwErr+"the name must be 1 to %d characters", filterNameMaxLength)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= 32 || c >= 123 || strings.IndexByte("\"<>%\\^[]`+$,='#&:", c) >= 0 {
			return errors.New(fwErr + "the name may use letters, digits and . - _ ( ) @ ! * / ; ? only, without spaces")
		}
	}
	return nil
}

// validMAC is isValidMacAddress(): six colon-separated hex pairs, not the
// broadcast address.
func validMAC(mac string) bool {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 || strings.EqualFold(mac, "ff:ff:ff:ff:ff:ff") {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		if _, err := strconv.ParseUint(p, 16, 8); err != nil {
			return false
		}
	}
	return true
}

// parseIPv4 is isValidIpAddress(): four decimal octets, the first not 0.
func parseIPv4(s string) (uint32, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var v uint32
	for i, p := range parts {
		if p == "" || len(p) > 3 {
			return 0, false
		}
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil || (i == 0 && n == 0) {
			return 0, false
		}
		v = v<<8 | uint32(n)
	}
	return v, true
}

// validHostIP is the pages' address test: empty, 0.0.0.0, or
// isAbcIpAddress() (first octet 1-223, not 127). IPv6 is not accepted here.
func validHostIP(s string) bool {
	if s == "" || s == "0.0.0.0" {
		return true
	}
	v, ok := parseIPv4(s)
	first := v >> 24
	return ok && first >= 1 && first < 224 && first != 127
}

// validMask is the pages' mask test: empty, 0.0.0.0, or a contiguous mask.
func validMask(s string) bool {
	if s == "" || s == "0.0.0.0" {
		return true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	var v uint32
	for _, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil || p == "" {
			return false
		}
		v = v<<8 | uint32(n)
	}
	inv := ^v
	return v != 0 && inv&(inv+1) == 0
}

// validPort is the pages' port test: empty, 0, or 1-65535.
func validPort(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > 65535 {
		return 0, false
	}
	return n, true
}

// ---- MAC filter rules ---------------------------------------------------------

// readList reads one of cfg_manager's list files the way the collector does:
// reading the count attribute makes cfg_manager rewrite the file.
func readList(opts Options, tc *tcapiReader, node, countAttr, file string) (lines []string, count int, err error) {
	asked := time.Now()
	num := tc.get(node, countAttr)
	lines, ok := readListFile(opts.tmpDir(), file, asked)
	if !ok && num != "0" {
		return nil, 0, errors.New(fwErr + "could not read the current rule list from the ONU; nothing was changed")
	}
	count, _ = strconv.Atoi(num)
	return lines, count, nil
}

func freeSlot(tc *tcapiReader, node, attr string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(tc.get(node, attr))
	if err != nil || n < lo || n >= hi {
		return 0, errors.New(fwErr + "the ONU reported no free rule slot; nothing was changed")
	}
	return n, nil
}

func addMACFilterRule(ctx context.Context, opts Options, input *wusp.Message) error {
	in, err := ruleInput(input, "MACFilter.AddRule()", "Name", "MACAddress")
	if err != nil {
		return err
	}
	if err := validFilterName(in["Name"]); err != nil {
		return err
	}
	if !validMAC(in["MACAddress"]) {
		return errors.New(fwErr + "the MAC address must look like AA:BB:CC:DD:EE:FF")
	}
	tc, cancel, err := firewallTcapi(ctx, opts)
	if err != nil {
		return err
	}
	defer cancel()
	lines, count, err := readList(opts, tc, "IpMacFilter", "mac_num", "macvalid")
	if err != nil {
		return err
	}
	rules := parseMACFilterList(lines)
	if limit := macFilterLimit(tc); count >= limit || len(rules) >= limit {
		return fmt.Errorf(fwErr+"the device list is full (%d rules)", limit)
	}
	for _, r := range rules {
		if strings.EqualFold(r.mac, in["MACAddress"]) {
			return fmt.Errorf(fwErr+"%s is already in the device list", in["MACAddress"])
		}
	}
	r := filterSlotRange["mac"]
	slot, err := freeSlot(tc, "IpMacFilter", "add_macnum", r[0], r[1])
	if err != nil {
		return err
	}
	entry := func(attr, value string) tcapiWrite {
		return tcapiWrite{node: "IpMacFilter_Entry", attr: attr, value: value}
	}
	// sec-addmacfilter.asp, Save_Flag = 1.
	return runFirewallSteps(ctx, opts, tc, []fwStep{{
		sets: []tcapiWrite{
			{node: "WebCurSet_Entry", attr: "ipfilter_id", value: strconv.Itoa(slot)},
			{node: "IpMacFilter_Common", attr: "Action", value: "Add"},
			{node: "IpMacFilter_Common", attr: "IpMacType", value: "Mac"},
			entry("Active", "Yes"),
			entry("RuleType", "MAC"),
			entry("MacName", in["Name"]),
			entry("MacAddr", in["MACAddress"]),
			entry("Interface", "br0"),
			entry("Direction", "Incoming"),
		},
		commits: []string{"IpMacFilter_Entry"},
	}})
}

// deleteFilterStep is the pages' delete submit (Mac_Flag 3, Port_Flag 2).
func deleteFilterStep(ipMacType string, macOrder bool, index string) fwStep {
	typ := tcapiWrite{node: "IpMacFilter_Common", attr: "IpMacType", value: ipMacType}
	act := tcapiWrite{node: "IpMacFilter_Common", attr: "Action", value: "Del"}
	del := tcapiWrite{node: "IpMacFilter_Common", attr: "DeleteIndex", value: index + ","}
	if macOrder {
		return fwStep{sets: []tcapiWrite{typ, act, del}, commits: []string{"IpMacFilter_Entry"}}
	}
	return fwStep{sets: []tcapiWrite{act, typ, del}, commits: []string{"IpMacFilter_Entry"}}
}

func entryIndexInput(in map[string]string, lo, hi int) (string, error) {
	n, err := strconv.Atoi(in["EntryIndex"])
	if err != nil || n < lo || n >= hi || strconv.Itoa(n) != in["EntryIndex"] {
		return "", errors.New(fwErr + "EntryIndex must be the entry index the ONU reported for the rule")
	}
	return in["EntryIndex"], nil
}

var errRuleMoved = errors.New(fwErr + "that rule is no longer what the console showed: refresh and try again. Nothing was changed")

func deleteMACFilterRule(ctx context.Context, opts Options, input *wusp.Message) error {
	in, err := ruleInput(input, "MACFilter.DeleteRule()", "EntryIndex", "MACAddress")
	if err != nil {
		return err
	}
	r := filterSlotRange["mac"]
	index, err := entryIndexInput(in, r[0], r[1])
	if err != nil {
		return err
	}
	tc, cancel, err := firewallTcapi(ctx, opts)
	if err != nil {
		return err
	}
	defer cancel()
	lines, _, err := readList(opts, tc, "IpMacFilter", "mac_num", "macvalid")
	if err != nil {
		return err
	}
	found := false
	for _, rule := range parseMACFilterList(lines) {
		if rule.index == index {
			found = in["MACAddress"] == "" || strings.EqualFold(rule.mac, in["MACAddress"])
		}
	}
	if !found {
		return errRuleMoved
	}
	return runFirewallSteps(ctx, opts, tc, []fwStep{deleteFilterStep("Mac", true, index)})
}

// ---- IP/port filter rules -----------------------------------------------------

var portFilterInputs = []string{
	"Direction", "Name", "Protocol", "Interface",
	"SourceIP", "SourceIPEnd", "SourceMask", "SourcePort", "SourcePortEnd",
	"DestIP", "DestIPEnd", "DestMask", "DestPort", "DestPortEnd",
}

type portFilterDir struct {
	direction, ipMacType, vendorDirection, countAttr, slotAttr, file string
}

func portFilterDirection(name string) (portFilterDir, error) {
	switch name {
	case "outbound":
		return portFilterDir{"outbound", "IpUp", "Outgoing", "ipup_num", "add_ipupnum", "ipupvalid"}, nil
	case "inbound":
		return portFilterDir{"inbound", "IpDown", "Incoming", "ipdown_num", "add_ipdownnum", "ipdownvalid"}, nil
	}
	return portFilterDir{}, errors.New(fwErr + "Direction must be inbound or outbound")
}

// validatePortFilterRule is checkForm() of sec-addportfilter.asp, IPv4 only.
func validatePortFilterRule(in map[string]string, inbound, cmcc bool, wans []string) error {
	if err := validFilterName(in["Name"]); err != nil {
		return err
	}
	if in["Protocol"] != "" && !contains(portFilterProtocols, in["Protocol"]) {
		return fmt.Errorf(fwErr+"protocol %q is not offered; choose one of %s, or leave it empty", in["Protocol"], strings.Join(portFilterProtocols, ", "))
	}
	if cmcc && (in["SourceMask"] != "" || in["DestMask"] != "") {
		return errors.New(fwErr + "this firmware takes address ranges, not masks")
	}
	if !cmcc && (in["SourceIPEnd"] != "" || in["DestIPEnd"] != "" || in["SourcePortEnd"] != "" || in["DestPortEnd"] != "") {
		return errors.New(fwErr + "this firmware takes single addresses with a mask and single ports, not ranges")
	}
	if inbound {
		if in["Protocol"] == "" && in["SourceIP"] == "" && in["SourceMask"] == "" && in["SourcePort"] == "" && in["DestPort"] == "" {
			return errors.New(fwErr + "fill at least one of protocol, source address, source port or destination port")
		}
		if !contains(wans, in["Interface"]) {
			if len(wans) == 0 {
				return errors.New(fwErr + "no WAN connection is present for an inbound rule")
			}
			return fmt.Errorf(fwErr+"Interface must be one of this ONU's WAN connections: %s", strings.Join(wans, ", "))
		}
	} else {
		if in["Interface"] != "" {
			return errors.New(fwErr + "an outbound rule takes no interface")
		}
		if in["Protocol"] == "" && in["SourceIP"] == "" && in["SourceMask"] == "" && in["SourcePort"] == "" && in["DestIP"] == "" && in["DestMask"] == "" && in["DestPort"] == "" {
			return errors.New(fwErr + "fill at least one of protocol, addresses or ports")
		}
	}
	for _, side := range []struct{ label, ip, end, mask, port, portEnd string }{
		{"source", "SourceIP", "SourceIPEnd", "SourceMask", "SourcePort", "SourcePortEnd"},
		{"destination", "DestIP", "DestIPEnd", "DestMask", "DestPort", "DestPortEnd"},
	} {
		if !validHostIP(in[side.ip]) {
			return fmt.Errorf(fwErr+"the %s address %q is not a valid IPv4 address", side.label, in[side.ip])
		}
		if in[side.end] != "" {
			if in[side.ip] == "" {
				return fmt.Errorf(fwErr+"the %s range needs a start address", side.label)
			}
			if !validHostIP(in[side.end]) {
				return fmt.Errorf(fwErr+"the %s range end %q is not a valid IPv4 address", side.label, in[side.end])
			}
			a, _ := parseIPv4(in[side.ip])
			b, _ := parseIPv4(in[side.end])
			if in[side.end] != "0.0.0.0" && b < a {
				return fmt.Errorf(fwErr+"the %s range ends before it starts", side.label)
			}
		}
		if !validMask(in[side.mask]) {
			return fmt.Errorf(fwErr+"the %s mask %q is not a valid subnet mask", side.label, in[side.mask])
		}
		if in[side.mask] != "" && in[side.ip] == "" {
			return fmt.Errorf(fwErr+"the %s mask needs an address", side.label)
		}
		start, ok := validPort(in[side.port])
		if !ok {
			return fmt.Errorf(fwErr+"the %s port %q must be 1 to 65535", side.label, in[side.port])
		}
		if in[side.portEnd] != "" {
			end, ok := validPort(in[side.portEnd])
			if !ok {
				return fmt.Errorf(fwErr+"the %s port range end %q must be 1 to 65535", side.label, in[side.portEnd])
			}
			if in[side.port] == "" {
				return fmt.Errorf(fwErr+"the %s port range needs a start port", side.label)
			}
			if end != 0 && end < start {
				return fmt.Errorf(fwErr+"the %s port range ends before it starts", side.label)
			}
		}
	}
	if in["SourcePort"] != "" || in["DestPort"] != "" {
		if p := in["Protocol"]; p != "TCP/UDP" && p != "TCP" && p != "UDP" {
			return errors.New(fwErr + "ports need protocol TCP, UDP or TCP/UDP")
		}
	}
	return nil
}

func addPortFilterRule(ctx context.Context, opts Options, input *wusp.Message) error {
	in, err := ruleInput(input, "PortFilter.AddRule()", portFilterInputs...)
	if err != nil {
		return err
	}
	dir, err := portFilterDirection(in["Direction"])
	if err != nil {
		return err
	}
	tc, cancel, err := firewallTcapi(ctx, opts)
	if err != nil {
		return err
	}
	defer cancel()
	inbound := dir.direction == "inbound"
	cmcc := tc.get("WebCustom_Entry", "isCMCCSupported") == "Yes"
	if err := validatePortFilterRule(in, inbound, cmcc, wanInterfaces(opts)); err != nil {
		return err
	}
	lines, count, err := readList(opts, tc, "IpMacFilter", dir.countAttr, dir.file)
	if err != nil {
		return err
	}
	rules := parsePortFilterList(lines, dir.direction, count, cmcc)
	if count >= portFilterMaxRules || len(rules) >= portFilterMaxRules {
		return fmt.Errorf(fwErr+"the %s rule list is full (%d rules)", dir.direction, portFilterMaxRules)
	}
	for _, r := range rules {
		if r.protocol == in["Protocol"] && r.srcIP == in["SourceIP"] && r.srcMask == in["SourceMask"] && r.srcPort == in["SourcePort"] &&
			r.dstIP == in["DestIP"] && r.dstMask == in["DestMask"] && r.dstPort == in["DestPort"] && (!inbound || r.iface == in["Interface"]) {
			return fmt.Errorf(fwErr+"an identical rule already exists (%s)", r.name)
		}
	}
	r := filterSlotRange[dir.direction]
	slot, err := freeSlot(tc, "IpMacFilter", dir.slotAttr, r[0], r[1])
	if err != nil {
		return err
	}
	iface := "br0"
	if inbound {
		iface = in["Interface"]
	}
	entry := func(attr, value string) tcapiWrite {
		return tcapiWrite{node: "IpMacFilter_Entry", attr: attr, value: value}
	}
	// sec-addportfilter.asp, Save_Flag = 1. Empty fields are posted empty.
	sets := []tcapiWrite{
		{node: "WebCurSet_Entry", attr: "ipfilter_id", value: strconv.Itoa(slot)},
		{node: "IpMacFilter_Common", attr: "IpMacType", value: dir.ipMacType},
		{node: "IpMacFilter_Common", attr: "Action", value: "Add"},
		entry("Interface", iface),
		entry("Direction", dir.vendorDirection),
		entry("Active", "Yes"),
		entry("RuleType", "IP"),
		entry("IPName", in["Name"]),
		entry("Protocol", in["Protocol"]),
		entry("SrcIPAddr", in["SourceIP"]),
		entry("SrcIPMask", in["SourceMask"]),
		entry("SrcPort", in["SourcePort"]),
		entry("DesIPAddr", in["DestIP"]),
		entry("DesIPMask", in["DestMask"]),
		entry("DesPort", in["DestPort"]),
	}
	if cmcc {
		sets = append(sets,
			entry("SrcIPEndAddr", in["SourceIPEnd"]),
			entry("DesIPEndAddr", in["DestIPEnd"]),
			entry("SrcPortEnd", in["SourcePortEnd"]),
			entry("DesPortEnd", in["DestPortEnd"]),
		)
	}
	return runFirewallSteps(ctx, opts, tc, []fwStep{{sets: sets, commits: []string{"IpMacFilter_Entry"}}})
}

func deletePortFilterRule(ctx context.Context, opts Options, input *wusp.Message) error {
	in, err := ruleInput(input, "PortFilter.DeleteRule()", "Direction", "EntryIndex", "Name")
	if err != nil {
		return err
	}
	dir, err := portFilterDirection(in["Direction"])
	if err != nil {
		return err
	}
	r := filterSlotRange[dir.direction]
	index, err := entryIndexInput(in, r[0], r[1])
	if err != nil {
		return err
	}
	tc, cancel, err := firewallTcapi(ctx, opts)
	if err != nil {
		return err
	}
	defer cancel()
	cmcc := tc.get("WebCustom_Entry", "isCMCCSupported") == "Yes"
	lines, count, err := readList(opts, tc, "IpMacFilter", dir.countAttr, dir.file)
	if err != nil {
		return err
	}
	found := false
	for _, rule := range parsePortFilterList(lines, dir.direction, count, cmcc) {
		if rule.index == index {
			found = in["Name"] == "" || rule.name == in["Name"]
		}
	}
	if !found {
		return errRuleMoved
	}
	return runFirewallSteps(ctx, opts, tc, []fwStep{deleteFilterStep(dir.ipMacType, false, index)})
}

// ---- URL filter entries -------------------------------------------------------

// urlFilterReserved are the values isValidUrlName() of sec-urlfilter.asp
// refuses outright.
var urlFilterReserved = []string{"www", "com", "org", "net", "edu", "www.", ".com", ".org", ".net", ".edu"}

// cleanFilterURL strips a scheme as the page's btnAdd does and applies its
// checks: 3 to 31 printable ASCII characters, no backslash or space.
func cleanFilterURL(raw string) (string, error) {
	u := raw
	for _, scheme := range []string{"https://", "http://"} {
		if len(u) >= len(scheme) && strings.EqualFold(u[:len(scheme)], scheme) {
			u = u[len(scheme):]
			break
		}
	}
	if len(u) < 3 || len(u) > urlMaxLength {
		return "", fmt.Errorf(fwErr+"the address must be 3 to %d characters, without http:// or https://", urlMaxLength)
	}
	for i := 0; i < len(u); i++ {
		if u[i] <= 0x20 || u[i] > 0x7e || u[i] == '\\' {
			return "", errors.New(fwErr + "the address must use printable ASCII characters only, without spaces or backslashes")
		}
	}
	if contains(urlFilterReserved, strings.ToLower(u)) {
		return "", fmt.Errorf(fwErr+"%q is not a website address", u)
	}
	return u, nil
}

func addURLFilterRule(ctx context.Context, opts Options, input *wusp.Message) error {
	in, err := ruleInput(input, "URLFilter.AddRule()", "URL")
	if err != nil {
		return err
	}
	u, err := cleanFilterURL(in["URL"])
	if err != nil {
		return err
	}
	tc, cancel, err := firewallTcapi(ctx, opts)
	if err != nil {
		return err
	}
	defer cancel()
	// The page offers its add box only while the filter is on, and posts
	// the filter's own switch as the entry's Activate.
	if on, _ := yesNo(tc.get("UrlFilter_Common", "Activate")); !on {
		return errors.New(fwErr + "turn the website filter on before adding an address")
	}
	lines, count, err := readList(opts, tc, "UrlFilter", "Url_num", "urladdr")
	if err != nil {
		return err
	}
	urls := parseURLFilterList(lines)
	if count >= urlFilterMaxRules || len(urls) >= urlFilterMaxRules {
		return fmt.Errorf(fwErr+"the website list is full (%d addresses)", urlFilterMaxRules)
	}
	for _, existing := range urls {
		if strings.EqualFold(existing[1], u) {
			return fmt.Errorf(fwErr+"%s is already in the website list", u)
		}
	}
	slot, err := freeSlot(tc, "UrlFilter", "add_num", 0, urlFilterMaxRules)
	if err != nil {
		return err
	}
	// sec-urlfilter.asp, Save_Flag = 1.
	return runFirewallSteps(ctx, opts, tc, []fwStep{{
		sets: []tcapiWrite{
			{node: "UrlFilter_Common", attr: "Action", value: "Add"},
			{node: "WebCurSet_Entry", attr: "url_filter_id", value: strconv.Itoa(slot)},
			{node: "UrlFilter_Entry", attr: "Activate", value: "1"},
			{node: "UrlFilter_Entry", attr: "URL", value: u},
		},
		commits: []string{"UrlFilter"},
	}})
}

func deleteURLFilterRule(ctx context.Context, opts Options, input *wusp.Message) error {
	in, err := ruleInput(input, "URLFilter.DeleteRule()", "EntryIndex", "URL")
	if err != nil {
		return err
	}
	index, err := entryIndexInput(in, 0, urlFilterMaxRules)
	if err != nil {
		return err
	}
	tc, cancel, err := firewallTcapi(ctx, opts)
	if err != nil {
		return err
	}
	defer cancel()
	lines, _, err := readList(opts, tc, "UrlFilter", "Url_num", "urladdr")
	if err != nil {
		return err
	}
	found := false
	for _, existing := range parseURLFilterList(lines) {
		if existing[0] == index {
			found = in["URL"] == "" || strings.EqualFold(existing[1], in["URL"])
		}
	}
	if !found {
		return errRuleMoved
	}
	// sec-urlfilter.asp, Save_Flag = 3.
	return runFirewallSteps(ctx, opts, tc, []fwStep{{
		sets: []tcapiWrite{
			{node: "UrlFilter_Common", attr: "Action", value: "Del"},
			{node: "UrlFilter_Common", attr: "DeleteIndex", value: index + ","},
		},
		commits: []string{"UrlFilter"},
	}})
}
