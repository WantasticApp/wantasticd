package fiberonu

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// fwFake is a stateful tcapi for the firewall nodes. It models what the
// firmware does around the store: un-indexed entry names resolve through
// WebCurSet_Entry, the count attributes rewrite the list files, add_* return
// the first free entry of a range, and a commit with Action=Del removes the
// entries DeleteIndex lists.
type fwFake struct {
	store  map[string]string
	writes []string
	gets   int
	tmp    string
	fail   string
	cmcc   bool
}

func (f *fwFake) entries(node string, lo, hi int) []int {
	seen := map[int]bool{}
	for k := range f.store {
		rest, ok := strings.CutPrefix(k, node)
		if !ok {
			continue
		}
		n, err := strconv.Atoi(rest[:strings.IndexByte(rest, '/')])
		if err == nil && n >= lo && n < hi {
			seen[n] = true
		}
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

func (f *fwFake) free(node string, lo, hi int) string {
	used := f.entries(node, lo, hi)
	for n := lo; n < hi; n++ {
		if !containsInt(used, n) {
			return strconv.Itoa(n)
		}
	}
	return "N/A"
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (f *fwFake) writeList(file, node string, lo, hi int, attrs []string) string {
	var lines []string
	list := f.entries(node, lo, hi)
	for _, n := range list {
		lines = append(lines, strconv.Itoa(n))
		for _, a := range attrs {
			lines = append(lines, f.store[node+strconv.Itoa(n)+"/"+a])
		}
	}
	os.WriteFile(filepath.Join(f.tmp, file), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	return strconv.Itoa(len(list))
}

func (f *fwFake) portAttrs() []string {
	attrs := []string{"Active", "Interface", "IPName", "Protocol", "SrcIPAddr", "SrcIPMask", "SrcPort", "DesIPAddr", "DesIPMask", "DesPort"}
	if f.cmcc {
		attrs = append(attrs, "SrcIPEndAddr", "DesIPEndAddr", "SrcPortEnd", "DesPortEnd")
	}
	return attrs
}

func (f *fwFake) get(node, attr string) string {
	switch node + "/" + attr {
	case "IpMacFilter/mac_num":
		return f.writeList("macvalid", "IpMacFilter_Entry", 0, 40, []string{"MacName", "MacAddr", "Active", "Interface"})
	case "IpMacFilter/ipup_num":
		return f.writeList("ipupvalid", "IpMacFilter_Entry", 40, 80, f.portAttrs())
	case "IpMacFilter/ipdown_num":
		return f.writeList("ipdownvalid", "IpMacFilter_Entry", 80, 120, f.portAttrs())
	case "UrlFilter/Url_num":
		return f.writeList("urladdr", "UrlFilter_Entry", 0, 100, []string{"URL"})
	case "IpMacFilter/add_macnum":
		return f.free("IpMacFilter_Entry", 0, 40)
	case "IpMacFilter/add_ipupnum":
		return f.free("IpMacFilter_Entry", 40, 80)
	case "IpMacFilter/add_ipdownnum":
		return f.free("IpMacFilter_Entry", 80, 120)
	case "UrlFilter/add_num":
		return f.free("UrlFilter_Entry", 0, 100)
	}
	if v, ok := f.store[node+"/"+attr]; ok {
		return v
	}
	return "no attribute information"
}

func (f *fwFake) remove(node, list string) {
	for _, idx := range strings.Split(list, ",") {
		if idx == "" {
			continue
		}
		for k := range f.store {
			if strings.HasPrefix(k, node+idx+"/") {
				delete(f.store, k)
			}
		}
	}
}

func (f *fwFake) exec(_ context.Context, name string, args ...string) ([]byte, error) {
	if !strings.HasSuffix(name, "tcapi") {
		return nil, errors.New("not found")
	}
	line := strings.Join(args, " ")
	switch args[0] {
	case "get":
		f.gets++
		return []byte(f.get(args[1], args[2]) + "\n"), nil
	case "set", "commit", "save":
		f.writes = append(f.writes, line)
		if f.fail != "" && strings.HasPrefix(line, f.fail) {
			return []byte("verify setting fail while tcapi set " + line + "\n"), nil
		}
		switch {
		case args[0] == "set":
			node := args[1]
			switch node {
			case "IpMacFilter_Entry":
				node += f.store["WebCurSet_Entry/ipfilter_id"]
			case "UrlFilter_Entry":
				node += f.store["WebCurSet_Entry/url_filter_id"]
			}
			f.store[node+"/"+args[2]] = args[3]
		case line == "commit IpMacFilter_Entry" && f.store["IpMacFilter_Common/Action"] == "Del":
			f.remove("IpMacFilter_Entry", f.store["IpMacFilter_Common/DeleteIndex"])
		case line == "commit UrlFilter" && f.store["UrlFilter_Common/Action"] == "Del":
			f.remove("UrlFilter_Entry", f.store["UrlFilter_Common/DeleteIndex"])
		}
		return nil, nil
	}
	return nil, errors.New("unknown tcapi verb")
}

func fwFixture(t *testing.T) (Options, *fwFake) {
	t.Helper()
	sysNet := t.TempDir()
	for _, name := range []string{"lo", "br0", "eth0.1", "ra0", "nas0_0", "nas4_0", "ppp80"} {
		if err := os.MkdirAll(filepath.Join(sysNet, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake := &fwFake{tmp: t.TempDir(), cmcc: true, store: map[string]string{
		"WebCustom_Entry/isCMCCSupported":   "Yes",
		"Firewall_Entry/firewall_status":    "0",
		"Firewall_Entry/spi_status":         "0",
		"IpMacFilter_Common/ListTypeMac":    "White",
		"IpMacFilter_Common/ActiveMac":      "0",
		"IpMacFilter_Common/ListTypeIpDown": "black",
		"IpMacFilter_Common/ListTypeIpUp":   "black",
		"UrlFilter_Common/Activate":         "0",
		"UrlFilter_Common/Filter_Policy":    "0",
	}}
	return Options{SysClassNetDir: sysNet, TmpDir: fake.tmp, TcapiPath: "/userfs/bin/tcapi", Exec: fake.exec}, fake
}

func fwInput(pairs ...string) *wusp.Message {
	msg := &wusp.Message{}
	for i := 0; i+1 < len(pairs); i += 2 {
		msg.Set(pairs[i], wusp.String(pairs[i+1]))
	}
	return msg
}

func fwApply(opts Options, pairs ...string) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		pairs[i] = netP + "Firewall." + pairs[i]
	}
	return ONUNetworkOperate(context.Background(), opts, netP+"Firewall.Apply()", fwInput(pairs...))
}

func fwOperate(opts Options, command string, pairs ...string) error {
	return ONUNetworkOperate(context.Background(), opts, netP+"Firewall."+command, fwInput(pairs...))
}

func fwWrites(t *testing.T, fake *fwFake, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(fake.writes, want) {
		t.Fatalf("tcapi writes:\n got  %q\n want %q", fake.writes, want)
	}
	fake.writes = nil
}

func TestFirewallProtectionSequence(t *testing.T) {
	opts, fake := fwFixture(t)
	if err := fwApply(opts, "Enable", "true", "Level", "high", "DoSProtection", "true", "PortScanProtection", "false", "IPv6SessionProtection", "true"); err != nil {
		t.Fatal(err)
	}
	// sec-firewall.asp: the sets, one commit per node in the page's order,
	// one save. Neither spi_status nor the WAN access rights are touched.
	fwWrites(t, fake,
		"set Firewall_Entry firewall_status 1",
		"set Firewall_Entry firewall_level high",
		"set Firewall_DoSEntry Enable Yes",
		"set Firewall_PortScanEntry Enable No",
		"set Firewall_IPv6SessionEntry Enable Yes",
		"commit Firewall_Entry",
		"commit Firewall_DoSEntry",
		"commit Firewall_PortScanEntry",
		"commit Firewall_IPv6SessionEntry",
		"save",
	)
	// A single leaf through Set writes only its own node.
	if err := SetONUNetworkParam(context.Background(), opts, netP+"Firewall.DoSProtection", wusp.Bool(false)); err != nil {
		t.Fatal(err)
	}
	fwWrites(t, fake, "set Firewall_DoSEntry Enable No", "commit Firewall_DoSEntry", "save")
}

func TestFirewallFilterSwitchAndModeSequences(t *testing.T) {
	opts, fake := fwFixture(t)
	// sec-macfilter.asp Mac_Flag=2: the switch is posted with the stored list type.
	if err := fwApply(opts, "MACFilter.Enable", "true"); err != nil {
		t.Fatal(err)
	}
	fwWrites(t, fake,
		"set IpMacFilter_Common IpMacType Mac",
		"set IpMacFilter_Common Action Add",
		"set IpMacFilter_Common ActiveMac 1",
		"set IpMacFilter_Common ListTypeMac White",
		"commit IpMacFilter_Entry",
		"save",
	)
	// Mac_Flag=4: the mode alone.
	if err := fwApply(opts, "MACFilter.Mode", "black"); err != nil {
		t.Fatal(err)
	}
	fwWrites(t, fake,
		"set IpMacFilter_Common IpMacType Mac",
		"set IpMacFilter_Common Action Mod",
		"set IpMacFilter_Common ListTypeMac Black",
		"commit IpMacFilter_Entry",
		"save",
	)
	// sec-portfilter.asp Port_Flag=3 (outbound mode), 6 (inbound switch):
	// each list commits on its own, one save.
	if err := fwApply(opts, "PortFilter.OutboundMode", "white", "PortFilter.InboundEnable", "true"); err != nil {
		t.Fatal(err)
	}
	fwWrites(t, fake,
		"set IpMacFilter_Common Action Mod",
		"set IpMacFilter_Common IpMacType IpUp",
		"set IpMacFilter_Common ListTypeIpUp white",
		"commit IpMacFilter_Entry",
		"set IpMacFilter_Common IpMacType IpDown",
		"set IpMacFilter_Common Action Mod",
		"set IpMacFilter_Common ActivePortIn 1",
		"set IpMacFilter_Common ListTypeIpDown black",
		"commit IpMacFilter_Entry",
		"save",
	)
	// sec-urlfilter.asp Save_Flag=4 then 2.
	if err := fwApply(opts, "URLFilter.Enable", "true", "URLFilter.Mode", "white"); err != nil {
		t.Fatal(err)
	}
	fwWrites(t, fake,
		"set UrlFilter_Common Action Filter",
		"set UrlFilter_Common Filter_Policy 1",
		"commit UrlFilter",
		"set UrlFilter_Common Action Status",
		"set UrlFilter_Common Activate 1",
		"commit UrlFilter",
		"save",
	)
}

func TestFirewallMACRuleRoundTripAndSlots(t *testing.T) {
	opts, fake := fwFixture(t)
	if err := fwOperate(opts, "MACFilter.AddRule()", "Name", "printer", "MACAddress", "AA:BB:CC:DD:EE:01"); err != nil {
		t.Fatal(err)
	}
	// sec-addmacfilter.asp, with the slot the firmware reported.
	fwWrites(t, fake,
		"set WebCurSet_Entry ipfilter_id 0",
		"set IpMacFilter_Common Action Add",
		"set IpMacFilter_Common IpMacType Mac",
		"set IpMacFilter_Entry Active Yes",
		"set IpMacFilter_Entry RuleType MAC",
		"set IpMacFilter_Entry MacName printer",
		"set IpMacFilter_Entry MacAddr AA:BB:CC:DD:EE:01",
		"set IpMacFilter_Entry Interface br0",
		"set IpMacFilter_Entry Direction Incoming",
		"commit IpMacFilter_Entry",
		"save",
	)
	for i, mac := range []string{"AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"} {
		if err := fwOperate(opts, "MACFilter.AddRule()", "Name", "dev"+strconv.Itoa(i), "MACAddress", mac); err != nil {
			t.Fatal(err)
		}
	}
	if fake.store["IpMacFilter_Entry2/MacAddr"] != "AA:BB:CC:DD:EE:03" {
		t.Fatalf("third rule did not land in entry 2: %v", fake.store)
	}
	fake.writes = nil

	// Remove the middle rule: sec-macfilter.asp Mac_Flag=3.
	if err := fwOperate(opts, "MACFilter.DeleteRule()", "EntryIndex", "1", "MACAddress", "aa:bb:cc:dd:ee:02"); err != nil {
		t.Fatal(err)
	}
	fwWrites(t, fake,
		"set IpMacFilter_Common IpMacType Mac",
		"set IpMacFilter_Common Action Del",
		"set IpMacFilter_Common DeleteIndex 1,",
		"commit IpMacFilter_Entry",
		"save",
	)
	if _, ok := fake.store["IpMacFilter_Entry1/MacAddr"]; ok {
		t.Fatal("entry 1 survived its delete")
	}
	// The freed slot is the next one used.
	if err := fwOperate(opts, "MACFilter.AddRule()", "Name", "tv", "MACAddress", "AA:BB:CC:DD:EE:04"); err != nil {
		t.Fatal(err)
	}
	if fake.writes[0] != "set WebCurSet_Entry ipfilter_id 1" {
		t.Fatalf("slot allocation: %q", fake.writes[0])
	}
	// The snapshot shows what was written.
	msg := &wusp.Message{}
	tc, cancel := newTcapi(context.Background(), opts)
	defer cancel()
	collectFirewallConfig(opts, tc, msg)
	expect(t, msg, "Firewall.MACFilter.RuleNumberOfEntries", "3")
	expect(t, msg, "Firewall.MACFilter.Rule.2.EntryIndex", "1")
	expect(t, msg, "Firewall.MACFilter.Rule.2.MACAddress", "AA:BB:CC:DD:EE:04")
}

func TestFirewallPortRuleRoundTrip(t *testing.T) {
	opts, fake := fwFixture(t)
	if err := fwOperate(opts, "PortFilter.AddRule()", "Direction", "outbound", "Name", "no-smtp", "Protocol", "TCP",
		"DestPort", "25", "DestPortEnd", "25", "SourceIP", "192.168.1.10", "SourceIPEnd", "192.168.1.20"); err != nil {
		t.Fatal(err)
	}
	// sec-addportfilter.asp: outbound rules use entries 40-79 and br0.
	fwWrites(t, fake,
		"set WebCurSet_Entry ipfilter_id 40",
		"set IpMacFilter_Common IpMacType IpUp",
		"set IpMacFilter_Common Action Add",
		"set IpMacFilter_Entry Interface br0",
		"set IpMacFilter_Entry Direction Outgoing",
		"set IpMacFilter_Entry Active Yes",
		"set IpMacFilter_Entry RuleType IP",
		"set IpMacFilter_Entry IPName no-smtp",
		"set IpMacFilter_Entry Protocol TCP",
		"set IpMacFilter_Entry SrcIPAddr 192.168.1.10",
		"set IpMacFilter_Entry SrcIPMask ",
		"set IpMacFilter_Entry SrcPort ",
		"set IpMacFilter_Entry DesIPAddr ",
		"set IpMacFilter_Entry DesIPMask ",
		"set IpMacFilter_Entry DesPort 25",
		"set IpMacFilter_Entry SrcIPEndAddr 192.168.1.20",
		"set IpMacFilter_Entry DesIPEndAddr ",
		"set IpMacFilter_Entry SrcPortEnd ",
		"set IpMacFilter_Entry DesPortEnd 25",
		"commit IpMacFilter_Entry",
		"save",
	)
	// Inbound: entries 80-119, the chosen WAN connection.
	if err := fwOperate(opts, "PortFilter.AddRule()", "Direction", "inbound", "Name", "no-ping", "Protocol", "ICMP", "Interface", "nas0_0"); err != nil {
		t.Fatal(err)
	}
	if got := fake.writes[:5]; !reflect.DeepEqual(got, []string{
		"set WebCurSet_Entry ipfilter_id 80",
		"set IpMacFilter_Common IpMacType IpDown",
		"set IpMacFilter_Common Action Add",
		"set IpMacFilter_Entry Interface nas0_0",
		"set IpMacFilter_Entry Direction Incoming",
	}) {
		t.Fatalf("inbound head: %q", got)
	}
	fake.writes = nil
	// A duplicate is refused before anything is written.
	if err := fwOperate(opts, "PortFilter.AddRule()", "Direction", "inbound", "Name", "again", "Protocol", "ICMP", "Interface", "nas0_0"); err == nil {
		t.Fatal("duplicate inbound rule accepted")
	}
	fwWrites(t, fake)

	// sec-portfilter.asp Port_Flag=2.
	if err := fwOperate(opts, "PortFilter.DeleteRule()", "Direction", "outbound", "EntryIndex", "40", "Name", "no-smtp"); err != nil {
		t.Fatal(err)
	}
	fwWrites(t, fake,
		"set IpMacFilter_Common Action Del",
		"set IpMacFilter_Common IpMacType IpUp",
		"set IpMacFilter_Common DeleteIndex 40,",
		"commit IpMacFilter_Entry",
		"save",
	)
	if len(fake.entries("IpMacFilter_Entry", 40, 80)) != 0 || len(fake.entries("IpMacFilter_Entry", 80, 120)) != 1 {
		t.Fatal("the delete removed the wrong entries")
	}
}

func TestFirewallMaskFormOnNonCMCCFirmware(t *testing.T) {
	opts, fake := fwFixture(t)
	fake.cmcc = false
	fake.store["WebCustom_Entry/isCMCCSupported"] = "No"
	if err := fwOperate(opts, "PortFilter.AddRule()", "Direction", "outbound", "Name", "lan", "SourceIP", "192.168.1.0", "SourceMask", "255.255.255.0"); err != nil {
		t.Fatal(err)
	}
	if n := len(fake.writes); n != 17 || fake.writes[10] != "set IpMacFilter_Entry SrcIPMask 255.255.255.0" {
		t.Fatalf("mask form: %d writes: %q", n, fake.writes)
	}
	fake.writes = nil
	if err := fwOperate(opts, "PortFilter.AddRule()", "Direction", "outbound", "Name", "r", "Protocol", "TCP", "DestPort", "80", "DestPortEnd", "90"); err == nil {
		t.Fatal("a port range was accepted on a firmware without ranges")
	}
	fwWrites(t, fake)
}

func TestFirewallURLRoundTrip(t *testing.T) {
	opts, fake := fwFixture(t)
	// The page only offers adding while the filter is on.
	if err := fwOperate(opts, "URLFilter.AddRule()", "URL", "example.com"); err == nil {
		t.Fatal("URL added while the filter is off")
	}
	fwWrites(t, fake)
	fake.store["UrlFilter_Common/Activate"] = "1"
	if err := fwOperate(opts, "URLFilter.AddRule()", "URL", "https://example.com"); err != nil {
		t.Fatal(err)
	}
	fwWrites(t, fake,
		"set UrlFilter_Common Action Add",
		"set WebCurSet_Entry url_filter_id 0",
		"set UrlFilter_Entry Activate 1",
		"set UrlFilter_Entry URL example.com",
		"commit UrlFilter",
		"save",
	)
	if err := fwOperate(opts, "URLFilter.AddRule()", "URL", "EXAMPLE.com"); err == nil {
		t.Fatal("duplicate URL accepted")
	}
	fwWrites(t, fake)
	if err := fwOperate(opts, "URLFilter.DeleteRule()", "EntryIndex", "0", "URL", "example.com"); err != nil {
		t.Fatal(err)
	}
	fwWrites(t, fake,
		"set UrlFilter_Common Action Del",
		"set UrlFilter_Common DeleteIndex 0,",
		"commit UrlFilter",
		"save",
	)
	if len(fake.entries("UrlFilter_Entry", 0, 100)) != 0 {
		t.Fatal("URL entry survived its delete")
	}
}

func TestFirewallRefusalsWriteNothing(t *testing.T) {
	opts, fake := fwFixture(t)
	fake.store["UrlFilter_Common/Activate"] = "1"
	fake.store["IpMacFilter_Entry0/MacAddr"] = "AA:BB:CC:DD:EE:01"
	fake.store["IpMacFilter_Entry0/MacName"] = "printer"
	full := func(node string, lo, hi int, attr string) func() {
		return func() {
			for n := lo; n < hi; n++ {
				fake.store[node+strconv.Itoa(n)+"/"+attr] = "x" + strconv.Itoa(n)
			}
		}
	}
	port := func(pairs ...string) func() error {
		return func() error { return fwOperate(opts, "PortFilter.AddRule()", pairs...) }
	}
	cases := []struct {
		name  string
		setup func()
		run   func() error
		want  string
	}{
		{"empty apply", nil, func() error { return fwApply(opts) }, "needs the changed settings"},
		{"unknown leaf", nil, func() error { return fwApply(opts, "SPIEnable", "true") }, "does not accept input"},
		{"raw rule leaf", nil, func() error { return fwApply(opts, "Rule.1.Raw", "-A INPUT -j DROP") }, "does not accept input"},
		{"bad level", nil, func() error { return fwApply(opts, "Level", "paranoid") }, "not offered"},
		{"bad mode", nil, func() error { return fwApply(opts, "MACFilter.Mode", "grey") }, "must be black"},
		{"bad bool", nil, func() error { return fwApply(opts, "Enable", "maybe") }, "true or false"},
		{"valid leaf after an invalid one", nil, func() error { return fwApply(opts, "DoSProtection", "true", "Level", "x") }, "not offered"},
		{"switch without a stored mode", func() { delete(fake.store, "IpMacFilter_Common/ListTypeIpUp") },
			func() error { return fwApply(opts, "PortFilter.OutboundEnable", "true") }, "no list mode stored"},
		{"mac: bad address", nil, func() error {
			return fwOperate(opts, "MACFilter.AddRule()", "Name", "a", "MACAddress", "AA-BB-CC-DD-EE-FF")
		}, "AA:BB:CC:DD:EE:FF"},
		{"mac: broadcast", nil, func() error {
			return fwOperate(opts, "MACFilter.AddRule()", "Name", "a", "MACAddress", "ff:ff:ff:ff:ff:ff")
		}, "AA:BB:CC:DD:EE:FF"},
		{"mac: name with a space", nil, func() error {
			return fwOperate(opts, "MACFilter.AddRule()", "Name", "my tv", "MACAddress", "AA:BB:CC:DD:EE:09")
		}, "without spaces"},
		{"mac: name too long", nil, func() error {
			return fwOperate(opts, "MACFilter.AddRule()", "Name", strings.Repeat("a", 32), "MACAddress", "AA:BB:CC:DD:EE:09")
		}, "1 to 31"},
		{"mac: duplicate", nil, func() error {
			return fwOperate(opts, "MACFilter.AddRule()", "Name", "again", "MACAddress", "aa:bb:cc:dd:ee:01")
		}, "already in the device list"},
		{"mac: unknown input", nil, func() error {
			return fwOperate(opts, "MACFilter.AddRule()", "Name", "a", "MACAddress", "AA:BB:CC:DD:EE:09", "Interface", "nas0_0")
		}, "does not accept input"},
		{"mac: list full", full("IpMacFilter_Entry", 0, 40, "MacAddr"), func() error {
			return fwOperate(opts, "MACFilter.AddRule()", "Name", "a", "MACAddress", "AA:BB:CC:DD:EE:09")
		}, "list is full"},
		{"mac: delete a rule that moved", nil, func() error {
			return fwOperate(opts, "MACFilter.DeleteRule()", "EntryIndex", "0", "MACAddress", "AA:BB:CC:DD:EE:77")
		}, "refresh and try again"},
		{"mac: delete outside the MAC range", nil, func() error { return fwOperate(opts, "MACFilter.DeleteRule()", "EntryIndex", "40") }, "EntryIndex"},
		{"mac: delete several at once", nil, func() error { return fwOperate(opts, "MACFilter.DeleteRule()", "EntryIndex", "0,1") }, "EntryIndex"},
		{"port: no direction", nil, port("Name", "a", "Protocol", "TCP"), "Direction"},
		{"port: nothing to match", nil, port("Direction", "outbound", "Name", "a"), "at least one"},
		{"port: inbound without a WAN", nil, port("Direction", "inbound", "Name", "a", "Protocol", "TCP"), "WAN connections"},
		{"port: inbound on a LAN interface", nil, port("Direction", "inbound", "Name", "a", "Protocol", "TCP", "Interface", "br0"), "WAN connections"},
		{"port: outbound with an interface", nil, port("Direction", "outbound", "Name", "a", "Protocol", "TCP", "Interface", "nas0_0"), "takes no interface"},
		{"port: unknown protocol", nil, port("Direction", "outbound", "Name", "a", "Protocol", "GRE"), "not offered"},
		{"port: port with ICMP", nil, port("Direction", "outbound", "Name", "a", "Protocol", "ICMP", "DestPort", "80"), "ports need protocol"},
		{"port: port out of range", nil, port("Direction", "outbound", "Name", "a", "Protocol", "TCP", "DestPort", "70000"), "1 to 65535"},
		{"port: range backwards", nil, port("Direction", "outbound", "Name", "a", "Protocol", "TCP", "DestPort", "90", "DestPortEnd", "80"), "ends before"},
		{"port: range end without a start", nil, port("Direction", "outbound", "Name", "a", "Protocol", "TCP", "DestPortEnd", "80"), "needs a start"},
		{"port: loopback address", nil, port("Direction", "outbound", "Name", "a", "SourceIP", "127.0.0.1"), "not a valid IPv4"},
		{"port: multicast address", nil, port("Direction", "outbound", "Name", "a", "DestIP", "224.0.0.1"), "not a valid IPv4"},
		{"port: IPv6 address", nil, port("Direction", "outbound", "Name", "a", "DestIP", "2001:db8::1"), "not a valid IPv4"},
		{"port: mask on a range firmware", nil, port("Direction", "outbound", "Name", "a", "SourceIP", "10.0.0.0", "SourceMask", "255.0.0.0"), "ranges, not masks"},
		{"port: address range backwards", nil, port("Direction", "outbound", "Name", "a", "SourceIP", "10.0.0.9", "SourceIPEnd", "10.0.0.1"), "ends before"},
		{"port: list full", full("IpMacFilter_Entry", 40, 80, "IPName"), port("Direction", "outbound", "Name", "a", "Protocol", "UDP"), "list is full"},
		{"port: delete with the other direction's index", nil, func() error {
			return fwOperate(opts, "PortFilter.DeleteRule()", "Direction", "inbound", "EntryIndex", "41")
		}, "EntryIndex"},
		{"url: too short", nil, func() error { return fwOperate(opts, "URLFilter.AddRule()", "URL", "ab") }, "3 to 31"},
		{"url: too long", nil, func() error { return fwOperate(opts, "URLFilter.AddRule()", "URL", strings.Repeat("a", 28)+".com") }, "3 to 31"},
		{"url: reserved word", nil, func() error { return fwOperate(opts, "URLFilter.AddRule()", "URL", ".com") }, "not a website"},
		{"url: space", nil, func() error { return fwOperate(opts, "URLFilter.AddRule()", "URL", "a b.com") }, "printable ASCII"},
		{"url: list full", full("UrlFilter_Entry", 0, 100, "URL"), func() error { return fwOperate(opts, "URLFilter.AddRule()", "URL", "new.example") }, "list is full"},
		{"url: delete a missing entry", nil, func() error { return fwOperate(opts, "URLFilter.DeleteRule()", "EntryIndex", "7") }, "refresh and try again"},
	}
	for _, tc := range cases {
		saved := map[string]string{}
		for k, v := range fake.store {
			saved[k] = v
		}
		if tc.setup != nil {
			tc.setup()
		}
		err := tc.run()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one containing %q", tc.name, err, tc.want)
		}
		if len(fake.writes) != 0 {
			t.Errorf("%s: a refused change wrote %q", tc.name, fake.writes)
		}
		fake.writes, fake.store = nil, saved
	}
}

// The agent's own path to the hub: nothing that filters forwarded traffic is
// refused, and what filters the ONU's own input is refused only while a
// system tunnel interface exists.
func TestFirewallManagementPathGuard(t *testing.T) {
	opts, fake := fwFixture(t)
	tun := filepath.Join(opts.SysClassNetDir, "wt0")
	if err := os.MkdirAll(tun, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tun, "tun_flags"), []byte("0x1001\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, pairs := range [][]string{
		{"Enable", "true"},
		{"PortScanProtection", "true"},
		{"DoSProtection", "true", "PortScanProtection", "true"},
	} {
		err := fwApply(opts, pairs...)
		if err == nil || !strings.Contains(err.Error(), "wt0") || !strings.Contains(err.Error(), "Nothing was changed") {
			t.Errorf("%v: want a refusal naming the tunnel, got %v", pairs, err)
		}
		fwWrites(t, fake)
	}
	// A level change is refused while the firewall is on, allowed while off.
	fake.store["Firewall_Entry/firewall_status"] = "1"
	if err := fwApply(opts, "Level", "high"); err == nil {
		t.Error("level change accepted with the firewall on and a tunnel interface present")
	}
	fwWrites(t, fake)
	// Turning things off, and everything that only filters forwarded
	// traffic, stays available.
	if err := fwApply(opts, "Enable", "false", "PortScanProtection", "false", "DoSProtection", "true",
		"MACFilter.Enable", "true", "MACFilter.Mode", "white", "PortFilter.InboundEnable", "true", "PortFilter.InboundMode", "white"); err != nil {
		t.Fatalf("a change that cannot reach the tunnel was refused: %v", err)
	}
	if len(fake.writes) == 0 {
		t.Fatal("nothing written")
	}
	msg := &wusp.Message{}
	tc, cancel := newTcapi(context.Background(), opts)
	defer cancel()
	collectFirewallConfig(opts, tc, msg)
	expect(t, msg, "Firewall.Guarded", "Enable,Level,PortScanProtection")
}

func TestFirewallFailureReportsTcapiOutput(t *testing.T) {
	opts, fake := fwFixture(t)
	fake.fail = "commit Firewall_DoSEntry"
	err := fwApply(opts, "DoSProtection", "true")
	if err == nil || !strings.Contains(err.Error(), "tcapi commit Firewall_DoSEntry failed") || !strings.Contains(err.Error(), "verify setting fail") {
		t.Fatalf("want the tcapi failure with its output, got %v", err)
	}
	if last := fake.writes[len(fake.writes)-1]; last != "commit Firewall_DoSEntry" {
		t.Errorf("writes continued after the failure: %q", fake.writes)
	}
}

func TestFirewallCollectionNeverWritesAndReportsCapabilities(t *testing.T) {
	opts, fake := fwFixture(t)
	msg := &wusp.Message{}
	tc, cancel := newTcapi(context.Background(), opts)
	defer cancel()
	collectFirewallConfig(opts, tc, msg)
	if len(fake.writes) != 0 {
		t.Fatalf("collection wrote to the device: %q", fake.writes)
	}
	if fake.gets == 0 {
		t.Fatal("the collection read nothing; the fixture is not wired")
	}
	expect(t, msg, "Firewall.Writable", strings.Join(firewallWritable, ","))
	expect(t, msg, "Firewall.LevelsAvailable", "low,medium,high")
	expect(t, msg, "Firewall.MACFilter.MaxRules", "40")
	expect(t, msg, "Firewall.PortFilter.MaxRules", "40")
	expect(t, msg, "Firewall.PortFilter.ProtocolsAvailable", "TCP/UDP,TCP,UDP,ICMP,All")
	expect(t, msg, "Firewall.PortFilter.AddressForm", "range")
	expect(t, msg, "Firewall.PortFilter.InterfacesAvailable", "nas0_0,nas4_0,ppp80")
	expect(t, msg, "Firewall.URLFilter.MaxRules", "100")
	absent(t, msg, "Firewall.Guarded")

	// NPU builds store 32 MAC rules; a firmware without ranges takes masks.
	fake.store["WebCustom_Entry/isNPUSupported"] = "Yes"
	fake.store["WebCustom_Entry/isCMCCSupported"] = "No"
	msg = &wusp.Message{}
	collectFirewallConfig(opts, tc, msg)
	expect(t, msg, "Firewall.MACFilter.MaxRules", "32")
	expect(t, msg, "Firewall.PortFilter.AddressForm", "mask")
}

// Every leaf the agent reports as writable is a ReadWrite parameter of the
// model, and every command is declared.
func TestFirewallModelMatchesTheAgent(t *testing.T) {
	access := map[string]wusp.Access{}
	for _, p := range wusp.AllWUSPONUParams {
		access[p.Path] = p.Access
	}
	for leaf := range firewallLeaves {
		if access[netP+leaf] != wusp.ReadWrite {
			t.Errorf("%s is writable in the agent but not ReadWrite in the model", leaf)
		}
	}
	if access[netP+"Firewall.SPIEnable"] != wusp.ReadOnly {
		t.Error("SPIEnable must stay read-only: the firmware does not act on it")
	}
	for _, cmd := range []string{
		wusp.WUSPONUNetworkFirewallApplyCommand,
		wusp.WUSPONUNetworkMACFilterAddCommand, wusp.WUSPONUNetworkMACFilterDelCommand,
		wusp.WUSPONUNetworkPortFilterAddCommand, wusp.WUSPONUNetworkPortFilterDelCommand,
		wusp.WUSPONUNetworkURLFilterAddCommand, wusp.WUSPONUNetworkURLFilterDelCommand,
	} {
		if err := ONUNetworkOperate(context.Background(), Options{}, cmd, nil); errors.Is(err, wusp.ErrUSPPathUnsupported) {
			t.Errorf("%s is declared but not handled", cmd)
		}
	}
}
