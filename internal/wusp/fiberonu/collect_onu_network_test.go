package fiberonu

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

// Fixtures follow the firmware's own formats (EN7528 CMCC rootfs):
// /proc/net/dev and /proc/net/route as the kernel prints them, `tcapi get`
// printing one value line ("N/A" when unset), the list files cfg_manager
// writes for the sec_*list.cgi scripts, and the mt7603eap driver's
// get_mac_table format strings.

const fixtureProcNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   45120     560    0    0    0     0          0         0    45120     560    0    0    0     0       0          0
  eth0: 9876543   20000    5    0    0     0          0         0  5432109   15000    2    0    0     0       0          0
eth0.1: 1234567    4000    0    0    0     0          0         0  7654321    5000    0    0    0     0       0          0
eth0.4:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
   br0: 2222222    3000    0    0    0     0          0         0  3333333    3500    0    0    0     0       0          0
nas0_0: 88888888  90000    0    0    0     0          0         0 77777777   80000    0    0    0     0       0          0
  omci:     100      10    0    0    0     0          0         0      200      20    0    0    0     0       0          0
   ra0:  500000    1000    0    0    0     0          0         0   600000    1200    0    0    0     0       0          0
   ra1:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
  wds0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
wan_int2_if:  0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
  sit0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
`

const fixtureProcNetRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
nas0_0	00000000	0100400A	0003	0	0	0	00000000	0	0	0
br0	0001A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`

// get_mac_table as iwpriv prints it: the ioctl name, then the driver's
// table (RTMPIoctlGetMacTable format strings).
const fixtureMacTable = `ra0       get_mac_table:
MAC                AID BSS PSM WMM MIMOPS RSSI0  RSSI1  RSSI2  PhMd      BW    MCS   SGI   STBC  Idle   Rate
A4:50:46:11:22:33  1   0   0   1   3       -45    -47    0      HTMIX     20M   7     1     0     299    72     0         , 1204, 0%
DC:A6:32:AA:BB:CC  2   1   1   1   3       -71    -68    0      HTMIX     40M   5     0     0     280    121    3         , 88, 3%
`

// tcapiFixture is the config tree as `tcapi get` reads it.
var tcapiFixture = map[string]string{
	"WLan_Common/APOn":              "1",
	"WLan_Common/Channel":           "0",
	"WLan_Common/HT_BW":             "1",
	"WLan_Common/HT_BSSCoexistence": "1",
	"WLan_Common/WirelessMode":      "9",
	"WLan_Common/Country":           "CN",
	"WLan_Common/CountryRegion":     "1",
	"WLan_Common/BssidNum":          "4",
	"WLan_Common/rt_device":         "7603",
	"WLan_Entry0/SSID":              "CMCC-AP1",
	"WLan_Entry0/EnableSSID":        "1",
	"WLan_Entry0/HideSSID":          "0",
	"WLan_Entry0/AuthMode":          "WPAPSKWPA2PSK",
	"WLan_Entry0/EncrypType":        "TKIPAES",
	"WLan_Entry0/MaxStaNum":         "40",
	"WLan_Entry0/WPAPSK":            "secret-passphrase",
	"WLan_Entry1/SSID":              "CMCC-AP2",
	"WLan_Entry1/EnableSSID":        "1",
	"WLan_Entry1/HideSSID":          "1",
	"WLan_Entry1/AuthMode":          "OPEN",
	"WLan_Entry1/EncrypType":        "NONE",
	"WLan_Entry1/MaxStaNum":         "8",
	"WLan_Entry2/SSID":              "CMCC-AP3",
	"WLan_Entry2/EnableSSID":        "0",
	"WLan_Entry3/SSID":              "CMCC-AP4",
	"WLan_Entry3/EnableSSID":        "0",
	// 5 GHz nodes exist in the tree, but this ONU has no rai0.
	"WLan11ac_Common/Channel": "149",
	"WLan11ac_Entry0/SSID":    "CMCC-AP1-5G",

	"Firewall_Entry/firewall_status":    "1",
	"Firewall_Entry/firewall_level":     "medium",
	"Firewall_Entry/spi_status":         "1",
	"Firewall_DoSEntry/Enable":          "Yes",
	"Firewall_PortScanEntry/Enable":     "No",
	"Firewall_IPv6SessionEntry/Enable":  "No",
	"IpMacFilter_Common/ActiveMac":      "1",
	"IpMacFilter_Common/ListTypeMac":    "Black",
	"IpMacFilter_Common/ActivePortIn":   "1",
	"IpMacFilter_Common/ListTypeIpDown": "black",
	"IpMacFilter_Common/ActivePortOut":  "0",
	"IpMacFilter_Common/ListTypeIpUp":   "white",
	"IpMacFilter/mac_num":               "2",
	"IpMacFilter/ipdown_num":            "1",
	"IpMacFilter/ipup_num":              "0",
	"WebCustom_Entry/isCMCCSupported":   "Yes",
	"UrlFilter_Common/Activate":         "1",
	"UrlFilter_Common/Filter_Policy":    "0",
	"UrlFilter/Url_num":                 "2",
	"IpMacFilter_EtherTypeFilter/P0":    "PPPoE",
	"IpMacFilter_EtherTypeFilter/P5":    "IPv4oE,ARP",
	"IpMacFilter_EtherTypeFilter/P1":    "N/A",
}

// listFiles are what cfg_manager writes when the counts are read.
var listFiles = map[string]string{
	"IpMacFilter/mac_num":    "macvalid",
	"IpMacFilter/ipdown_num": "ipdownvalid",
	"IpMacFilter/ipup_num":   "ipupvalid",
	"UrlFilter/Url_num":      "urladdr",
}

var listFileContent = map[string]string{
	"macvalid":    "0\nkids-tablet\n11:22:33:44:55:66\nYes\nN/A\n3\nguest\naa:bb:cc:dd:ee:ff\nNo\nN/A\n",
	"ipdownvalid": "1\nYes\nINTERNET\nblock-telnet\nTCP\n0.0.0.0\n0.0.0.0\n0\n192.168.1.0\n255.255.255.0\n23\n0.0.0.0\n192.168.1.255\n0\n23\n",
	"ipupvalid":   "",
	"urladdr":     "0\nexample.com\n4\nads.example.net\n",
}

type fakeONU struct {
	t     *testing.T
	tmp   string
	calls []string
}

func (f *fakeONU) exec(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch {
	case strings.HasSuffix(name, "tcapi") && len(args) == 3 && args[0] == "get":
		key := args[1] + "/" + args[2]
		if file, ok := listFiles[key]; ok {
			if err := os.WriteFile(filepath.Join(f.tmp, file), []byte(listFileContent[file]), 0o644); err != nil {
				f.t.Fatal(err)
			}
		}
		if v, ok := tcapiFixture[key]; ok {
			return []byte(v + "\n"), nil
		}
		return []byte("no attribute information\n"), nil
	case name == "iwpriv" && len(args) == 2 && args[0] == "ra0" && args[1] == "get_mac_table":
		return []byte(fixtureMacTable), nil
	case name == "iptables" && len(args) == 3 && args[1] == "filter":
		return []byte("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-N macfilter_chain\n-A FORWARD -j macfilter_chain\n"), nil
	}
	return nil, errors.New("not found")
}

func writeSysNet(t *testing.T, dir string) {
	t.Helper()
	ifaces := map[string][3]string{ // address, operstate, flags
		"lo":          {"00:00:00:00:00:00", "unknown", "0x9"},
		"eth0":        {"e0:5d:54:00:00:01", "up", "0x1003"},
		"eth0.1":      {"e0:5d:54:00:00:01", "up", "0x1003"},
		"eth0.4":      {"e0:5d:54:00:00:01", "down", "0x1002"},
		"br0":         {"e0:5d:54:00:00:01", "up", "0x1003"},
		"nas0_0":      {"e0:5d:54:00:00:02", "up", "0x1003"},
		"omci":        {"", "unknown", "0x1003"},
		"ra0":         {"e0:5d:54:00:00:03", "unknown", "0x1003"},
		"ra1":         {"e0:5d:54:00:00:04", "unknown", "0x1003"},
		"wds0":        {"", "down", "0x1002"},
		"wan_int2_if": {"", "down", "0x1002"},
		"sit0":        {"", "down", "0x80"},
	}
	for name, v := range ifaces {
		d := filepath.Join(dir, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, "address"), []byte(v[0]+"\n"), 0o644)
		os.WriteFile(filepath.Join(d, "operstate"), []byte(v[1]+"\n"), 0o644)
		os.WriteFile(filepath.Join(d, "flags"), []byte(v[2]+"\n"), 0o644)
		os.WriteFile(filepath.Join(d, "mtu"), []byte("1500\n"), 0o644)
	}
	os.MkdirAll(filepath.Join(dir, "eth0.1", "brport"), 0o755)
	os.Symlink("../../br0", filepath.Join(dir, "eth0.1", "brport", "bridge"))
}

func fixtureOptions(t *testing.T) (Options, *fakeONU) {
	t.Helper()
	root := t.TempDir()
	procNet := filepath.Join(root, "proc_net")
	sysNet := filepath.Join(root, "sys_class_net")
	tmp := filepath.Join(root, "tmp")
	for _, d := range []string{procNet, sysNet, tmp} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(procNet, "dev"), []byte(fixtureProcNetDev), 0o644)
	os.WriteFile(filepath.Join(procNet, "route"), []byte(fixtureProcNetRoute), 0o644)
	writeSysNet(t, sysNet)
	fake := &fakeONU{t: t, tmp: tmp}
	return Options{
		ProcNetDir:     procNet,
		SysClassNetDir: sysNet,
		TmpDir:         tmp,
		TcapiPath:      "/userfs/bin/tcapi",
		Exec:           fake.exec,
		IfaceAddrs: func() (map[string][]string, error) {
			return map[string][]string{
				"lo":     {"127.0.0.1/8"},
				"br0":    {"192.168.1.1/24", "192.168.192.1/24"},
				"nas0_0": {"10.64.0.23/22"},
			}, nil
		},
	}, fake
}

func field(t *testing.T, msg *wusp.Message, path string) string {
	t.Helper()
	v, ok := msg.Get(netPrefix + path)
	if !ok {
		t.Errorf("missing %s", path)
		return ""
	}
	return wusp.ValueToString(v)
}

func expect(t *testing.T, msg *wusp.Message, path, want string) {
	t.Helper()
	if got := field(t, msg, path); got != want {
		t.Errorf("%s = %q, want %q", path, got, want)
	}
}

func absent(t *testing.T, msg *wusp.Message, path string) {
	t.Helper()
	if v, ok := msg.Get(netPrefix + path); ok {
		t.Errorf("%s = %q, want unset", path, wusp.ValueToString(v))
	}
}

func TestCollectNetworkInterfaces(t *testing.T) {
	opts, _ := fixtureOptions(t)
	msg := wusp.NewMessage()
	CollectNetwork(context.Background(), opts, msg)

	expect(t, msg, "InterfaceNumberOfEntries", "12")
	// /proc/net/dev order is kept: the setter resolves the same index.
	expect(t, msg, "Interface.1.Name", "lo")
	expect(t, msg, "Interface.1.Role", "internal")
	expect(t, msg, "Interface.1.Controllable", "false")
	absent(t, msg, "Interface.1.MACAddress")

	expect(t, msg, "Interface.2.Name", "eth0")
	expect(t, msg, "Interface.2.TxErrors", "2") // the 11th counter, read safely
	expect(t, msg, "Interface.2.Role", "internal")

	expect(t, msg, "Interface.3.Name", "eth0.1")
	expect(t, msg, "Interface.3.Role", "lan_port")
	expect(t, msg, "Interface.3.LANPort", "1")
	expect(t, msg, "Interface.3.Bridge", "br0")
	expect(t, msg, "Interface.3.Up", "true")
	expect(t, msg, "Interface.3.Controllable", "true")
	expect(t, msg, "Interface.4.Up", "false")

	expect(t, msg, "Interface.5.Name", "br0")
	expect(t, msg, "Interface.5.Role", "lan_bridge")
	expect(t, msg, "Interface.5.IPv4Address", "192.168.1.1")
	expect(t, msg, "Interface.5.IPv4PrefixLength", "24")
	expect(t, msg, "Interface.5.IPv4Addresses", "192.168.1.1/24,192.168.192.1/24")
	expect(t, msg, "Interface.5.Controllable", "false")

	expect(t, msg, "Interface.6.Name", "nas0_0")
	expect(t, msg, "Interface.6.Role", "uplink")
	expect(t, msg, "Interface.6.DefaultRoute", "true")
	expect(t, msg, "Interface.6.IPv4Address", "10.64.0.23")
	expect(t, msg, "Interface.6.Controllable", "false")

	expect(t, msg, "Interface.7.Role", "internal") // omci
	expect(t, msg, "Interface.8.Name", "ra0")
	expect(t, msg, "Interface.8.Role", "wifi")
	expect(t, msg, "Interface.8.OperState", "unknown")
	expect(t, msg, "Interface.8.Up", "true")
	expect(t, msg, "Interface.8.Controllable", "true")
	expect(t, msg, "Interface.10.Role", "internal") // wds0
	expect(t, msg, "Interface.11.Role", "internal") // wan_int2_if
	expect(t, msg, "Interface.12.Role", "internal") // sit0

	if got := resolveIfaceByIndex(opts, 8); got != "ra0" {
		t.Errorf("resolveIfaceByIndex(8) = %q, want ra0", got)
	}
}

func TestInterfaceRole(t *testing.T) {
	cases := []struct {
		name string
		def  bool
		want string
	}{
		{"nas0_0", false, roleUplink}, {"nas10", false, roleUplink}, {"ppp0", false, roleUplink},
		{"br0", false, roleLANBridge}, {"eth0.3", false, roleLANPort}, {"ra3", false, roleWiFi},
		{"rai0", false, roleWiFi}, {"apcli0", false, roleWiFi}, {"wds1", false, roleInternal},
		{"wdsi2", false, roleInternal}, {"lan_int4_if", false, roleInternal}, {"omci", false, roleInternal},
		{"lo", false, roleInternal}, {"eth0", false, roleInternal}, {"usb0", true, roleUplink},
	}
	for _, c := range cases {
		if got := interfaceRole(c.name, c.def); got != c.want {
			t.Errorf("interfaceRole(%q, %v) = %q, want %q", c.name, c.def, got, c.want)
		}
	}
	if ifaceControllable(roleWiFi, true) {
		t.Error("an interface carrying the default route must never be controllable")
	}
}

func TestParseProcNetDevShortLine(t *testing.T) {
	rows := parseProcNetDev("  x0: 1 2 3 4 5 6 7 8 9 10\n")
	if len(rows) != 1 || rows[0].counters {
		t.Fatalf("a line with 10 counters must not be read past its end: %+v", rows)
	}
}

func TestCollectNetworkWLAN(t *testing.T) {
	opts, fake := fixtureOptions(t)
	msg := wusp.NewMessage()
	CollectNetwork(context.Background(), opts, msg)

	expect(t, msg, "RadioNumberOfEntries", "1") // no rai0: 2.4 GHz only
	expect(t, msg, "Radio.1.Band", "2.4GHz")
	expect(t, msg, "Radio.1.Enable", "true")
	expect(t, msg, "Radio.1.Channel", "0")
	expect(t, msg, "Radio.1.AutoChannel", "true")
	expect(t, msg, "Radio.1.Bandwidth", "20/40 MHz")
	expect(t, msg, "Radio.1.Mode", "802.11b/g/n")
	expect(t, msg, "Radio.1.ModeCode", "9")
	expect(t, msg, "Radio.1.Country", "CN")
	expect(t, msg, "Radio.1.Chip", "7603")
	expect(t, msg, "Radio.1.SSIDCount", "4")
	expect(t, msg, "Radio.1.Interfaces", "ra0,ra1,ra2,ra3")

	expect(t, msg, "SSIDNumberOfEntries", "4")
	expect(t, msg, "SSID.1.Name", "CMCC-AP1")
	expect(t, msg, "SSID.1.Interface", "ra0")
	expect(t, msg, "SSID.1.Radio", "1")
	expect(t, msg, "SSID.1.Enable", "true")
	expect(t, msg, "SSID.1.Hidden", "false")
	expect(t, msg, "SSID.1.AuthMode", "WPAPSKWPA2PSK")
	expect(t, msg, "SSID.1.Encryption", "TKIPAES")
	expect(t, msg, "SSID.1.MaxStations", "40")
	expect(t, msg, "SSID.1.StationCount", "1")
	expect(t, msg, "SSID.2.Hidden", "true")
	expect(t, msg, "SSID.2.StationCount", "1")
	expect(t, msg, "SSID.3.Enable", "false")
	absent(t, msg, "SSID.3.AuthMode")

	expect(t, msg, "StationNumberOfEntries", "2")
	expect(t, msg, "Station.1.MACAddress", "a4:50:46:11:22:33")
	expect(t, msg, "Station.1.Interface", "ra0")
	expect(t, msg, "Station.1.Signal", "-45 dBm")
	expect(t, msg, "Station.1.TxBitrate", "72 Mbit/s")
	expect(t, msg, "Station.1.PhyMode", "HTMIX")
	expect(t, msg, "Station.1.Bandwidth", "20M")
	expect(t, msg, "Station.1.PowerSave", "false")
	expect(t, msg, "Station.2.Interface", "ra1")
	expect(t, msg, "Station.2.Signal", "-68 dBm")
	expect(t, msg, "Station.2.PowerSave", "true")

	// Exec budget on a 2.4 GHz-only ONU with 4 SSIDs: 10 radio (TxPowerLevel
	// included) + 6 per SSID + 31 firewall tcapi reads + 1 for the firewall
	// write capabilities (WebCustom_Entry isNPUSupported, the MAC rule
	// limit) + 5 for the Wi-Fi write capabilities (four WebCustom_Entry
	// switches and HT_EXTCHA). Each is a fork on a MIPS box; keep it pinned.
	tcapiCalls := 0
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "/userfs/bin/tcapi ") {
			tcapiCalls++
		}
	}
	if tcapiCalls > 71 {
		t.Errorf("collection ran %d tcapi reads, budget is 71", tcapiCalls)
	}
	for _, call := range fake.calls {
		for _, secret := range []string{"WPAPSK", "KeyPassphrase", "Key1Str", "RADIUS_Key", "WdsKey"} {
			if strings.Contains(call, secret) {
				t.Errorf("collector read a secret: %s", call)
			}
		}
		if strings.Contains(call, "WLan11ac") {
			t.Errorf("read 5 GHz config on a 2.4 GHz-only ONU: %s", call)
		}
		if strings.Contains(call, "show stainfo") || strings.Contains(call, " set ") || strings.Contains(call, "site_survey") || strings.Contains(call, "PartialScan") {
			t.Errorf("collector ran a non-passive command: %s", call)
		}
	}
}

func TestCollectNetworkFirewall(t *testing.T) {
	opts, _ := fixtureOptions(t)
	msg := wusp.NewMessage()
	CollectNetwork(context.Background(), opts, msg)

	expect(t, msg, "Firewall.Enable", "true")
	expect(t, msg, "Firewall.Level", "medium")
	expect(t, msg, "Firewall.SPIEnable", "true")
	expect(t, msg, "Firewall.DoSProtection", "true")
	expect(t, msg, "Firewall.PortScanProtection", "false")

	expect(t, msg, "Firewall.MACFilter.Enable", "true")
	expect(t, msg, "Firewall.MACFilter.Mode", "black")
	expect(t, msg, "Firewall.MACFilter.RuleNumberOfEntries", "2")
	expect(t, msg, "Firewall.MACFilter.Rule.1.Name", "kids-tablet")
	expect(t, msg, "Firewall.MACFilter.Rule.1.MACAddress", "11:22:33:44:55:66")
	expect(t, msg, "Firewall.MACFilter.Rule.1.Enable", "true")
	absent(t, msg, "Firewall.MACFilter.Rule.1.Interface")
	expect(t, msg, "Firewall.MACFilter.Rule.2.EntryIndex", "3")
	expect(t, msg, "Firewall.MACFilter.Rule.2.Enable", "false")

	expect(t, msg, "Firewall.PortFilter.InboundEnable", "true")
	expect(t, msg, "Firewall.PortFilter.InboundMode", "black")
	expect(t, msg, "Firewall.PortFilter.OutboundEnable", "false")
	expect(t, msg, "Firewall.PortFilter.OutboundMode", "white")
	expect(t, msg, "Firewall.PortFilter.RuleNumberOfEntries", "1")
	expect(t, msg, "Firewall.PortFilter.Rule.1.Direction", "inbound")
	expect(t, msg, "Firewall.PortFilter.Rule.1.Name", "block-telnet")
	expect(t, msg, "Firewall.PortFilter.Rule.1.Protocol", "TCP")
	expect(t, msg, "Firewall.PortFilter.Rule.1.DestIP", "192.168.1.0")
	expect(t, msg, "Firewall.PortFilter.Rule.1.DestIPEnd", "192.168.1.255")
	expect(t, msg, "Firewall.PortFilter.Rule.1.DestPort", "23")
	expect(t, msg, "Firewall.PortFilter.Rule.1.DestPortEnd", "23")

	expect(t, msg, "Firewall.URLFilter.Enable", "true")
	expect(t, msg, "Firewall.URLFilter.Mode", "black")
	expect(t, msg, "Firewall.URLFilter.RuleNumberOfEntries", "2")
	expect(t, msg, "Firewall.URLFilter.Rule.2.URL", "ads.example.net")
	expect(t, msg, "Firewall.URLFilter.Rule.2.EntryIndex", "4")

	expect(t, msg, "Firewall.ProtocolFilter.RuleNumberOfEntries", "2")
	expect(t, msg, "Firewall.ProtocolFilter.Rule.1.Port", "LAN1")
	expect(t, msg, "Firewall.ProtocolFilter.Rule.1.Blocked", "PPPoE")
	expect(t, msg, "Firewall.ProtocolFilter.Rule.2.Port", "SSID2")

	// Raw iptables: policies and rules, -N chains skipped.
	expect(t, msg, "Firewall.RuleNumberOfEntries", "3")
	expect(t, msg, "Firewall.Rule.1.Type", "policy")
	expect(t, msg, "Firewall.Rule.3.Raw", "-A FORWARD -j macfilter_chain")
	expect(t, msg, "Firewall.Rule.3.Table", "filter")
}

func TestStaleListFileIsIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "macvalid")
	os.WriteFile(path, []byte("0\nold\n11:22:33:44:55:66\nYes\nN/A\n"), 0o644)
	old := time.Now().Add(-time.Hour)
	os.Chtimes(path, old, old)
	if _, ok := readListFile(dir, "macvalid", time.Now()); ok {
		t.Fatal("a list file older than the count read must not be reported")
	}
}

func TestPortFilterRecordSize(t *testing.T) {
	eleven := strings.Split("2\nNo\nINTERNET\nweb\nTCP\n10.0.0.1\n255.255.255.255\n80\n0.0.0.0\n0.0.0.0\n0", "\n")
	rules := parsePortFilterList(eleven, "outbound", 1, true) // count wins over isCMCCSupported
	if len(rules) != 1 || rules[0].srcPort != "80" || rules[0].dstPortEnd != "" {
		t.Fatalf("11-line record: %+v", rules)
	}
}

func TestCleanTcapiValue(t *testing.T) {
	for in, want := range map[string]string{
		"CMCC-AP1\n":                 "CMCC-AP1",
		"N/A\n":                      "",
		"no attribute information\n": "",
		"My Home WiFi\n":             "My Home WiFi",
	} {
		if got := cleanTcapiValue(in); got != want {
			t.Errorf("cleanTcapiValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMacTableIgnoresWDSTable(t *testing.T) {
	wds := "MAC                IDX AID PSM RSSI0  RSSI1  RSSI2  PhMd      BW    MCS   SGI   STBC\n00:11:22:33:44:55  0   1   0   -50    -50    0      HTMIX     20M   7     0     0\n"
	if got := parseMacTable(wds); len(got) != 0 {
		t.Fatalf("WDS peers are not stations: %+v", got)
	}
}

func TestChannelWidth(t *testing.T) {
	g24, g5 := wlanBands[0], wlanBands[1]
	cases := []struct {
		b                 wlanBand
		ht, coex, vht, ok string
	}{
		{g24, "0", "", "", "20 MHz"}, {g24, "1", "1", "", "20/40 MHz"}, {g24, "1", "0", "", "40 MHz"},
		{g5, "0", "", "1", "20 MHz"}, {g5, "1", "", "0", "20/40 MHz"}, {g5, "1", "", "1", "80 MHz"},
		{g5, "1", "", "2", "160 MHz"},
	}
	for _, c := range cases {
		if got := channelWidth(c.b, c.ht, c.coex, c.vht); got != c.ok {
			t.Errorf("channelWidth(%s, %s, %s, %s) = %q, want %q", c.b.band, c.ht, c.coex, c.vht, got, c.ok)
		}
	}
}

// Every path the network collector writes must exist in the ONU model, or
// the hub drops it.
func TestCollectedNetworkPathsAreModelled(t *testing.T) {
	opts, _ := fixtureOptions(t)
	msg := wusp.NewMessage()
	CollectNetwork(context.Background(), opts, msg)
	model := map[string]bool{}
	for _, p := range wusp.AllWUSPONUParams {
		model[p.Path] = true
	}
	for _, f := range msg.Fields {
		parts := strings.Split(f.Path, ".")
		for i, part := range parts {
			if part != "" && strings.Trim(part, "0123456789") == "" {
				parts[i] = "{i}"
			}
		}
		if template := strings.Join(parts, "."); !model[template] {
			t.Errorf("%s is collected but %s is not in the ONU model", f.Path, template)
		}
	}
}
