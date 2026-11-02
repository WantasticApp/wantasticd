package platforms

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

// Captured from macOS 27 (wdutil redacts SSID, BSSID and MAC even for root).
const wdutilSample = `————————————————————————————————————————————————————————————————————
NETWORK
————————————————————————————————————————————————————————————————————
    Primary IPv4         : en1 (Wi-Fi / 9802C1A2)
————————————————————————————————————————————————————————————————————
WIFI
————————————————————————————————————————————————————————————————————
    MAC Address          : <redacted> (hw=<redacted>)
    Interface Name       : en1
    Power                : On [On]
    Op Mode              : STA
    SSID                 : <redacted>
    BSSID                : <redacted>
    RSSI                 : -20 dBm
    CCA                  : 7 %
    Noise                : -98 dBm
    Tx Rate              : 2401.0 Mbps
    Security             : WPA2 Personal
    PHY Mode             : 11ax
    Channel              : 5g60/160
    IPv4 Address         : 192.168.100.9
————————————————————————————————————————————————————————————————————
BLUETOOTH
————————————————————————————————————————————————————————————————————
    Power                : Off
`

func TestDesktopParseWdutil(t *testing.T) {
	w := parseWdutilWiFi(wdutilSample)
	if w.Interface != "en1" || !w.PowerOn || !w.Connected {
		t.Fatalf("interface/power/connected = %q %v %v", w.Interface, w.PowerOn, w.Connected)
	}
	if w.SSID != "" || w.BSSID != nil || w.MAC != nil {
		t.Errorf("redacted values were kept: ssid=%q bssid=%v mac=%v", w.SSID, w.BSSID, w.MAC)
	}
	if w.RSSI != -20 || !w.RSSIKnown || w.Noise != -98 || !w.NoiseKnown {
		t.Errorf("rssi/noise = %d/%d", w.RSSI, w.Noise)
	}
	if w.TxRateKbps != 2401000 || w.Security != "WPA2-Personal" || w.Standard != "ax" {
		t.Errorf("rate/security/standard = %d %q %q", w.TxRateKbps, w.Security, w.Standard)
	}
	if w.Channel != 60 || w.Band != "5GHz" || w.WidthMHz != 160 {
		t.Errorf("channel = %d %s %d", w.Channel, w.Band, w.WidthMHz)
	}

	off := parseWdutilWiFi("WIFI\n    Interface Name : en0\n    Power : Off [Off]\n")
	if off.PowerOn || off.Connected {
		t.Errorf("powered-off adapter reported on/connected")
	}
}

func TestDesktopParseMacChannel(t *testing.T) {
	for in, want := range map[string][3]any{
		"2g6/20":   {6, "2.4GHz", 20},
		"6g37/320": {37, "6GHz", 320},
		"bogus":    {0, "", 0},
	} {
		ch, band, width := parseMacChannel(in)
		if ch != want[0] || band != want[1] || width != want[2] {
			t.Errorf("%s = %d %s %d", in, ch, band, width)
		}
	}
}

func TestDesktopParseNetstat(t *testing.T) {
	out := `Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                      87971786     0 173037517192 87971786     0 173037517192     0
lo0        16384 127           127.0.0.1       87971786     - 173037517192 87971786     - 173037517192     -
gif0*      1280  <Link#2>                             0     0          0        0     0          0     0
en1        1500  <Link#11>   c8:80:6d:51:f9:f1  1200     3     900000      800     1     500000     0
`
	c := parseNetstatIBN(out)
	if got := c["en1"]; got.PacketsReceived != 1200 || got.ErrorsReceived != 3 || got.BytesReceived != 900000 || got.PacketsSent != 800 || got.BytesSent != 500000 {
		t.Errorf("en1 = %+v", got)
	}
	if got := c["lo0"]; got.BytesReceived != 173037517192 {
		t.Errorf("lo0 (no MAC column) = %+v", got)
	}
	if _, ok := c["gif0"]; !ok {
		t.Error("an interface marked down (gif0*) was dropped")
	}
}

func TestDesktopParseHardwarePortsAndProfiler(t *testing.T) {
	ports := parseHardwarePorts("Hardware Port: Ethernet\nDevice: en0\nEthernet Address: c8:80:6d:4e:c4:d4\n\nHardware Port: Wi-Fi\nDevice: en1\n")
	if ports["en0"] != "Ethernet" || ports["en1"] != "Wi-Fi" {
		t.Errorf("ports = %v", ports)
	}
	hw := parseSPHardware([]byte(`{"SPHardwareDataType":[{"chip_type":"Apple M6","machine_model":"Mac18,5","machine_name":"Mac mini","model_number":"Z1UA00040LL/A","serial_number":"MVM0YFKQLW"}]}`))
	if hw.MachineName != "Mac mini" || hw.MachineModel != "Mac18,5" || hw.Serial != "MVM0YFKQLW" || hw.Chip != "Apple M6" {
		t.Errorf("hardware = %+v", hw)
	}
	if got := zoneFromLocaltime("/var/db/timezone/zoneinfo/America/Matamoros"); got != "America/Matamoros" {
		t.Errorf("zone = %q", got)
	}
}

func TestDesktopWindowsParsers(t *testing.T) {
	if got := parseW32TimeServers("time.windows.com,0x9 pool.ntp.org,0x8  10.0.0.1"); len(got) != 3 || got[0] != "time.windows.com" || got[2] != "10.0.0.1" {
		t.Errorf("w32time servers = %v", got)
	}
	if got := windowsProductName("Windows 10 Pro", 22631); got != "Windows 11 Pro" {
		t.Errorf("product = %q", got)
	}
	if got := windowsProductName("Windows 10 Pro", 19045); got != "Windows 10 Pro" {
		t.Errorf("product = %q", got)
	}
	if windowsWiFiBand(6, 0) != "2.4GHz" || windowsWiFiBand(149, 0) != "5GHz" || windowsWiFiBand(5, 5975000) != "6GHz" {
		t.Error("band from channel/frequency")
	}
	if windowsSecurityMode(7, true) != "WPA2-Personal" || windowsSecurityMode(9, true) != "WPA3-Personal" || windowsSecurityMode(1, false) != "None" {
		t.Error("security mode mapping")
	}
}

// smbiosStruct builds one SMBIOS structure with its string set.
func smbiosStruct(kind byte, serialIndex byte, strs ...string) []byte {
	formatted := make([]byte, 0x08)
	formatted[0], formatted[1] = kind, byte(len(formatted))
	formatted[0x07] = serialIndex
	out := append([]byte(nil), formatted...)
	for _, s := range strs {
		out = append(out, s...)
		out = append(out, 0)
	}
	if len(strs) == 0 {
		out = append(out, 0)
	}
	return append(out, 0)
}

func TestDesktopSMBIOSSerial(t *testing.T) {
	table := append(smbiosStruct(0, 0), smbiosStruct(1, 2, "Dell Inc.", "ABC1234")...)
	if got := parseSMBIOSSerial(table); got != "ABC1234" {
		t.Errorf("system serial = %q", got)
	}
	placeholder := append(smbiosStruct(1, 1, "To Be Filled By O.E.M."), smbiosStruct(2, 1, "BOARD-77")...)
	if got := parseSMBIOSSerial(placeholder); got != "BOARD-77" {
		t.Errorf("baseboard fallback = %q", got)
	}
	if got := parseSMBIOSSerial([]byte{1, 0xff, 0}); got != "" {
		t.Errorf("truncated table = %q", got)
	}
	header := []byte{0, 3, 4, 0, byte(len(table)), 0, 0, 0}
	if got := parseSMBIOSSerial(rawSMBIOSTable(append(header, table...))); got != "ABC1234" {
		t.Errorf("with RawSMBIOSData header = %q", got)
	}
}

func TestDesktopHostnames(t *testing.T) {
	if got := desktopHostnameLabel("Karim’s MacBook Pro"); got != "Karims-MacBook-Pro" {
		t.Errorf("label = %q", got)
	}
	for _, bad := range []string{"", "-edge", "a b", "12345", "x;reboot"} {
		if validDesktopHostname(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := validDesktopHostname("office-pc-2"); err != nil {
		t.Errorf("valid name refused: %v", err)
	}
}

func TestDesktopLastUplinkGuard(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	up := net.FlagUp | net.FlagRunning
	ifaces := []net.Interface{
		{Name: "en0", Flags: up, HardwareAddr: mac},
		{Name: "en1", Flags: up, HardwareAddr: mac},
		{Name: "utun4", Flags: up},
	}
	addrs := map[string]string{"en0": "192.168.1.5/24", "en1": "169.254.3.3/16", "utun4": "10.7.0.2/32"}
	lookup := func(i net.Interface) ([]net.Addr, error) {
		_, ipNet, _ := net.ParseCIDR(addrs[i.Name])
		ip, _, _ := net.ParseCIDR(addrs[i.Name])
		ipNet.IP = ip
		return []net.Addr{ipNet}, nil
	}
	if !isLastUplink("en0", ifaces, lookup) {
		t.Error("en0 is the only routed uplink (en1 is link-local, utun4 a tunnel)")
	}
	if isLastUplink("en1", ifaces, lookup) {
		t.Error("en1 carries no routable address; turning it off cannot cut the device off")
	}
	addrs["en1"] = "10.1.1.9/24"
	if isLastUplink("en0", ifaces, lookup) {
		t.Error("en1 is also connected; en0 is not the last uplink")
	}
}

func TestDesktopTimeZoneMaps(t *testing.T) {
	for windowsName, iana := range windowsZoneToIANA {
		if back := ianaToWindowsZone[iana]; back != windowsName {
			t.Errorf("%s -> %s -> %s", windowsName, iana, back)
		}
		if runtime.GOOS != "windows" {
			if _, err := time.LoadLocation(iana); err != nil {
				t.Errorf("%s maps to unknown zone %s", windowsName, iana)
			}
		}
	}
	if ianaToWindowsZone["Europe/Madrid"] != "Romance Standard Time" {
		t.Error("alias Europe/Madrid")
	}
}

// TestDesktopMessageValidates builds a full desktop reading and checks that
// every field passes the data-model schema: change notifications that fail
// validation are dropped.
func TestDesktopMessageValidates(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	snap := &desktopSnapshot{
		Manufacturer: "Apple", ModelName: "Mac mini", ModelNumber: "Z1UA00040LL/A", HardwareVersion: "Mac18,5",
		SoftwareVersion: "27.0.1", Description: "macOS 27.0.1 (26A434)", SerialNumber: "MVM0YFKQLW",
		Hostname: "mini", ComputerName: "Karim’s Mac mini", ProcessorModel: "Apple M6", Architecture: "arm64",
		MemTotalKiB: 32 << 20, MemFreeKiB: 1 << 20, UptimeSeconds: 3600,
		TimeZone: "America/Matamoros", Time: timeState{Enabled: true, Known: true}, NTPServers: []string{"time.apple.com"},
		Interfaces: map[string]desktopInterface{},
	}
	for i, iface := range ipInterfaceOrder(ifaces) {
		snap.Interfaces[iface.Name] = desktopInterface{SpeedMbps: 1000, StatsKnown: true, Stats: desktopCounters{BytesReceived: 10, BytesSent: 20}}
		if i == 0 {
			snap.WiFi = []desktopWiFi{{
				Interface: iface.Name, MAC: net.HardwareAddr{2, 0, 0, 0, 0, 9}, PowerOn: true, Connected: true,
				SSID: "Office", BSSID: net.HardwareAddr{2, 0, 0, 0, 0, 10}, RSSI: -55, RSSIKnown: true, Noise: -95, NoiseKnown: true,
				Channel: 36, Band: "5GHz", WidthMHz: 80, Standard: "ax", TxRateKbps: 866000, RxRateKbps: 780000, Security: "WPA3-Personal",
			}}
		}
	}
	snap.WiFi = append(snap.WiFi, desktopWiFi{Interface: "en9"})

	runner := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("not run in tests") }
	b := newHostBackend(KindMacOS, Options{CommandRunner: runner, StatePath: filepath.Join(t.TempDir(), "state.json")})
	msg := b.collectDesktop(context.Background(), snap)
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("desktop fields fail validation: %v", err)
	}
	want := map[string]string{
		"Device.DeviceInfo.ModelName":                   "Mac mini",
		"Device.DeviceInfo.FriendlyName":                "Karim’s Mac mini",
		"Device.DeviceInfo.Processor.1.Architecture":    "arm",
		"Device.Time.LocalTimeZone":                     "America/Matamoros",
		"Device.Time.Client.1.Servers":                  "time.apple.com",
		"Device.WiFi.EndPointNumberOfEntries":           "2",
		"Device.WiFi.EndPoint.2.ProfileNumberOfEntries": "0",
	}
	if len(snap.WiFi) > 1 && snap.WiFi[0].Interface != "en9" {
		want["Device.WiFi.EndPoint.1.Stats.SignalStrength"] = "-55"
		want["Device.WiFi.EndPoint.1.Profile.1.SSID"] = "Office"
		want["Device.WiFi.Radio.1.OperatingFrequencyBand"] = "5GHz"
		want["Device.IP.Interface.1.LowerLayers"] = "Device.WiFi.SSID.1."
	}
	got := make(map[string]string, len(msg.Fields))
	for _, f := range msg.Fields {
		got[f.Path] = wusp.ValueToString(f.Val)
	}
	for path, value := range want {
		if got[path] != value {
			t.Errorf("%s = %q, want %q", path, got[path], value)
		}
	}
}

func TestTR181Architecture(t *testing.T) {
	for in, want := range map[string]string{
		"x86_64\n": "x86_64", "amd64": "x86_64", "aarch64": "arm", "arm64": "arm", "armv7l": "arm",
		"i686": "i386", "mips": "mipseb", "mipsel": "mipsel", "ppc64le": "powerpc", "riscv64": "",
	} {
		if got := tr181Architecture(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}
