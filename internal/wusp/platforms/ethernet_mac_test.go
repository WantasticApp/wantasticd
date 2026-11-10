package platforms

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// fakeNetClass lays out /sys/class/net entries: each name maps to the
// markers (subdirectories) and MAC it should have.
func fakeNetClass(t *testing.T, ifaces map[string][]string, macs map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, markers := range ifaces {
		base := filepath.Join(dir, name)
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, m := range markers {
			if err := os.MkdirAll(filepath.Join(base, m), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if mac := macs[name]; mac != "" {
			if err := os.WriteFile(filepath.Join(base, "address"), []byte(mac+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}

// Wired ports carry their MAC in Device.Ethernet.Interface; bridges and radios do not.
func TestWiredPortsReportEthernetMAC(t *testing.T) {
	netClass := fakeNetClass(t, map[string][]string{
		"eth0":   {"device"},
		"br-lan": {"bridge"},
		"ath0":   {"wireless"},
		"lan1":   {"device"},
	}, nil)
	ifaces := []net.Interface{
		{Index: 1, Name: "br-lan", HardwareAddr: mustMAC(t, "e0:5d:54:4b:e9:10"), Flags: net.FlagUp},
		{Index: 2, Name: "eth0", HardwareAddr: mustMAC(t, "e0:5d:54:4b:e9:0e"), Flags: net.FlagUp},
		{Index: 3, Name: "ath0", HardwareAddr: mustMAC(t, "e2:5d:54:4b:e9:11"), Flags: net.FlagUp},
		{Index: 4, Name: "lan1", HardwareAddr: mustMAC(t, "e0:5d:54:4b:e9:0f")},
	}
	msg := wusp.NewMessage()
	appendNetworkInterfaces(msg, netClass, ifaces)

	get := func(path string) string {
		v, ok := msg.Get(path)
		if !ok {
			return ""
		}
		return strings.ToLower(wusp.ValueToString(v))
	}
	if n := get("Device.Ethernet.InterfaceNumberOfEntries"); n != "2" {
		t.Fatalf("ethernet entries = %q, want 2 (eth0, lan1)", n)
	}
	if get("Device.Ethernet.Interface.1.Name") != "eth0" || !strings.Contains(get("Device.Ethernet.Interface.1.MACAddress"), "e0:5d:54:4b:e9:0e") {
		t.Fatalf("eth0 entry: name=%q mac=%q", get("Device.Ethernet.Interface.1.Name"), get("Device.Ethernet.Interface.1.MACAddress"))
	}
	if get("Device.Ethernet.Interface.2.Name") != "lan1" || get("Device.Ethernet.Interface.2.Status") != "down" {
		t.Fatalf("lan1 entry: name=%q status=%q", get("Device.Ethernet.Interface.2.Name"), get("Device.Ethernet.Interface.2.Status"))
	}
	if !strings.Contains(get("Device.IP.Interface.2.LowerLayers"), "device.ethernet.interface.1.") {
		t.Fatalf("eth0 IP interface must point at its Ethernet entry, got %q", get("Device.IP.Interface.2.LowerLayers"))
	}
}

// The OUI comes from eth0 even when another interface sorts first.
func TestManufacturerOUIPrefersEth0(t *testing.T) {
	netClass := fakeNetClass(t,
		map[string][]string{"ath0": {"wireless"}, "bond0": nil, "eth0": {"device"}},
		map[string]string{"ath0": "02:11:22:33:44:55", "bond0": "aa:bb:cc:00:00:01", "eth0": "e0:5d:54:4b:e9:0e"})
	b := &OpenWrtBackend{netClassDir: netClass}
	if got := b.readManufacturerOUI(); got != "E05D54" {
		t.Fatalf("OUI = %q, want E05D54 from eth0", got)
	}
}
