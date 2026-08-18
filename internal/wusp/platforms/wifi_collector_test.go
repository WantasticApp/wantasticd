package platforms

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wusp"
)

func TestOpenWrtWirelessStatusPrefersLocalUbus(t *testing.T) {
	httpCalls := 0
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		CommandRunner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "ubus" && len(args) == 3 && args[0] == "call" && args[1] == "network.wireless" && args[2] == "status" {
				return []byte(`{"radio0":{"up":true,"interfaces":[{"section":"default_radio0","ifname":"phy0-ap0","up":true,"config":{"mode":"ap"}}]}}`), nil
			}
			return nil, errors.New("unexpected command")
		},
		UbusCaller: func(string, string, time.Duration) ([]byte, error) {
			httpCalls++
			return nil, errors.New("anonymous access denied")
		},
	})
	radios := backend.readWirelessRadioStatus()
	if got := radios["radio0"].Interfaces[0].IfName; got != "phy0-ap0" {
		t.Fatalf("runtime ifname=%q want phy0-ap0", got)
	}
	if httpCalls != 0 {
		t.Fatalf("HTTP ubus called %d times after local success", httpCalls)
	}
}

func TestOpenWrtUCIDoesNotInventInterfaceFromSectionName(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "wireless"), []byte(`config wifi-device 'radio0'
	option band '5g'
config wifi-iface 'default_radio0'
	option device 'radio0'
	option mode 'ap'
	option ssid 'test'
`), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{UCIConfigDir: configDir, NetClassDir: filepath.Join(root, "sys", "class", "net")})
	radios := backend.readWirelessRadioStatusFromUCI()
	if got := radios["radio0"].Interfaces[0].IfName; got != "" {
		t.Fatalf("UCI section was treated as runtime interface: %q", got)
	}
}

func TestOpenWrtRadioInventoryKeepsUCIDeviceIdentity(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "config")
	netClassDir := filepath.Join(root, "sys", "class", "net")
	if err := os.MkdirAll(filepath.Join(netClassDir, "phy0-ap0"), 0o755); err != nil {
		t.Fatal(err)
	}
	wirelessPath := filepath.Join(configDir, "wireless")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wirelessPath, []byte(`config wifi-device 'qcawifi0'
	option band '5g'
	option channel '36'
config wifi-iface 'main_ap'
	option device 'qcawifi0'
	option mode 'ap'
`), 0o600); err != nil {
		t.Fatal(err)
	}

	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir: configDir,
		NetClassDir:  netClassDir,
		CommandRunner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "ubus" && len(args) == 3 && args[0] == "call" && args[1] == "network.wireless" && args[2] == "status" {
				return []byte(`{"phy0":{"up":true,"config":{"band":"6g","channel":"149"},"interfaces":[{"section":"main_ap","ifname":"phy0-ap0","up":true,"config":{"mode":"ap"}}]}}`), nil
			}
			return nil, errors.New("unavailable")
		},
		UbusCaller: func(string, string, time.Duration) ([]byte, error) {
			return nil, errors.New("HTTP ubus denied")
		},
	})

	radios := backend.openWrtWirelessRadios()
	if len(radios) != 1 {
		t.Fatalf("radio inventory=%v want exactly one UCI-backed radio", radios)
	}
	radio, ok := radios["qcawifi0"]
	if !ok {
		t.Fatalf("UCI radio identity missing: %v", radios)
	}
	if _, exists := radios["phy0"]; exists {
		t.Fatalf("runtime PHY leaked into OpenWrt radio identity: %v", radios)
	}
	if got := configString(radio.Config, "band"); got != "5g" {
		t.Fatalf("radio band=%q want UCI value 5g", got)
	}
	if len(radio.Interfaces) != 1 || radio.Interfaces[0].IfName != "phy0-ap0" || !radio.Interfaces[0].Up {
		t.Fatalf("runtime interface was not merged into UCI radio: %+v", radio.Interfaces)
	}

	if err := backend.Set(context.Background(), "Device.WiFi.Radio.1.Channel", wusp.Uint(44)); err != nil {
		t.Fatalf("Set(Channel): %v", err)
	}
	updated, err := os.ReadFile(wirelessPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "config wifi-device 'qcawifi0'\n\toption band '5g'\n\toption channel '44'") {
		t.Fatalf("Set did not update UCI wifi-device section:\n%s", updated)
	}
}

func TestOpenWrtRuntimeDiscoversHostapdObject(t *testing.T) {
	root := t.TempDir()
	netClass := filepath.Join(root, "sys", "class", "net")
	if err := os.MkdirAll(filepath.Join(netClass, "phy0-ap0"), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		NetClassDir: netClass,
		CommandRunner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "ubus" && len(args) >= 2 && args[0] == "list" {
				return []byte("hostapd.phy0-ap0\n"), nil
			}
			return nil, errors.New("unavailable")
		},
		WiFiInfo: func(string) (*iwinfo.InterfaceInfo, error) {
			return &iwinfo.InterfaceInfo{Mode: 1}, nil
		},
	})
	radios := backend.enrichWirelessRuntime(nil)
	if got := radios["phy0"].Interfaces; len(got) != 1 || got[0].IfName != "phy0-ap0" {
		t.Fatalf("hostapd runtime discovery=%+v", got)
	}
}

func TestDecodeIWInfoAssociationsTracksKnownZero(t *testing.T) {
	stations := decodeIWInfoAssociations([]byte(`{"results":[{
		"mac":"02:00:00:00:00:01","signal":-52,"noise":-95,
		"authorized":false,"connected_time":0,
		"rx":{"bytes":0,"packets":0,"rate":0},
		"tx":{"bytes":0,"packets":0,"rate":0,"retries":0,"failed":0}
	}]}`))
	if len(stations) != 1 {
		t.Fatalf("stations=%d want 1", len(stations))
	}
	station := stations[0]
	if !station.ConnectedTimeKnown || !station.RxBytesKnown || !station.TxRetriesKnown || !station.RxRateKnown {
		t.Fatalf("known zero presence lost: %+v", station)
	}
	if !station.AuthenticationKnown || station.Authenticated {
		t.Fatalf("known false authentication lost: %+v", station)
	}
}

func TestAssociatedDeviceOmitsUnknownAndEmitsKnownZero(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	msg := wusp.NewMessage()
	appendWiFiAssociatedDeviceFields(msg, "Device.WiFi.AccessPoint.1.AssociatedDevice.1.", iwinfo.AssocEntry{MAC: mac}, time.Unix(1700000000, 0))
	if _, found := msg.Get("Device.WiFi.AccessPoint.1.AssociatedDevice.1.Stats.BytesSent"); found {
		t.Fatal("unknown byte counter was emitted as zero")
	}
	if _, found := msg.Get("Device.WiFi.AccessPoint.1.AssociatedDevice.1.AuthenticationState"); found {
		t.Fatal("unknown authentication state was emitted")
	}

	known := wusp.NewMessage()
	appendWiFiAssociatedDeviceFields(known, "Device.WiFi.AccessPoint.1.AssociatedDevice.1.", iwinfo.AssocEntry{
		MAC: mac, TxBytesKnown: true, TxPacketsKnown: true, TxFailedKnown: true, TxRetriesKnown: true,
	}, time.Unix(1700000000, 0))
	assertUintField(t, known, "Device.WiFi.AccessPoint.1.AssociatedDevice.1.Stats.BytesSent", 0)
	assertUintField(t, known, "Device.WiFi.AccessPoint.1.AssociatedDevice.1.Stats.PacketsSent", 0)
	assertUintField(t, known, "Device.WiFi.AccessPoint.1.AssociatedDevice.1.Stats.ErrorsSent", 0)
}

func TestOptionalCommandStationParsers(t *testing.T) {
	iwStations := parseIWStationDump(`Station 02:00:00:00:00:01 (on phy0-ap0)
	inactive time: 0 ms
	rx bytes: 0
	tx bytes: 42
	signal: -51 dBm
	tx bitrate: 86.7 MBit/s
	connected time: 10 seconds
`)
	if len(iwStations) != 1 || !iwStations[0].InactiveKnown || !iwStations[0].RxBytesKnown || iwStations[0].TxRate != 86700 {
		t.Fatalf("iw station parse=%+v", iwStations)
	}
	iwinfoStations := parseIWInfoCLIStations(`02:00:00:00:00:02  -55 dBm / -95 dBm (SNR 40)  0 ms ago
	RX: 24.0 MBit/s, MCS 3
	TX: 36.0 MBit/s, MCS 4
`)
	if len(iwinfoStations) != 1 || iwinfoStations[0].Signal != -55 || iwinfoStations[0].Noise != -95 || iwinfoStations[0].RxRate != 24000 || iwinfoStations[0].TxRate != 36000 {
		t.Fatalf("iwinfo station parse=%+v", iwinfoStations)
	}
}

func TestLinuxWiFiInventoryMergesDynamicAPVLANStations(t *testing.T) {
	apMAC, _ := net.ParseMAC("02:00:00:00:10:01")
	stationMAC, _ := net.ParseMAC("02:00:00:00:20:01")
	interfaces := []iwinfo.WirelessInterface{
		{Name: "phy0-ap0", PHY: 0, Mode: "ap", Up: true, HardwareAddr: apMAC, Frequency: 5180, ChannelWidth: "80"},
		{Name: "wlan0.10", PHY: 0, Mode: "ap-vlan", Up: true, HardwareAddr: apMAC, Frequency: 5180, ChannelWidth: "80"},
	}
	collections := map[string]linuxStationCollection{
		"phy0-ap0": {Succeeded: true},
		"wlan0.10": {Succeeded: true, Stations: []iwinfo.AssocEntry{{MAC: stationMAC, Signal: -48, SignalKnown: true}}},
	}
	msg := wusp.NewMessage()
	hosts := appendLinuxWiFiInventory(msg, interfaces, collections, time.Unix(1700000000, 0))
	assertUintField(t, msg, "Device.WiFi.RadioNumberOfEntries", 1)
	assertUintField(t, msg, "Device.WiFi.SSIDNumberOfEntries", 1)
	assertUintField(t, msg, "Device.WiFi.AccessPointNumberOfEntries", 1)
	assertUintField(t, msg, "Device.WiFi.AccessPoint.1.AssociatedDeviceNumberOfEntries", 1)
	assertMACField(t, msg, "Device.WiFi.AccessPoint.1.AssociatedDevice.1.MACAddress", stationMAC.String())
	if hosts[stationMAC.String()] == "" {
		t.Fatalf("station was not linked into host inventory: %+v", hosts)
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast: %v", err)
	}
}

func TestLinuxWiFiSuccessfulEmptyIsAuthoritativeButFailureIsNot(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:10:01")
	interfaces := []iwinfo.WirelessInterface{{Name: "phy0-ap0", PHY: 0, Mode: "ap", Up: true, HardwareAddr: mac, Frequency: 2412, ChannelWidth: "20"}}

	empty := wusp.NewMessage()
	appendLinuxWiFiInventory(empty, append([]iwinfo.WirelessInterface(nil), interfaces...), map[string]linuxStationCollection{
		"phy0-ap0": {Succeeded: true},
	}, time.Now())
	assertUintField(t, empty, "Device.WiFi.AccessPoint.1.AssociatedDeviceNumberOfEntries", 0)

	failed := wusp.NewMessage()
	appendLinuxWiFiInventory(failed, append([]iwinfo.WirelessInterface(nil), interfaces...), map[string]linuxStationCollection{
		"phy0-ap0": {Succeeded: false, Errors: []string{"nl80211: failed"}},
	}, time.Now())
	if _, found := failed.Get("Device.WiFi.AccessPoint.1.AssociatedDeviceNumberOfEntries"); found {
		t.Fatal("total station source failure emitted an authoritative zero")
	}
}

func TestHostMappingLinksStationAndIPv4IPv6Neighbors(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:20:01")
	msg := wusp.NewMessage()
	appendLANHostFields(msg, []*openWrtLANHost{{
		mac:              mac,
		associatedDevice: "Device.WiFi.AccessPoint.1.AssociatedDevice.1.",
		layer3Interface:  "Device.IP.Interface.2.",
		interfaceType:    "Wi-Fi",
		active:           true,
		ipv4:             []net.IP{net.ParseIP("192.0.2.10").To4()},
		ipv6:             []net.IP{net.ParseIP("2001:db8::10").To16()},
	}})
	assertUintField(t, msg, "Device.Hosts.HostNumberOfEntries", 1)
	assertStringField(t, msg, "Device.Hosts.Host.1.AssociatedDevice", "Device.WiFi.AccessPoint.1.AssociatedDevice.1.")
	assertStringField(t, msg, "Device.Hosts.Host.1.Layer3Interface", "Device.IP.Interface.2.")
	assertUintField(t, msg, "Device.Hosts.Host.1.IPv4AddressNumberOfEntries", 1)
	assertUintField(t, msg, "Device.Hosts.Host.1.IPv6AddressNumberOfEntries", 1)
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast: %v", err)
	}
}
