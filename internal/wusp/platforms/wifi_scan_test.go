package platforms

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wusp"
)

func TestWiFiScanCoordinatorDeduplicatesCapsAndExcludesOwnBSSID(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	done := make(chan struct{}, 1)
	own, _ := net.ParseMAC("02:00:00:00:00:01")
	entries := make([]iwinfo.ScanEntry, 0, 72)
	entries = append(entries, iwinfo.ScanEntry{BSSID: own, Frequency: 2412, SignalDBM: -10})
	for index := 0; index < 70; index++ {
		mac := net.HardwareAddr{0x02, 0, 0, 1, byte(index / 256), byte(index)}
		entries = append(entries, iwinfo.ScanEntry{BSSID: mac, Frequency: 2412, SignalDBM: -30 - index})
	}
	entries = append(entries, iwinfo.ScanEntry{BSSID: entries[1].BSSID, Frequency: 2412, SignalDBM: -20})
	coordinator := &wifiScanCoordinator{
		states: make(map[int]*wifiScanState),
		now:    func() time.Time { return now },
		cached: func(string) ([]iwinfo.ScanEntry, error) { return nil, nil },
		active: func(context.Context, string) ([]iwinfo.ScanEntry, error) {
			defer func() { done <- struct{}{} }()
			return entries, nil
		},
	}
	interfaces := []iwinfo.WirelessInterface{{Name: "phy0-ap0", PHY: 0, Mode: "ap", HardwareAddr: own}}
	if snapshots := coordinator.snapshotsAndTrigger(interfaces); len(snapshots) != 1 || !snapshots[0].Timestamp.IsZero() {
		t.Fatalf("first snapshot should return immediately before async scan: %+v", snapshots)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("asynchronous scan did not complete")
	}
	snapshot := coordinator.snapshotsAndTrigger(interfaces)[0]
	if len(snapshot.Entries) != wifiScanMaxBSS {
		t.Fatalf("neighbor count=%d want cap %d", len(snapshot.Entries), wifiScanMaxBSS)
	}
	if snapshot.Entries[0].SignalDBM != -20 {
		t.Fatalf("strongest duplicate was not retained: %+v", snapshot.Entries[0])
	}
	for _, entry := range snapshot.Entries {
		if entry.BSSID.String() == own.String() {
			t.Fatal("own BSSID leaked into scan results")
		}
	}
}

func TestWiFiScanFailurePreservesLastSuccess(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	mac, _ := net.ParseMAC("02:00:00:00:10:01")
	coordinator := &wifiScanCoordinator{
		states: map[int]*wifiScanState{0: {interfaceName: "wlan0", entries: []iwinfo.ScanEntry{{BSSID: mac, SignalDBM: -50}}, timestamp: now.Add(-time.Minute)}},
		now:    func() time.Time { return now },
		active: func(context.Context, string) ([]iwinfo.ScanEntry, error) { return nil, errors.New("device busy") },
	}
	coordinator.scanPHY(0, "wlan0", nil)
	state := coordinator.states[0]
	if len(state.entries) != 1 || !state.timestamp.Equal(now.Add(-time.Minute)) {
		t.Fatalf("last successful scan was replaced: %+v", state)
	}
	if state.lastError == "" || state.nextAttempt.Sub(now) != wifiScanInterval {
		t.Fatalf("failure/backoff not recorded: %+v", state)
	}
}

func TestWiFiSuccessfulEmptyScanPublishesZeroNeighbors(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	coordinator := &wifiScanCoordinator{
		states: map[int]*wifiScanState{0: {interfaceName: "wlan0"}},
		now:    func() time.Time { return now },
		active: func(context.Context, string) ([]iwinfo.ScanEntry, error) { return []iwinfo.ScanEntry{}, nil },
	}
	coordinator.scanPHY(0, "wlan0", nil)
	state := coordinator.states[0]
	if state.timestamp.IsZero() || len(state.entries) != 0 || state.lastError != "" {
		t.Fatalf("successful empty scan not authoritative: %+v", state)
	}
	snapshot := wifiPHYScanSnapshot{PHY: 0, Timestamp: state.timestamp, Entries: state.entries}
	msg := wusp.NewMessage()
	appendScanResultFields(msg, "Device.WiFi.DataElements.Network.Device.1.Radio.1.ScanResult.1.", snapshot)
	assertUintField(t, msg, "Device.WiFi.DataElements.Network.Device.1.Radio.1.ScanResult.1.OpClassScanNumberOfEntries", 0)
}

func TestScanMappingUsesRCPIAndCoexistsWithMeshDevice(t *testing.T) {
	remote, _ := net.ParseMAC("02:00:00:00:90:01")
	local, _ := net.ParseMAC("02:00:00:00:10:01")
	neighbor, _ := net.ParseMAC("02:00:00:00:20:01")
	msg := wusp.NewMessage()
	msg.Set("Device.WiFi.DataElements.Network.DeviceNumberOfEntries", wusp.Uint(1))
	msg.Set("Device.WiFi.DataElements.Network.Device.1.ID", wusp.MAC(remote))
	index, selected, ok := resolveLocalDataElementsDevice(msg, []iwinfo.WirelessInterface{{Name: "phy0-ap0", PHY: 0, Mode: "ap", HardwareAddr: local}})
	if !ok || index != 2 || selected.String() != local.String() {
		t.Fatalf("local device resolution index=%d mac=%v ok=%t", index, selected, ok)
	}
	assertUintField(t, msg, "Device.WiFi.DataElements.Network.DeviceNumberOfEntries", 2)

	appendScanResultFields(msg, "Device.WiFi.DataElements.Network.Device.2.Radio.1.ScanResult.1.", wifiPHYScanSnapshot{
		Timestamp: time.Unix(1700000000, 0).UTC(), Width: "20",
		Entries: []iwinfo.ScanEntry{{
			SSID: "nearby", BSSID: neighbor, Frequency: 2412, SignalDBM: -50,
			BSSLoadKnown: true, StationCount: 0, ChannelUtilizationKnown: true, ChannelUtilization: 0,
		}},
		Survey: map[int]iwinfo.SurveyEntry{2412: {Frequency: 2412, Noise: -95, ActiveTime: 100, BusyTime: 20}},
	})
	assertUintField(t, msg, "Device.WiFi.DataElements.Network.Device.2.Radio.1.ScanResult.1.OpClassScan.1.ChannelScan.1.NeighborBSS.1.SignalStrength", 120)
	assertUintField(t, msg, "Device.WiFi.DataElements.Network.Device.2.Radio.1.ScanResult.1.OpClassScan.1.ChannelScan.1.Noise", 15)
	assertUintField(t, msg, "Device.WiFi.DataElements.Network.Device.2.Radio.1.ScanResult.1.OpClassScan.1.ChannelScan.1.Utilization", 51)
	assertUintField(t, msg, "Device.WiFi.DataElements.Network.Device.2.Radio.1.ScanResult.1.OpClassScan.1.ChannelScan.1.NeighborBSS.1.StationCount", 0)
	if signalDBMToRCPI(20) != 220 {
		t.Fatalf("RCPI reserved range was not clamped: %d", signalDBMToRCPI(20))
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast: %v", err)
	}
}
