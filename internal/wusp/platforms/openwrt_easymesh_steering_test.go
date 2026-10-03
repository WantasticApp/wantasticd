package platforms

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

const easyMeshNativeSteerFixture = `
Topology Discovery Service module status:
QCA IEEE 1905.1 device: 00:03:7F:BA:DB:AD, IPv4 address: 192.168.200.1
Local interfaces:
ath2 (R=0) WLAN6G 02:03:7F:12:54:54 117 AP 20MHz
SSID: mesh-backhaul, ESSID: 0
Map BSS Type : 0x40, Role: |BH|
-- DB (2 entries):
#1: QCA IEEE 1905.1 device: E0:5D:54:4B:E5:DC, IPv4 address: 192.168.200.141
Remote connections (Directly connected to self):
ath2 (R=0) WLAN6G E0:5D:54:4B:E5:E2 3193 Yes Yes 25389 117 STA
BSSID: 02:03:7F:12:54:54
Map BSS Type : 0x40, Role: |BH|
Remote connections (Not directly connected to self):
1 (R=1) WLAN6G E2:5D:54:4B:E5:E3 1 AP 20MHz
SSID: mesh-backhaul, ESSID: 0
Map BSS Type : 0x40, Role: |BH|
4 Radios:
E0:5D:54:4B:E5:E2 WLAN6G 117 13 LPI
E0:5D:54:4B:E5:E3 WLAN6G 1 18 LPI
#2: QCA IEEE 1905.1 device: E0:5D:54:4B:E6:CF, IPv4 address: 192.168.200.227
Remote connections (Directly connected to self):
ath2 (R=0) WLAN6G E0:5D:54:4B:E6:D5 2585 Yes Yes 25374 117 STA
BSSID: 02:03:7F:12:54:54
Map BSS Type : 0x40, Role: |BH|
4 Radios:
E0:5D:54:4B:E6:D5 WLAN6G 117 13 LPI
E0:5D:54:4B:E6:D6 WLAN6G 33 30 LPI
`

func TestParseEasyMeshNativeDatabaseBuildsBackhaulSteer(t *testing.T) {
	database, err := parseEasyMeshNativeDatabase(easyMeshNativeSteerFixture)
	if err != nil {
		t.Fatalf("parseEasyMeshNativeDatabase: %v", err)
	}
	steer, err := database.backhaulSteer("E0:5D:54:4B:E6:CF", "E0:5D:54:4B:E5:DC")
	if err != nil {
		t.Fatalf("backhaulSteer: %v", err)
	}
	if steer.staMAC != "E0:5D:54:4B:E6:D5" ||
		steer.targetBSSID != "E2:5D:54:4B:E5:E3" ||
		steer.opClass != 131 || steer.channel != 1 {
		t.Fatalf("steer=%+v", steer)
	}
}

func TestEasyMeshNativeDatabaseRejectsNonBackhaulParent(t *testing.T) {
	fixture := strings.Replace(
		easyMeshNativeSteerFixture,
		"Map BSS Type : 0x40, Role: |BH|\n4 Radios:\nE0:5D:54:4B:E5:E2",
		"Map BSS Type : 0x00, Role:\n4 Radios:\nE0:5D:54:4B:E5:E2",
		1,
	)
	database, err := parseEasyMeshNativeDatabase(fixture)
	if err != nil {
		t.Fatalf("parseEasyMeshNativeDatabase: %v", err)
	}
	_, err = database.backhaulSteer("E0:5D:54:4B:E6:CF", "E0:5D:54:4B:E5:DC")
	if err == nil || !strings.Contains(err.Error(), "not advertising an operational backhaul BSS") {
		t.Fatalf("backhaulSteer error=%v", err)
	}
}

func TestExecuteEasyMeshBackhaulSteerUsesNativeControllerCommand(t *testing.T) {
	const starTopology = `{"topo":[{"mac":"00:03:7F:BA:DB:AD","pMac":"","hops":0},{"mac":"E0:5D:54:4B:E5:DC","pMac":"00:03:7F:BA:DB:AD","hops":1},{"mac":"E0:5D:54:4B:E6:CF","pMac":"00:03:7F:BA:DB:AD","hops":1}]}`
	const chainTopology = `{"topo":[{"mac":"00:03:7F:BA:DB:AD","pMac":"","hops":0},{"mac":"E0:5D:54:4B:E5:DC","pMac":"00:03:7F:BA:DB:AD","hops":1},{"mac":"E0:5D:54:4B:E6:CF","pMac":"E0:5D:54:4B:E5:DC","hops":2}]}`

	liveTopology := starTopology
	var gotName string
	gotArgs := []string{}
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		EasyMeshVerifyInterval: time.Millisecond,
		CommandRunner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			gotName = name
			gotArgs = append(gotArgs, args...)
			liveTopology = chainTopology
			return nil, nil
		},
		UbusParamCaller: func(
			_ context.Context,
			object string,
			method string,
			_ map[string]any,
		) ([]byte, error) {
			if object == "device" && method == "getRealTopo" {
				return []byte(liveTopology), nil
			}
			return nil, wusp.ErrUSPPathUnsupported
		},
	})

	steer := easyMeshBackhaulSteer{
		childALID:   "E0:5D:54:4B:E6:CF",
		parentALID:  "E0:5D:54:4B:E5:DC",
		staMAC:      "E0:5D:54:4B:E6:D5",
		targetBSSID: "E2:5D:54:4B:E5:E3",
		opClass:     131,
		channel:     1,
	}
	if err := backend.executeEasyMeshBackhaulSteer(t.Context(), steer); err != nil {
		t.Fatalf("executeEasyMeshBackhaulSteer: %v", err)
	}
	wantArgs := []string{
		"map", "bhs",
		"E0:5D:54:4B:E6:CF",
		"E0:5D:54:4B:E6:D5",
		"E2:5D:54:4B:E5:E3",
		"131", "1",
	}
	if gotName != easyMeshCommandPath || !slices.Equal(gotArgs, wantArgs) {
		t.Fatalf("command=%s %v want %s %v", gotName, gotArgs, easyMeshCommandPath, wantArgs)
	}
}

func TestEasyMeshOperatingClass(t *testing.T) {
	tests := []struct {
		name    string
		medium  string
		channel int
		want    int
	}{
		{name: "2.4 GHz", medium: "WLAN2G", channel: 6, want: 81},
		{name: "5 GHz low", medium: "WLAN5G", channel: 44, want: 115},
		{name: "5 GHz high", medium: "WLAN5G", channel: 149, want: 124},
		{name: "6 GHz", medium: "WLAN6G", channel: 117, want: 131},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := easyMeshOperatingClass(test.medium, test.channel)
			if err != nil || got != test.want {
				t.Fatalf("easyMeshOperatingClass(%q, %d)=(%d, %v), want %d", test.medium, test.channel, got, err, test.want)
			}
		})
	}
}
