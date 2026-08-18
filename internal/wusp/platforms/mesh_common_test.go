package platforms

import (
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func TestAppendMeshSnapshotDeduplicatesIdentityAcrossParents(t *testing.T) {
	root := &meshNode{
		name: "gateway",
		mac:  "02:00:00:00:00:01",
		role: "controller",
		children: []*meshNode{
			{
				name:      "device-a",
				mac:       "02:00:00:00:00:02",
				sourceHop: 1,
				hasHop:    true,
			},
			{
				name: "relay",
				mac:  "02:00:00:00:00:03",
				children: []*meshNode{
					{
						name:      "device-a",
						mac:       "02-00-00-00-00-02",
						ip:        "192.168.200.91",
						sourceHop: 2,
						hasHop:    true,
					},
				},
			},
		},
	}
	message := wusp.NewMessage()
	appendMeshSnapshot(message, meshSnapshot{
		protocol:   "OpenMesh",
		topology:   root,
		sampleTime: time.Unix(1_700_000_000, 0).UTC(),
	})

	assertUintField(t, message, "Device.WUSP_MeshTelemetry.NodeNumberOfEntries", 3)
	assertUintField(t, message, "Device.WUSP_MeshTelemetry.LinkNumberOfEntries", 2)
	assertStringField(t, message, "Device.WUSP_MeshTelemetry.Node.2.Hostname", "device-a")
	assertStringField(t, message, "Device.WUSP_MeshTelemetry.Node.2.Address", "192.168.200.91")
	assertUintField(t, message, "Device.WUSP_MeshTelemetry.Node.2.HopCount", 1)
	assertStringField(t, message, "Device.WUSP_MeshTelemetry.Node.2.ParentNode", "Device.WUSP_MeshTelemetry.Node.1.")
	if _, exists := message.Get("Device.WUSP_MeshTelemetry.Node.4.Hostname"); exists {
		t.Fatal("duplicate mesh identity was published as a fourth node")
	}
}

func TestMeshBackhaulLinkTypeDoesNotConfuseLowBandWithLAN(t *testing.T) {
	tests := []struct {
		backhaul string
		want     string
	}{
		{backhaul: "L", want: "Wi-Fi"},
		{backhaul: "H", want: "Wi-Fi"},
		{backhaul: "LAN", want: "Ethernet"},
		{backhaul: "ethernet", want: "Ethernet"},
	}
	for _, test := range tests {
		t.Run(test.backhaul, func(t *testing.T) {
			got := meshBackhaulLinkType(&meshNode{backhaul: test.backhaul}, 2, "Agent")
			if got != test.want {
				t.Fatalf("meshBackhaulLinkType(%q) = %q, want %q", test.backhaul, got, test.want)
			}
		})
	}
}

func TestDedupeMeshForestDoesNotMergeReusedHostname(t *testing.T) {
	roots := dedupeMeshForest([]*meshNode{
		{name: "OpenWrt", mac: "02:00:00:00:00:11", ip: "208.125.216.78"},
		{name: "OpenWrt", mac: "02:00:00:00:00:12", ip: "208.125.216.78"},
	})
	if len(roots) != 2 {
		t.Fatalf("distinct MACs sharing a hostname and public IP collapsed to %d node(s)", len(roots))
	}
}

func TestDedupeMeshForestNeverUsesAddressAlone(t *testing.T) {
	roots := dedupeMeshForest([]*meshNode{
		{ip: "208.125.216.78"},
		{ip: "208.125.216.78"},
	})
	if len(roots) != 2 {
		t.Fatalf("shared address collapsed address-only observations to %d node(s)", len(roots))
	}
}
