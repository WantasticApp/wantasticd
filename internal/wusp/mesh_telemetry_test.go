package wusp

import "testing"

func TestWUSPMeshTelemetryModelRegistered(t *testing.T) {
	model := RuntimeDevice()

	tests := []struct {
		path   string
		typ    ParamType
		access Access
	}{
		{"Device.WUSP_MeshTelemetry.Link.1.PacketLoss", TypeDecimal, ReadOnly},
		{"Device.WUSP_MeshTelemetry.Protocol.1.Name", TypeString, ReadOnly},
		{"Device.WUSP_MeshTelemetry.IEEE80211s.1.MeshID", TypeString, ReadWrite},
		{"Device.WUSP_MeshTelemetry.IEEE80211s.1.Key", TypeString, WriteOnly},
		{"Device.WUSP_MeshTelemetry.BATMANAdv.1.OrigInterval", TypeUnsignedInt, ReadWrite},
		{"Device.WUSP_MeshTelemetry.BATMANAdv.1.Originator.1.TQ", TypeUnsignedInt, ReadOnly},
		{"Device.WiFi.MultiAP.APDevice.1.Radio.1.Channel", TypeUnsignedInt, ReadWrite},
		{"Device.WiFi.MultiAP.APDevice.1.BackhaulLinkType", TypeString, ReadOnly},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			param, ok := model.GetParam(tt.path)
			if !ok {
				t.Fatalf("%s not registered", tt.path)
			}
			if param.Type != tt.typ {
				t.Fatalf("%s type = %s, want %s", tt.path, param.Type, tt.typ)
			}
			if param.Access != tt.access {
				t.Fatalf("%s access = %s, want %s", tt.path, param.Access, tt.access)
			}
		})
	}

	root, ok := model.GetObject("Device.WUSP_MeshTelemetry.")
	if !ok {
		t.Fatal("Device.WUSP_MeshTelemetry. object not registered")
	}
	if root.Path != "Device.WUSP_MeshTelemetry." {
		t.Fatalf("root path = %q", root.Path)
	}

	if _, ok := model.GetObject("Device.WiFi.MultiAP.APDevice.1.Radio.1.AP.1.AssociatedDevice.1.SteeringHistory.1."); !ok {
		t.Fatal("Device.WiFi.MultiAP steering history object not registered")
	}
}

func TestWUSPMeshTelemetryValuesValidate(t *testing.T) {
	tests := []string{
		"Device.WUSP_MeshTelemetry.Enable",
		"Device.WUSP_MeshTelemetry.Node.1.Role",
		"Device.WUSP_MeshTelemetry.Link.1.SignalQuality",
		"Device.WUSP_MeshTelemetry.Route.1.NextHopNode",
		"Device.WUSP_MeshTelemetry.Protocol.1.StandardMultiAPReference",
		"Device.WUSP_MeshTelemetry.IEEE80211s.1.RadioReference",
		"Device.WUSP_MeshTelemetry.IEEE80211s.1.MeshRSSIThreshold",
		"Device.WUSP_MeshTelemetry.BATMANAdv.1.IsolationMark",
		"Device.WUSP_MeshTelemetry.BATMANAdv.1.Gateway.1.BandwidthDown",
		"Device.WiFi.MultiAP.APDevice.1.Radio.1.AP.1.AssociatedDevice.1.Stats.BytesReceived",
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			value, err := FilledValueForPath(path, FillProfileRealistic)
			if err != nil {
				t.Fatalf("FilledValueForPath: %v", err)
			}
			if err := ValidateFieldFast(Field{Path: path, Val: value}); err != nil {
				t.Fatalf("ValidateFieldFast: %v", err)
			}
		})
	}
}

func TestWUSPMeshTelemetrySupportedDM(t *testing.T) {
	agent := NewUSPAgent(USPAgentOptions{})
	model := agent.GetSupportedDM("Device.WUSP_MeshTelemetry.")

	var foundObject, foundParam, foundProtocol bool
	for _, object := range model.Objects {
		if object.Path == "Device.WUSP_MeshTelemetry.Link.{i}." {
			foundObject = true
		}
		if object.Path == "Device.WUSP_MeshTelemetry.BATMANAdv.{i}.Originator.{i}." {
			foundProtocol = true
		}
	}
	for _, param := range model.Params {
		if param.Path == "Device.WUSP_MeshTelemetry.Route.{i}.Status" {
			foundParam = true
			if param.Access != ReadOnly {
				t.Fatalf("Route status access = %s, want %s", param.Access, ReadOnly)
			}
			break
		}
	}

	if !foundObject {
		t.Fatal("SupportedDM missing Device.WUSP_MeshTelemetry.Link.{i}.")
	}
	if !foundParam {
		t.Fatal("SupportedDM missing Device.WUSP_MeshTelemetry.Route.{i}.Status")
	}
	if !foundProtocol {
		t.Fatal("SupportedDM missing Device.WUSP_MeshTelemetry.BATMANAdv.{i}.Originator.{i}.")
	}
}

func TestWiFiMultiAPSupportedDM(t *testing.T) {
	agent := NewUSPAgent(USPAgentOptions{})
	model := agent.GetSupportedDM("Device.WiFi.MultiAP.")

	var foundObject, foundWritable bool
	for _, object := range model.Objects {
		if object.Path == "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.AP.{i}.AssociatedDevice.{i}.Stats." {
			foundObject = true
			break
		}
	}
	for _, param := range model.Params {
		if param.Path == "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.TransmitPowerLimit" {
			foundWritable = param.Access == ReadWrite
			break
		}
	}
	if !foundObject {
		t.Fatal("SupportedDM missing Device.WiFi.MultiAP associated device stats object")
	}
	if !foundWritable {
		t.Fatal("SupportedDM missing writable Device.WiFi.MultiAP radio transmit power limit")
	}
}
