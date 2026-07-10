package wusp

import "testing"

func TestBroadbandDataModelsCoverAggregates(t *testing.T) {
	if len(BroadbandDataModels) != 4 {
		t.Fatalf("expected 4 broadband data models, got %d", len(BroadbandDataModels))
	}

	paramCount := 0
	objectCount := 0
	for _, model := range BroadbandDataModels {
		if model.ModelVersion == "" {
			t.Fatalf("model %q has empty ModelVersion", model.ID)
		}
		if model.FirstVersion == "" || model.LatestVersion == "" {
			t.Fatalf("model %q has incomplete version range: first=%q latest=%q", model.ID, model.FirstVersion, model.LatestVersion)
		}
		if compareModelVersion(model.FirstVersion, model.LatestVersion) > 0 {
			t.Fatalf("model %q has inverted version range: first=%q latest=%q", model.ID, model.FirstVersion, model.LatestVersion)
		}
		paramCount += model.ParamCount
		objectCount += model.ObjectCount
	}

	if paramCount != len(AllDeviceParams) {
		t.Fatalf("catalog param count=%d, want %d", paramCount, len(AllDeviceParams))
	}
	if objectCount != len(AllDeviceObjects) {
		t.Fatalf("catalog object count=%d, want %d", objectCount, len(AllDeviceObjects))
	}
}

func TestLookupBroadbandDataModel(t *testing.T) {
	model, ok := LookupBroadbandDataModel("wireguard")
	if !ok {
		t.Fatal("wireguard model not found")
	}
	if model.ModelVersion != BroadbandTR181ModelVersion {
		t.Fatalf("wireguard model version=%q, want %q", model.ModelVersion, BroadbandTR181ModelVersion)
	}
	if model.FirstVersion != "2.20" || model.LatestVersion != "2.20" {
		t.Fatalf("wireguard version range=%q..%q, want 2.20..2.20", model.FirstVersion, model.LatestVersion)
	}
}

func TestRuntimeDevicePathIndex(t *testing.T) {
	device := RuntimeDevice()
	if device == nil {
		t.Fatal("RuntimeDevice returned nil")
	}
	if device.Root != "device." {
		t.Fatalf("root=%q want device.", device.Root)
	}

	param, ok := device.GetParam("device.deviceinfo.friendlyname")
	if !ok {
		t.Fatal("friendly name param not found")
	}
	if param.Path != "Device.DeviceInfo.FriendlyName" {
		t.Fatalf("friendly name path=%q", param.Path)
	}

	object, ok := device.GetObject("device.wusp.request.{i}.")
	if !ok || !object.MultiInstance {
		t.Fatalf("wusp request object=%+v ok=%v", object, ok)
	}

	subset := device.Search("device.wusp.")
	if subset == nil || len(subset.Params) == 0 || len(subset.Objects) == 0 {
		t.Fatalf("subset=%+v", subset)
	}

	device.SetParam(Param{Path: "Device.WUSP.CustomFlag", Type: TypeBoolean, Access: ReadWrite, SinceVersion: "1.0"})
	if _, ok := device.GetParam("device.wusp.customflag"); !ok {
		t.Fatal("custom param not found after SetParam")
	}

	canonicalPath, ok := device.CanonicalPath("Device.WireGuard.Peer.1.Alias")
	if !ok {
		t.Fatal("canonical path lookup failed")
	}
	if canonicalPath != "Device.WireGuard.Peer.{i}.Alias" {
		t.Fatalf("canonical path=%q", canonicalPath)
	}

	paramCode, ok := device.PathCode("Device.WireGuard.Peer.1.Alias")
	if !ok || paramCode == 0 {
		t.Fatalf("param code=%d ok=%v", paramCode, ok)
	}
	if EncodePathCode("Device.WireGuard.Peer.{i}.Alias") != paramCode {
		t.Fatalf("encoded path code mismatch for peer alias")
	}

	objectCode, ok := device.PathCode("Device.WUSP.Request.1.")
	if !ok || objectCode == 0 {
		t.Fatalf("object code=%d ok=%v", objectCode, ok)
	}
	objectPath, ok := device.PathByCode(objectCode)
	if !ok || objectPath != "Device.WUSP.Request.{i}." {
		t.Fatalf("object path=%q ok=%v", objectPath, ok)
	}

	objects := device.BatchGetObjectsByCode(objectCode)
	if len(objects) != 1 || objects[0].Path != "Device.WUSP.Request.{i}." {
		t.Fatalf("objects=%+v", objects)
	}

	codes := device.BatchPathCodes(
		"Device.DeviceInfo.Manufacturer",
		"Device.WUSP.Request.1.",
	)
	if len(codes) != 2 {
		t.Fatalf("codes=%v", codes)
	}

	paths := device.BatchPathsByCode(codes...)
	if len(paths) != 2 {
		t.Fatalf("paths=%v", paths)
	}
	if paths[0] != "Device.DeviceInfo.Manufacturer" || paths[1] != "Device.WUSP.Request.{i}." {
		t.Fatalf("resolved paths=%v", paths)
	}
}
