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
