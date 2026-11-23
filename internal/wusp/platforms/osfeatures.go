package platforms

import (
	"encoding/json"
	"os"
	"sync"
)

// osFeature names one console-writable collection toggle.
type osFeature string

const (
	featureNeighbors osFeature = "neighbors"
	featureOSUsers   osFeature = "osusers"
)

// osFeatureState is the on-disk form of the Device.WUSP_Neighbors.Enable and
// Device.WUSP_OSUsers.Enable toggles.
//
// These are runtime state an operator writes from the console, not
// configuration: nothing in a deploy sets them, the file is written only when
// a toggle actually changes, and a missing file means both collections are on.
// That keeps the daemon's config surface unchanged while an operator who turns
// a collection off still finds it off after a restart.
type osFeatureState struct {
	NeighborsEnabled *bool `json:"neighbors_enabled,omitempty"`
	OSUsersEnabled   *bool `json:"osusers_enabled,omitempty"`
}

var (
	osFeatureMu     sync.Mutex
	osFeatureCache  *osFeatureState
	osFeatureLoaded bool
	// osFeatureStatePath is overridden by tests.
	osFeatureStatePath = ""
)

func osFeaturePath() string {
	if osFeatureStatePath != "" {
		return osFeatureStatePath
	}
	return defaultWantasticStatePath("wusp-os-features.json")
}

// readOSFeatureState returns the persisted toggles, caching the read. A
// missing or unreadable file reports the defaults rather than failing the
// collection.
func readOSFeatureState() osFeatureState {
	osFeatureMu.Lock()
	defer osFeatureMu.Unlock()
	if osFeatureLoaded && osFeatureCache != nil {
		return *osFeatureCache
	}
	state := osFeatureState{}
	if data, err := os.ReadFile(osFeaturePath()); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	osFeatureCache = &state
	osFeatureLoaded = true
	return state
}

// osFeatureEnabled reports whether a collection is on. Both default to on
// once the platform supports them, matching the other WUSP backends.
func osFeatureEnabled(feature osFeature) bool {
	state := readOSFeatureState()
	switch feature {
	case featureNeighbors:
		return state.NeighborsEnabled == nil || *state.NeighborsEnabled
	case featureOSUsers:
		return state.OSUsersEnabled == nil || *state.OSUsersEnabled
	default:
		return false
	}
}

// setOSFeatureEnabled persists a toggle written from the console.
func setOSFeatureEnabled(feature osFeature, enabled bool) error {
	osFeatureMu.Lock()
	defer osFeatureMu.Unlock()
	state := osFeatureState{}
	if data, err := os.ReadFile(osFeaturePath()); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	switch feature {
	case featureNeighbors:
		state.NeighborsEnabled = &enabled
	case featureOSUsers:
		state.OSUsersEnabled = &enabled
	default:
		return nil
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	path := osFeaturePath()
	if err := ensureStateParentDir(path); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	osFeatureCache = &state
	osFeatureLoaded = true
	return nil
}
