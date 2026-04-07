package wusp

import (
	"strconv"
	"strings"
)

const (
	// BroadbandTR181ModelVersion is the BBF TR-181 Issue 2 Amendment 20 source
	// snapshot used by the core Device., LocalAgent., and WireGuard. schema data.
	BroadbandTR181ModelVersion = "2.20.1"

	// BroadbandRootDataModelVersion is the major.minor value exposed by
	// Device.RootDataModelVersion.
	BroadbandRootDataModelVersion = "2.20"

	// BroadbandCWMPModelVersion tracks the TR-181 CWMP presentation version used
	// for Device.ManagementServer.* definitions.
	BroadbandCWMPModelVersion = "2.20"

	BroadbandTR181Source      = "BBF TR-181 Issue 2, Amendment 20 (November 2025)"
	BroadbandTR181SourceURL   = "https://usp-data-models.broadband-forum.org/tr-181-2-20-1-usp-full.xml"
	BroadbandCWMPSource       = "BroadbandForum/cwmp-data-models tr-181-2-cwmp.xml"
	BroadbandCWMPSourceURL    = "https://cwmp-data-models.broadband-forum.org/"
	BroadbandLocalAgentSource = "BroadbandForum/device-data-model tr-181-2-localagent.xml"
	BroadbandWireGuardSource  = "BroadbandForum/device-data-model tr-181-2-wireguard.xml"
)

// BroadbandDataModel describes one source data-model slice bundled into WUSP.
// ModelVersion is the source snapshot version. FirstVersion and LatestVersion
// describe the per-object/per-parameter SinceVersion range covered by that
// slice in this package.
type BroadbandDataModel struct {
	ID            string
	Name          string
	ModelVersion  string
	FirstVersion  string
	LatestVersion string
	Source        string
	SourceURL     string
	ObjectCount   int
	ParamCount    int
}

var allCoreDeviceParams = concat(
	DeviceRootParams,
	DeviceInfoParams,
	DeviceTimeParams,
	DeviceIPParams,
	DeviceFirewallParams,
	DeviceNATParams,
	DeviceBulkDataParams,
	DeviceLocalAgentParams,
)

// AllDeviceObjects is the union of the standard Device.* object catalog plus
// the extra CWMP and USP sub-tables maintained in dedicated files.
var AllDeviceObjects = concatObjects(
	DeviceObjects,
	ManagementServerObjects,
	LocalAgentExtraObjects,
)

// AllDeviceParams is the full WUSP schema registry consumed by the encoder and
// tests. It stays centralized here so the package has one authoritative
// aggregation point.
var AllDeviceParams = concat(
	allCoreDeviceParams,
	AllWireGuardParams,
	AllManagementServerParams,
	AllLocalAgentSubParams,
)

// BroadbandDataModels collects the version/source metadata for every bundled
// BBF data-model slice in one place.
var BroadbandDataModels = []BroadbandDataModel{
	newBroadbandDataModel(
		"device",
		"TR-181 Device",
		BroadbandTR181ModelVersion,
		BroadbandTR181Source,
		BroadbandTR181SourceURL,
		DeviceObjects,
		allCoreDeviceParams,
	),
	newBroadbandDataModel(
		"cwmp",
		"TR-181 ManagementServer (CWMP)",
		BroadbandCWMPModelVersion,
		BroadbandCWMPSource,
		BroadbandCWMPSourceURL,
		ManagementServerObjects,
		AllManagementServerParams,
	),
	newBroadbandDataModel(
		"usp",
		"TR-181 LocalAgent (USP)",
		BroadbandTR181ModelVersion,
		BroadbandLocalAgentSource,
		BroadbandTR181SourceURL,
		LocalAgentExtraObjects,
		AllLocalAgentSubParams,
	),
	newBroadbandDataModel(
		"wireguard",
		"TR-181 WireGuard",
		BroadbandTR181ModelVersion,
		BroadbandWireGuardSource,
		BroadbandTR181SourceURL,
		nil,
		AllWireGuardParams,
	),
}

func LookupBroadbandDataModel(id string) (BroadbandDataModel, bool) {
	for _, model := range BroadbandDataModels {
		if model.ID == id {
			return model, true
		}
	}
	return BroadbandDataModel{}, false
}

func newBroadbandDataModel(id, name, modelVersion, source, sourceURL string, objects []Object, params []Param) BroadbandDataModel {
	first, latest := versionRange(objects, params)
	return BroadbandDataModel{
		ID:            id,
		Name:          name,
		ModelVersion:  normalizeModelVersion(modelVersion),
		FirstVersion:  first,
		LatestVersion: latest,
		Source:        source,
		SourceURL:     sourceURL,
		ObjectCount:   len(objects),
		ParamCount:    len(params),
	}
}

func versionRange(objects []Object, params []Param) (string, string) {
	var first, latest string
	for _, object := range objects {
		first, latest = extendVersionRange(first, latest, object.SinceVersion)
	}
	for _, param := range params {
		first, latest = extendVersionRange(first, latest, param.SinceVersion)
	}
	return first, latest
}

func extendVersionRange(first, latest, value string) (string, string) {
	value = normalizeModelVersion(value)
	if value == "" {
		return first, latest
	}
	if first == "" || compareModelVersion(value, first) < 0 {
		first = value
	}
	if latest == "" || compareModelVersion(value, latest) > 0 {
		latest = value
	}
	return first, latest
}

func normalizeModelVersion(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "v")
	value = strings.TrimPrefix(value, "V")
	return value
}

func compareModelVersion(a, b string) int {
	a = normalizeModelVersion(a)
	b = normalizeModelVersion(b)
	if a == b {
		return 0
	}
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	width := len(aParts)
	if len(bParts) > width {
		width = len(bParts)
	}
	for i := 0; i < width; i++ {
		aPart := 0
		if i < len(aParts) {
			aPart = parseModelVersionPart(aParts[i])
		}
		bPart := 0
		if i < len(bParts) {
			bPart = parseModelVersionPart(bParts[i])
		}
		if aPart < bPart {
			return -1
		}
		if aPart > bPart {
			return 1
		}
	}
	if a < b {
		return -1
	}
	return 1
}

func parseModelVersionPart(value string) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return n
}

// iptr returns a pointer to the given int64 value. Used in Limits.Min/Max.
func iptr(v int64) *int64 { return &v }

// concat merges multiple []Param slices into one.
func concat(slices ...[]Param) []Param {
	n := 0
	for _, s := range slices {
		n += len(s)
	}
	out := make([]Param, 0, n)
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}

func concatObjects(slices ...[]Object) []Object {
	n := 0
	for _, s := range slices {
		n += len(s)
	}
	out := make([]Object, 0, n)
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}
