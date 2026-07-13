package wusp

import (
	"strconv"
	"strings"
)

const (
	// BroadbandTR181ModelVersion is the BBF full-model snapshot used by the
	// imported runtime Device.* schema.
	BroadbandTR181ModelVersion = "2.20.1"

	// BroadbandRootDataModelVersion is the major.minor value exposed by
	// Device.RootDataModelVersion.
	BroadbandRootDataModelVersion = "2.20"

	BroadbandTR181Source     = "BroadbandForum/usp-data-models tr-181-2-20-1-usp-full.xml"
	BroadbandTR181SourceURL  = "https://github.com/BroadbandForum/usp-data-models/blob/master/tr-181-2-20-1-usp-full.xml"
	BroadbandWireGuardSource = "BroadbandForum/device-data-model tr-181-2-wireguard.xml"
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

// SupplementalDeviceParams are Wantastic-specific parameters merged on top of
// the imported BBF USP model.
var SupplementalDeviceParams = []Param{
	{
		Path:         "Device.DeviceInfo.FriendlyName",
		Type:         TypeString,
		Access:       ReadWrite,
		SinceVersion: "2.0",
		Description:  "Human-friendly device name exposed by Wantastic backends when the underlying platform supports it.",
		Limits:       Limits{MaxLength: 64},
	},
	{
		Path:         "Device.Cellular.Interface.{i}.SINR",
		Type:         TypeInt,
		Access:       ReadOnly,
		SinceVersion: "2.20",
		Description:  "Wantastic runtime cellular signal-to-interference-plus-noise ratio in dB, collected from LTE/NR modem telemetry when the platform exposes it.",
	},
}

// DeviceObjects is sourced from the generated USP model, excluding the
// WireGuard subtree (which is provided by wireguard.go).
var DeviceObjects = objectsWithoutPrefix(uspModelObjects, "Device.WireGuard.")

var runtimeDeviceParams = concatUniqueParams(
	paramsWithoutPrefix(uspModelParams, "Device.WireGuard."),
	SupplementalDeviceParams,
)

var DeviceRootParams = directParamsUnder(runtimeDeviceParams, "Device.")
var DeviceInfoParams = paramsWithPrefix(runtimeDeviceParams, "Device.DeviceInfo.")
var DeviceTimeParams = paramsWithPrefix(runtimeDeviceParams, "Device.Time.")
var DeviceIPParams = paramsWithPrefix(runtimeDeviceParams, "Device.IP.")
var DeviceFirewallParams = paramsWithPrefix(runtimeDeviceParams, "Device.Firewall.")
var DeviceNATParams = paramsWithPrefix(runtimeDeviceParams, "Device.NAT.")
var DeviceBulkDataParams = paramsWithPrefix(runtimeDeviceParams, "Device.BulkData.")
var DeviceLocalAgentParams = directParamsUnder(runtimeDeviceParams, "Device.LocalAgent.")
var DeviceWiFiParams = paramsWithPrefix(runtimeDeviceParams, "Device.WiFi.")

var ManagementServerObjects = objectsWithPrefix(DeviceObjects, "Device.ManagementServer.")
var AllManagementServerParams = paramsWithPrefix(runtimeDeviceParams, "Device.ManagementServer.")

var LocalAgentExtraObjects = objectsWithPrefixExcluding(DeviceObjects, "Device.LocalAgent.", "Device.LocalAgent.")
var AllLocalAgentSubParams = paramsWithPrefixExcludingDirect(runtimeDeviceParams, "Device.LocalAgent.")

// AllDeviceObjects is the full runtime schema object registry consumed by the
// WUSP supported-data-model surface.
var AllDeviceObjects = concatObjects(
	DeviceObjects,
	WireGuardObjects,
	WUSPObjects,
	WUSPCellularTelemetryObjects,
	WUSPMeshTelemetryObjects,
)

// AllDeviceParams is the full WUSP schema registry consumed by the encoder and
// tests. It stays centralized here so the package has one authoritative
// aggregation point.
var AllDeviceParams = concat(
	runtimeDeviceParams,
	AllWireGuardParams,
	AllWUSPParams,
	AllWUSPCellularTelemetryParams,
	AllWUSPMeshTelemetryParams,
)

// BroadbandDataModels collects the runtime model slices bundled into WUSP.
var BroadbandDataModels = []BroadbandDataModel{
	newBroadbandDataModel(
		"device",
		"TR-181 Device (USP Full Import)",
		BroadbandTR181ModelVersion,
		BroadbandTR181Source,
		BroadbandTR181SourceURL,
		DeviceObjects,
		runtimeDeviceParams,
	),
	newBroadbandDataModel(
		"wireguard",
		"TR-181 WireGuard",
		BroadbandTR181ModelVersion,
		BroadbandWireGuardSource,
		BroadbandTR181SourceURL,
		WireGuardObjects,
		AllWireGuardParams,
	),
	newBroadbandDataModel(
		"wusp",
		"Wantastic WUSP",
		WUSPModelVersion,
		WUSPSource,
		WUSPSourceURL,
		WUSPObjects,
		AllWUSPParams,
	),
	newBroadbandDataModel(
		"wusp-cellular-telemetry",
		"Wantastic WUSP Cellular Telemetry",
		WUSPModelVersion,
		WUSPSource,
		WUSPSourceURL,
		WUSPCellularTelemetryObjects,
		AllWUSPCellularTelemetryParams,
	),
	newBroadbandDataModel(
		"wusp-mesh-telemetry",
		"Wantastic WUSP Mesh Telemetry",
		WUSPModelVersion,
		WUSPSource,
		WUSPSourceURL,
		WUSPMeshTelemetryObjects,
		AllWUSPMeshTelemetryParams,
	),
}

var runtimeDeviceModel = NewDevice(ImportedModelSummary{
	ID:           "runtime-device",
	FileName:     "runtime-device",
	Name:         "Device",
	ModelVersion: BroadbandTR181ModelVersion,
	Source:       "Wantastic runtime device model",
	SourceURL:    BroadbandTR181SourceURL,
	ObjectCount:  len(AllDeviceObjects),
	ParamCount:   len(AllDeviceParams),
}, AllDeviceObjects, AllDeviceParams)

// RuntimeDevice returns the canonical Wantastic Device model, rooted at
// "device.", with the imported BBF schema plus the runtime WireGuard and WUSP
// extensions merged in.
func RuntimeDevice() *Device {
	return runtimeDeviceModel.Clone()
}

func runtimeDeviceFast() *Device {
	return runtimeDeviceModel
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

// fptr returns a pointer to the given float64 value. Used in Limits.MinF/MaxF.
func fptr(v float64) *float64 { return &v }

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
