package platforms

import (
	"context"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/platforms/ubus"
)

// Kind identifies the concrete device/backend family.
type Kind string

const (
	KindAuto    Kind = "auto"
	KindOpenWrt Kind = "openwrt"
	KindLinux   Kind = "linux"
	KindMacOS   Kind = "macos"
	KindWindows Kind = "windows"
	KindAndroid Kind = "android"
	KindOLT     Kind = "olt"
	KindONU     Kind = "onu"
)

// CommandRunner executes a platform command for collect/apply operations.
type CommandRunner func(context.Context, string, ...string) ([]byte, error)

// Options configures platform detection and backend construction.
type Options struct {
	Kind                  Kind
	UCIConfigDir          string
	StatePath             string
	HostnamePath          string
	UptimePath            string
	MemInfoPath           string
	IPv6DisablePath       string
	TCPImplementationPath string
	OpenWrtReleasePath    string
	OSReleasePath         string
	SerialNumberPath      string
	MachineIDPath         string
	DeviceModelPath       string
	DeviceVendorPath      string
	DeviceVersionPath     string
	BuildPropPath         string
	TimezonePath          string
	OLTReleasePath        string
	SysinfoPath           string
	ONUReleasePath        string
	// OLTAPIURL/OLTAPIUser/OLTAPIPassword point the OLT backend at a
	// remote FOS device (proxy mode): an agent anywhere can manage an OLT
	// over its goform web API instead of running on the OLT itself.
	OLTAPIURL      string
	OLTAPIUser     string
	OLTAPIPassword string
	NetClassDir    string
	UbusURL        string
	UbusSessionID  string
	UbusTimeout    time.Duration
	UbusCaller     func(string, string, time.Duration) ([]byte, error)
	UbusClient     *ubus.Client
	CommandRunner  CommandRunner
	Now            func() time.Time
}

// DetectKind resolves the most likely platform/backend family.
func DetectKind(opts Options) Kind {
	if opts.Kind != "" && opts.Kind != KindAuto {
		return opts.Kind
	}

	if fileExists(coalesceString(opts.OpenWrtReleasePath, "/etc/openwrt_release")) {
		return KindOpenWrt
	}
	// Several OpenWrt-derived CPE/LTE images replace or omit
	// /etc/openwrt_release while retaining the canonical UCI wireless model.
	// A real wifi-device section is stronger evidence than kernel PHY names and
	// ensures writable WiFi controls use UCI rather than the generic Linux path.
	if hasOpenWrtWirelessUCI(coalesceString(opts.UCIConfigDir, "/etc/config")) {
		return KindOpenWrt
	}
	if fileExists(coalesceString(opts.BuildPropPath, "/system/build.prop")) || runtime.GOOS == "android" {
		return KindAndroid
	}
	// Fiber OLTs (Broadcom iProc GPON OLTs like Photon PTF3708/GP8X2G6) must
	// be checked before KindONU: their hostnames and model strings often
	// contain "gpon"/"pon", which would otherwise be read as an ONU.
	if fileExists(coalesceString(opts.OLTReleasePath, "/etc/olt-release")) {
		return KindOLT
	}
	if sysinfo, _ := parseSysinfoFile(coalesceString(opts.SysinfoPath, defaultSysinfoPath())); isOLTSysinfo(sysinfo) {
		return KindOLT
	}
	if hasOLTMarker(readTextFile(coalesceString(opts.DeviceModelPath, defaultDeviceModelPath(KindLinux)))) {
		return KindOLT
	}
	if fileExists(coalesceString(opts.ONUReleasePath, "/etc/onu-release")) {
		return KindONU
	}
	if hasONUMarker(readTextFile(coalesceString(opts.DeviceModelPath, defaultDeviceModelPath(KindLinux)))) {
		return KindONU
	}
	// DT-less MIPS ONUs (EcoNet EN7528 and friends) carry no model file at
	// all; their only identity string is the cpuinfo "system type" line
	// (e.g. "EcoNet EN7528 SOC").
	if model := cpuinfoSystemType(); model != "" {
		if hasOLTMarker(model) {
			return KindOLT
		}
		if hasONUMarker(model) {
			return KindONU
		}
	}

	switch runtime.GOOS {
	case "darwin":
		return KindMacOS
	case "windows":
		return KindWindows
	case "android":
		return KindAndroid
	default:
		return KindLinux
	}
}

// NewBackend builds the appropriate WUSP data backend for the requested or
// detected platform.
func NewBackend(opts Options) wusp.DataBackend {
	switch DetectKind(opts) {
	case KindOpenWrt:
		return newOpenWrtBackendFromOptions(opts)
	case KindMacOS:
		return NewMacOSBackend(opts)
	case KindWindows:
		return NewWindowsBackend(opts)
	case KindAndroid:
		return NewAndroidBackend(opts)
	case KindONU:
		return NewONUBackend(opts)
	case KindOLT:
		return NewOLTBackend(opts)
	default:
		return NewLinuxBackend(opts)
	}
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func hasOpenWrtWirelessUCI(configDir string) bool {
	data, err := os.ReadFile(strings.TrimSpace(configDir) + string(os.PathSeparator) + "wireless")
	if err != nil || len(data) == 0 {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "config" && fields[1] == "wifi-device" {
			return true
		}
	}
	return false
}

func subsetPlatformMessageByPaths(msg *wusp.Message, paths ...string) *wusp.Message {
	if msg == nil {
		return &wusp.Message{}
	}

	out := &wusp.Message{
		DeviceID:  msg.DeviceID,
		Timestamp: msg.Timestamp,
		Fields:    make([]wusp.Field, 0, len(msg.Fields)),
	}
	if len(paths) == 0 {
		out.Fields = append(out.Fields, msg.Fields...)
		return out
	}

	seen := make(map[string]struct{})
	for _, requested := range paths {
		requested = strings.TrimSpace(requested)
		if requested == "" {
			continue
		}
		for _, field := range msg.Fields {
			if requested != field.Path && !(strings.HasSuffix(requested, ".") && strings.HasPrefix(field.Path, requested)) {
				continue
			}
			if _, ok := seen[field.Path]; ok {
				continue
			}
			seen[field.Path] = struct{}{}
			out.Fields = append(out.Fields, field)
		}
	}
	sort.Slice(out.Fields, func(i, j int) bool {
		return out.Fields[i].Path < out.Fields[j].Path
	})
	return out
}

// defaultSysinfoPath is where FOS-based OLTs (Photon PTF3708/GP8X2G6 family)
// write their platform info file at boot.
func defaultSysinfoPath() string {
	return "/tmp/sysinfo.txt"
}

// isOLTSysinfo reports whether a parsed FOS sysinfo.txt describes an OLT.
// The vendor writes Kind/Type/ModelName/Vendor/SoftwareVersion/HardwareVersion/
// MAC/MgtIP/Sn lines; "Kind: OLT" or "Type: GPON" with a PON port count is
// conclusive, while an ONU never carries the OLT product class.
func isOLTSysinfo(values map[string]string) bool {
	if values == nil {
		return false
	}
	kind := strings.ToLower(strings.TrimSpace(values["Kind"]))
	model := strings.ToLower(strings.TrimSpace(values["ModelName"]))
	if kind == "olt" {
		return true
	}
	// Defensive: an ONU model never looks like an OLT product name.
	return kind == "" && (strings.HasPrefix(model, "ptf-gp") || strings.HasPrefix(model, "ptf-ep") ||
		strings.Contains(model, "g8x") || strings.Contains(model, "g4x"))
}

// hasOLTMarker reports whether a device-model string names a GPON/EPON OLT.
// Checked before hasONUMarker, since OLT hostnames usually contain "pon".
func hasOLTMarker(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(value, "olt"),
		strings.HasPrefix(value, "ptf370"),
		strings.HasPrefix(value, "ptf-gp8"),
		strings.HasPrefix(value, "ptf-gp4"),
		strings.HasPrefix(value, "ptf-ep8"),
		strings.HasPrefix(value, "ptf-ep4"),
		strings.HasPrefix(value, "gpon-olt"),
		strings.HasPrefix(value, "epon-olt"):
		return true
	default:
		return false
	}
}

// cpuinfoSystemType returns the "system type" line of /proc/cpuinfo, used
// to identify MIPS platforms that expose no device-tree or DMI model file.
func cpuinfoSystemType() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(fields) == 2 && strings.TrimSpace(fields[0]) == "system type" {
			return strings.TrimSpace(fields[1])
		}
	}
	return ""
}
