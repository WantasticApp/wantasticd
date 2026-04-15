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
	ONUReleasePath        string
	NetClassDir           string
	UbusURL               string
	UbusSessionID         string
	UbusTimeout           time.Duration
	UbusCaller            func(string, string, time.Duration) ([]byte, error)
	UbusClient            *ubus.Client
	CommandRunner         CommandRunner
	Now                   func() time.Time
}

// DetectKind resolves the most likely platform/backend family.
func DetectKind(opts Options) Kind {
	if opts.Kind != "" && opts.Kind != KindAuto {
		return opts.Kind
	}

	if fileExists(coalesceString(opts.OpenWrtReleasePath, "/etc/openwrt_release")) {
		return KindOpenWrt
	}
	if fileExists(coalesceString(opts.BuildPropPath, "/system/build.prop")) || runtime.GOOS == "android" {
		return KindAndroid
	}
	if fileExists(coalesceString(opts.ONUReleasePath, "/etc/onu-release")) {
		return KindONU
	}
	if hasONUMarker(readTextFile(coalesceString(opts.DeviceModelPath, defaultDeviceModelPath(KindLinux)))) {
		return KindONU
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
