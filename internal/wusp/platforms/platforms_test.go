package platforms

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func TestDetectKindOpenWrt(t *testing.T) {
	root := t.TempDir()
	openwrtRelease := filepath.Join(root, "openwrt_release")
	if err := os.WriteFile(openwrtRelease, []byte("DISTRIB_ID='OpenWrt'\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(openwrt_release): %v", err)
	}

	kind := DetectKind(Options{
		OpenWrtReleasePath: openwrtRelease,
		BuildPropPath:      filepath.Join(root, "missing-build.prop"),
		DeviceModelPath:    filepath.Join(root, "missing-model"),
	})
	if kind != KindOpenWrt {
		t.Fatalf("DetectKind()=%s want %s", kind, KindOpenWrt)
	}
}

func TestEnsureStateParentDirRejectsFileParent(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "wantastic")
	mustWriteFile(t, parent, "config")

	err := ensureStateParentDir(filepath.Join(parent, "usp-host.json"))
	if err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("ensureStateParentDir()=%v want not-directory error", err)
	}
}

func TestLinuxBackendCollectAndSet(t *testing.T) {
	root := t.TempDir()
	netClassDir := filepath.Join(root, "sys", "class", "net", "eth0")
	if err := os.MkdirAll(netClassDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(net): %v", err)
	}
	mustWriteFile(t, filepath.Join(root, "hostname"), "mesh-node-7\n")
	mustWriteFile(t, filepath.Join(root, "uptime"), "321.9 0.0\n")
	mustWriteFile(t, filepath.Join(root, "meminfo"), "MemTotal:       262144 kB\nMemAvailable:   131072 kB\n")
	mustWriteFile(t, filepath.Join(root, "os-release"), "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04\"\nVERSION_ID=\"24.04\"\n")
	mustWriteFile(t, filepath.Join(root, "serial"), "SN-LNX-001\n")
	mustWriteFile(t, filepath.Join(root, "machine-id"), "machine-123\n")
	mustWriteFile(t, filepath.Join(root, "model"), "Mini Edge Box\n")
	mustWriteFile(t, filepath.Join(root, "vendor"), "Wantastic\n")
	mustWriteFile(t, filepath.Join(root, "version"), "rev-b\n")
	mustWriteFile(t, filepath.Join(root, "timezone"), "UTC0\n")
	mustWriteFile(t, filepath.Join(root, "tcp"), "bbr\n")
	mustWriteFile(t, filepath.Join(root, "ipv6_disable"), "0\n")
	mustWriteFile(t, filepath.Join(netClassDir, "address"), "e0:5d:54:4b:e6:fa\n")

	var calls []string
	backend := NewLinuxBackend(Options{
		StatePath:             filepath.Join(root, "state.json"),
		HostnamePath:          filepath.Join(root, "hostname"),
		UptimePath:            filepath.Join(root, "uptime"),
		MemInfoPath:           filepath.Join(root, "meminfo"),
		OSReleasePath:         filepath.Join(root, "os-release"),
		SerialNumberPath:      filepath.Join(root, "serial"),
		MachineIDPath:         filepath.Join(root, "machine-id"),
		DeviceModelPath:       filepath.Join(root, "model"),
		DeviceVendorPath:      filepath.Join(root, "vendor"),
		DeviceVersionPath:     filepath.Join(root, "version"),
		TimezonePath:          filepath.Join(root, "timezone"),
		TCPImplementationPath: filepath.Join(root, "tcp"),
		IPv6DisablePath:       filepath.Join(root, "ipv6_disable"),
		NetClassDir:           filepath.Join(root, "sys", "class", "net"),
		CommandRunner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+joinArgs(args))
			switch {
			case name == "timedatectl" && len(args) == 4 && args[0] == "show" && args[1] == "-p" && args[2] == "NTP":
				return []byte("yes\n"), nil
			case name == "hostnamectl" && len(args) >= 2:
				return nil, nil
			case name == "timedatectl" && len(args) >= 2:
				return nil, nil
			case name == "hostname":
				return []byte("mesh-node-7\n"), nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})

	if err := backend.Set(context.Background(), "Device.DeviceInfo.FriendlyName", wusp.String("Kitchen Node")); err != nil {
		t.Fatalf("Set(FriendlyName): %v", err)
	}
	if err := backend.Set(context.Background(), "Device.Time.Enable", wusp.Bool(true)); err != nil {
		t.Fatalf("Set(Time.Enable): %v", err)
	}
	msg, err := backend.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertStringField(t, msg, "Device.DeviceInfo.Manufacturer", "Wantastic")
	assertStringField(t, msg, "Device.DeviceInfo.ModelName", "Mini Edge Box")
	assertStringField(t, msg, "Device.DeviceInfo.FriendlyName", "Kitchen Node")
	assertListContains(t, msg, "Device.DeviceInfo.NetworkProperties.TCPImplementation", "BBR")
	assertBoolField(t, msg, "Device.Time.Enable", true)
	assertBoolField(t, msg, "Device.IP.IPv6Enable", true)
	assertStringField(t, msg, "Device.DeviceInfo.ManufacturerOUI", "E05D54")
	assertUintField(t, msg, "Device.DeviceInfo.UpTime", 321)
	assertUintField(t, msg, "Device.DeviceInfo.MemoryStatus.Total", 262144)
	assertUintField(t, msg, "Device.DeviceInfo.MemoryStatus.Free", 131072)
	assertStringField(t, msg, "Device.Time.LocalTimeZone", "UTC0")
	assertUintField(t, msg, "Device.IP.InterfaceNumberOfEntries", 1)

	if !containsCall(calls, "timedatectl set-ntp true") {
		t.Fatalf("missing timedatectl set-ntp true in %v", calls)
	}
}

func TestAndroidBackendCollect(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "build.prop"), "ro.product.manufacturer=Acme\nro.product.model=Pocket Router\nro.build.version.release=14\nro.serialno=ANDROID123\n")
	mustWriteFile(t, filepath.Join(root, "meminfo"), "MemTotal:       524288 kB\nMemFree:        131072 kB\n")
	mustWriteFile(t, filepath.Join(root, "uptime"), "100.0 0.0\n")

	backend := NewAndroidBackend(Options{
		StatePath:       filepath.Join(root, "state.json"),
		BuildPropPath:   filepath.Join(root, "build.prop"),
		MemInfoPath:     filepath.Join(root, "meminfo"),
		UptimePath:      filepath.Join(root, "uptime"),
		CommandRunner:   func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("disabled") },
		Now:             func() time.Time { return time.Unix(1700000000, 0).UTC() },
		IPv6DisablePath: filepath.Join(root, "ipv6_disable"),
	})

	msg, err := backend.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertStringField(t, msg, "Device.DeviceInfo.Manufacturer", "Acme")
	assertStringField(t, msg, "Device.DeviceInfo.ModelName", "Pocket Router")
	assertStringField(t, msg, "Device.DeviceInfo.SoftwareVersion", "14")
	assertStringField(t, msg, "Device.DeviceInfo.SerialNumber", "ANDROID123")
	assertUintField(t, msg, "Device.DeviceInfo.UpTime", 100)
}

func TestNewBackendONU(t *testing.T) {
	root := t.TempDir()
	modelPath := filepath.Join(root, "model")
	if err := os.WriteFile(modelPath, []byte("XGS-PON ONU\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(model): %v", err)
	}

	backend := NewBackend(Options{
		BuildPropPath:      filepath.Join(root, "missing.prop"),
		OpenWrtReleasePath: filepath.Join(root, "missing.openwrt"),
		DeviceModelPath:    modelPath,
		StatePath:          filepath.Join(root, "state.json"),
		CommandRunner:      func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("disabled") },
	})
	if _, ok := backend.(*hostBackend); !ok {
		t.Fatalf("NewBackend() type=%T want *hostBackend", backend)
	}
}

func TestNewBackendOpenWrtWrapper(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "config")
	openwrtRelease := filepath.Join(root, "openwrt_release")
	mustWriteFile(t, openwrtRelease, "DISTRIB_ID='OpenWrt'\nDISTRIB_DESCRIPTION='OpenWrt 24.10'\n")
	mustWriteFile(t, filepath.Join(configDir, "system"), "config system\n\toption timezone 'UTC0'\n")
	mustWriteFile(t, filepath.Join(configDir, "network"), "config globals 'globals'\n")
	mustWriteFile(t, filepath.Join(configDir, "firewall"), "config defaults\n\toption disabled '0'\n")
	mustWriteFile(t, filepath.Join(root, "hostname"), "openwrt-node\n")
	mustWriteFile(t, filepath.Join(root, "uptime"), "12.0 0.0\n")
	mustWriteFile(t, filepath.Join(root, "meminfo"), "MemTotal:       262144 kB\nMemAvailable:   131072 kB\n")
	mustWriteFile(t, filepath.Join(root, "serial"), "OWRT123\n")

	backend := NewBackend(Options{
		UCIConfigDir:       configDir,
		StatePath:          filepath.Join(root, "state.json"),
		OpenWrtReleasePath: openwrtRelease,
		HostnamePath:       filepath.Join(root, "hostname"),
		UptimePath:         filepath.Join(root, "uptime"),
		MemInfoPath:        filepath.Join(root, "meminfo"),
		SerialNumberPath:   filepath.Join(root, "serial"),
		CommandRunner:      func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("disabled") },
		UbusCaller:         func(string, string, time.Duration) ([]byte, error) { return nil, errors.New("disabled") },
		Now:                func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})

	if _, ok := backend.(*OpenWrtBackend); !ok {
		t.Fatalf("NewBackend() type=%T want *OpenWrtBackend", backend)
	}

	msg, err := backend.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertStringField(t, msg, "Device.DeviceInfo.HostName", "openwrt-node")
}

func mustWriteFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func assertStringField(t *testing.T, msg *wusp.Message, path, want string) {
	t.Helper()
	got, ok := msg.Get(path)
	if !ok {
		t.Fatalf("%s missing from message", path)
	}
	if got.AsString() != want {
		t.Fatalf("%s=%q want %q", path, got.AsString(), want)
	}
}

func assertBoolField(t *testing.T, msg *wusp.Message, path string, want bool) {
	t.Helper()
	got, ok := msg.Get(path)
	if !ok {
		t.Fatalf("%s missing from message", path)
	}
	if got.AsBool() != want {
		t.Fatalf("%s=%t want %t", path, got.AsBool(), want)
	}
}

func assertUintField(t *testing.T, msg *wusp.Message, path string, want uint64) {
	t.Helper()
	got, ok := msg.Get(path)
	if !ok {
		t.Fatalf("%s missing from message", path)
	}
	if got.AsUint() != want {
		t.Fatalf("%s=%d want %d", path, got.AsUint(), want)
	}
}

func assertListContains(t *testing.T, msg *wusp.Message, path, want string) {
	t.Helper()
	got, ok := msg.Get(path)
	if !ok {
		t.Fatalf("%s missing from message", path)
	}
	for _, item := range got.AsList() {
		if item.AsString() == want {
			return
		}
	}
	t.Fatalf("%s list does not contain %q", path, want)
}

func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

func joinArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return strings.Join(args, " ")
}
