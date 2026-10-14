// +build darwin

package platforms

import (
	"context"
	"runtime"
	"testing"

	"wantastic-agent/internal/wusp"
)

// TestDarwinCollector exercises the real macOS collector on the host machine.
// Run with: go test ./internal/wusp/platforms/ -run TestDarwinCollector -v
func TestDarwinCollector(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only test")
	}

	backend := NewBackend(Options{})
	msg, err := backend.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	t.Logf("Collected %d fields", len(msg.Fields))

	// Group by section
	sections := map[string]int{}
	for _, f := range msg.Fields {
		parts := splitPath(f.Path, 2)
		sections[parts]++
	}
	for section, count := range sections {
		t.Logf("  %s: %d fields", section, count)
	}

	// Check critical identity fields
	checkField(t, msg, "Device.DeviceInfo.Manufacturer", "Apple")
	checkNonEmpty(t, msg, "Device.DeviceInfo.ModelName")
	checkNonEmpty(t, msg, "Device.DeviceInfo.SoftwareVersion")
	checkNonEmpty(t, msg, "Device.DeviceInfo.HardwareVersion")
	checkNonEmpty(t, msg, "Device.DeviceInfo.HostName")
	checkNonEmpty(t, msg, "Device.DeviceInfo.SerialNumber")
	checkNonEmpty(t, msg, "Device.DeviceInfo.UpTime")
	checkNonEmpty(t, msg, "Device.DeviceInfo.MemoryStatus.Total")
	checkNonEmpty(t, msg, "Device.DeviceInfo.MemoryStatus.Free")
	checkNonEmpty(t, msg, "Device.DeviceInfo.NetworkProperties.TCPImplementation")
	checkNonEmpty(t, msg, "Device.DeviceInfo.ProductClass")

	// Dump all for inspection
	t.Log("\n=== Full collected data ===")
	for _, f := range msg.Fields {
		val := wusp.ValueToString(f.Val)
		if val == "" {
			continue
		}
		t.Logf("  %-60s = %s", f.Path, truncate(val, 80))
	}
}

func splitPath(path string, depth int) string {
	count := 0
	for i, c := range path {
		if c == '.' {
			count++
			if count == depth {
				return path[:i]
			}
		}
	}
	return path
}

func checkField(t *testing.T, msg *wusp.Message, path, want string) {
	t.Helper()
	if f, ok := msg.Get(path); ok {
		got := wusp.ValueToString(f)
		if got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	} else {
		t.Errorf("%s: not found in message", path)
	}
}

func checkNonEmpty(t *testing.T, msg *wusp.Message, path string) {
	t.Helper()
	if f, ok := msg.Get(path); ok {
		got := wusp.ValueToString(f)
		if got == "" || got == "0" {
			t.Errorf("%s: empty or zero", path)
		}
	} else {
		t.Errorf("%s: not found in message", path)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
