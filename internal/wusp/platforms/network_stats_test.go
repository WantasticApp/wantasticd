package platforms

import (
	"os"
	"path/filepath"
	"testing"

	"wantastic-agent/internal/wusp"
)

func TestAppendNetworkInterfaceStatsUsesTR181Counters(t *testing.T) {
	root := t.TempDir()
	stats := filepath.Join(root, "wwan0", "statistics")
	if err := os.MkdirAll(stats, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"rx_bytes": "12345\n", "tx_bytes": "6789\n", "rx_packets": "12\n", "tx_packets": "7\n"} {
		if err := os.WriteFile(filepath.Join(stats, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	msg := wusp.NewMessage()
	appendNetworkInterfaceStats(msg, "Device.IP.Interface.1.", root, "wwan0")
	for path, want := range map[string]uint64{
		"Device.IP.Interface.1.Stats.BytesReceived":   12345,
		"Device.IP.Interface.1.Stats.BytesSent":       6789,
		"Device.IP.Interface.1.Stats.PacketsReceived": 12,
		"Device.IP.Interface.1.Stats.PacketsSent":     7,
	} {
		value, ok := msg.Get(path)
		if !ok || value.AsUint() != want {
			t.Fatalf("%s = %d, present=%v; want %d", path, value.AsUint(), ok, want)
		}
	}
}
