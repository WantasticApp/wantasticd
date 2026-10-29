package device

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"wantastic-agent/internal/device/wireguard-go/conn/bindtest"
	wg "wantastic-agent/internal/device/wireguard-go/device"
	"wantastic-agent/internal/device/wireguard-go/tun/tuntest"
)

// The exit-node IPC commands must be accepted by the real UAPI parser: a
// rejected command leaves the exit node on standby forever.
func TestAddAllowedIPCmdAcceptedByDevice(t *testing.T) {
	dev := wg.NewDevice(tuntest.NewChannelTUN().TUN(), bindtest.NewChannelBinds()[0], wg.NewLogger(wg.LogLevelSilent, ""))
	defer dev.Close()

	peer := hex.EncodeToString(make([]byte, 31)) + "01"
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=10.255.255.36/32\n", strings.Repeat("11", 32), peer)); err != nil {
		t.Fatalf("add peer: %v", err)
	}
	if err := dev.IpcSet(addAllowedIPCmd(peer, "0.0.0.0/0")); err != nil {
		t.Fatalf("addAllowedIPCmd rejected: %v", err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"allowed_ip=10.255.255.36/32", "allowed_ip=0.0.0.0/0"} {
		if !strings.Contains(got, want) {
			t.Fatalf("peer missing %s after add (existing IPs must be kept):\n%s", want, got)
		}
	}
}
