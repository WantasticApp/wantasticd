package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func TestOpenWrtBackendCollect(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "config")
	netClassDir := filepath.Join(root, "sys", "class", "net", "eth0")

	mustWriteFile(t, filepath.Join(configDir, "system"), "config system\n\toption timezone 'UTC0'\nconfig timeserver 'ntp'\n\toption enabled '1'\n\toption enable_server '1'\n\tlist server '0.pool.ntp.org'\n\tlist server '1.pool.ntp.org'\n")
	mustWriteFile(t, filepath.Join(configDir, "network"), "config globals 'globals'\n\toption ula_prefix 'fd12:3456:789a::/48'\n")
	mustWriteFile(t, filepath.Join(configDir, "firewall"), "config defaults\n\toption disabled '0'\n")
	mustWriteFile(t, filepath.Join(configDir, "wireless"), "config wifi-device 'radio0'\n\toption band '5g'\n\toption channel '36'\n\toption htmode 'HE80'\nconfig wifi-iface 'default_radio0'\n\toption device 'radio0'\n\toption ifname 'wlan0'\n\toption mode 'ap'\n\toption ssid 'SkyNet-5G'\nconfig wifi-device 'radio1'\n\toption band '2g'\n\toption channel '11'\n\toption htmode 'HT20'\nconfig wifi-iface 'sta_radio1'\n\toption device 'radio1'\n\toption ifname 'wlan1'\n\toption mode 'sta'\n\toption ssid 'UpstreamNet'\n")
	firewallPath := filepath.Join(configDir, "firewall")
	firewallTS := time.Unix(1700000100, 0)
	if err := os.Chtimes(firewallPath, firewallTS, firewallTS); err != nil {
		t.Fatalf("Chtimes(firewall): %v", err)
	}
	mustWriteFile(t, filepath.Join(root, "hostname"), "openwrt-ap\n")
	mustWriteFile(t, filepath.Join(root, "uptime"), "1234.56 999.00\n")
	mustWriteFile(t, filepath.Join(root, "meminfo"), "MemTotal:       262144 kB\nMemAvailable:   131072 kB\n")
	mustWriteFile(t, filepath.Join(root, "ipv6_disable"), "0\n")
	mustWriteFile(t, filepath.Join(root, "tcp_cc"), "bbr\n")
	mustWriteFile(t, filepath.Join(root, "openwrt_release"), "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10'\nDISTRIB_DESCRIPTION='OpenWrt 24.10'\n")
	mustWriteFile(t, filepath.Join(root, "serial"), "SN123456\n")
	mustWriteFile(t, filepath.Join(netClassDir, "address"), "e0:5d:54:4b:e6:fa\n")

	stateBytes, err := json.Marshal(openWrtState{
		FriendlyName:     "Living Room AP",
		ProvisioningCode: "sp-tag-1",
	})
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	mustWriteFile(t, filepath.Join(root, "state.json"), string(stateBytes))

	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir:          configDir,
		StatePath:             filepath.Join(root, "state.json"),
		HostnamePath:          filepath.Join(root, "hostname"),
		UptimePath:            filepath.Join(root, "uptime"),
		MemInfoPath:           filepath.Join(root, "meminfo"),
		IPv6DisablePath:       filepath.Join(root, "ipv6_disable"),
		TCPImplementationPath: filepath.Join(root, "tcp_cc"),
		OpenWrtReleasePath:    filepath.Join(root, "openwrt_release"),
		SerialNumberPath:      filepath.Join(root, "serial"),
		NetClassDir:           filepath.Join(root, "sys", "class", "net"),
		CommandRunner: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return nil, errors.New("disabled in test")
		},
		Now: func() time.Time {
			return time.Unix(1700000000, 0).UTC()
		},
		UbusCaller: func(object, method string, _ time.Duration) ([]byte, error) {
			switch {
			case object == "system" && method == "board":
				return []byte(`{"hostname":"openwrt-ap","model":"Qualcomm IPQ807x","board_name":"plasmacloud,superpod","system":"ARMv8","kernel":"6.6.0","release":{"distribution":"OpenWrt","version":"24.10","target":"qualcommax/ipq807x","description":"OpenWrt 24.10"}}`), nil
			case object == "system" && method == "info":
				return []byte(`{"localtime":1700000200,"uptime":4321,"memory":{"total":524288,"free":65536,"available":262144}}`), nil
			case object == "network.interface" && method == "dump":
				return []byte(`{"interface":[{"interface":"loopback","up":true},{"interface":"lan","up":true},{"interface":"wan","up":false}]}`), nil
			case object == "network.wireless" && method == "status":
				return []byte(`{"radio0":{"up":true,"config":{"band":"5g","channel":"36","htmode":"HE80"},"interfaces":[{"section":"default_radio0","ifname":"wlan0","up":true,"config":{"mode":"ap","ssid":"SkyNet-5G"}}]},"radio1":{"up":false,"config":{"band":"2g","channel":"11","htmode":"HT20"},"interfaces":[{"section":"sta_radio1","ifname":"wlan1","up":false,"config":{"mode":"sta","ssid":"UpstreamNet"}}]}}`), nil
			case object == "device" && method == "getStaList":
				return []byte(`{"station":[{"mac":"e0:5d:54:4b:e6:fa","rssi":-62,"iface":"wlan0"},{"mac":"e0:5d:54:4b:e5:92","rssi":-50,"iface":"wlan0"}]}`), nil
			default:
				return nil, wusp.ErrUSPPathUnsupported
			}
		},
	})

	msg, err := backend.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	assertStringField(t, msg, "Device.DeviceInfo.HostName", "openwrt-ap")
	assertStringField(t, msg, "Device.DeviceInfo.FriendlyName", "Living Room AP")
	assertStringField(t, msg, "Device.DeviceInfo.ProvisioningCode", "sp-tag-1")
	assertStringField(t, msg, "Device.DeviceInfo.ManufacturerOUI", "E05D54")
	assertListContains(t, msg, "Device.DeviceInfo.NetworkProperties.TCPImplementation", "BBR")
	assertBoolField(t, msg, "Device.Time.Enable", true)
	assertUintField(t, msg, "Device.Time.ClientNumberOfEntries", 2)
	assertUintField(t, msg, "Device.Time.ServerNumberOfEntries", 1)
	assertBoolField(t, msg, "Device.Firewall.Enable", true)
	assertBoolField(t, msg, "Device.IP.IPv6Enable", true)
	assertUintField(t, msg, "Device.IP.InterfaceNumberOfEntries", 3)
	assertTimeField(t, msg, "Device.Time.CurrentLocalTime", time.Unix(1700000200, 0))
	assertTimeField(t, msg, "Device.Firewall.LastChange", firewallTS)
	assertUintField(t, msg, "Device.WiFi.RadioNumberOfEntries", 2)
	assertUintField(t, msg, "Device.WiFi.SSIDNumberOfEntries", 2)
	assertUintField(t, msg, "Device.WiFi.AccessPointNumberOfEntries", 1)
	assertUintField(t, msg, "Device.WiFi.EndPointNumberOfEntries", 1)
	assertStringField(t, msg, "Device.WiFi.Radio.1.Name", "radio0")
	assertStringField(t, msg, "Device.WiFi.Radio.1.OperatingFrequencyBand", "5GHz")
	assertUintField(t, msg, "Device.WiFi.Radio.1.Channel", 36)
	assertStringField(t, msg, "Device.WiFi.SSID.1.SSID", "SkyNet-5G")
	assertStringField(t, msg, "Device.WiFi.SSID.1.LowerLayers", "Device.WiFi.Radio.1.")
	assertUintField(t, msg, "Device.WiFi.AccessPoint.1.AssociatedDeviceNumberOfEntries", 2)

	ula, ok := msg.Get("Device.IP.ULAPrefix")
	if !ok {
		t.Fatal("Device.IP.ULAPrefix missing from collected message")
	}
	if ula.Tag != wusp.TagIP6Pfx {
		t.Fatalf("Device.IP.ULAPrefix tag=%v want TagIP6Pfx", ula.Tag)
	}
}

func TestOpenWrtBackendSetAndDelete(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "config")
	mustWriteFile(t, filepath.Join(configDir, "system"), "config timeserver 'ntp'\n\toption enabled '0'\n\toption enable_server '0'\n")
	mustWriteFile(t, filepath.Join(configDir, "network"), "config globals 'globals'\n")

	var (
		calls     []string
		ubusCalls []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Decode ubus request: %v", err)
		}
		if len(req.Params) != 4 {
			t.Fatalf("ubus params len=%d want 4", len(req.Params))
		}

		var object, method string
		if err := json.Unmarshal(req.Params[1], &object); err != nil {
			t.Fatalf("Decode ubus object: %v", err)
		}
		if err := json.Unmarshal(req.Params[2], &method); err != nil {
			t.Fatalf("Decode ubus method: %v", err)
		}
		ubusCalls = append(ubusCalls, object+"."+method)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[0,{}]}`))
	}))
	defer server.Close()

	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir: configDir,
		StatePath:    filepath.Join(root, "state.json"),
		UbusURL:      server.URL,
		CommandRunner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
			return nil, nil
		},
	})

	if err := backend.Set(context.Background(), "Device.DeviceInfo.HostName", wusp.String("mesh-node-1")); err != nil {
		t.Fatalf("Set(hostname) returned error: %v", err)
	}
	if err := backend.Set(context.Background(), "Device.Time.Enable", wusp.Bool(true)); err != nil {
		t.Fatalf("Set(time enable) returned error: %v", err)
	}
	if err := backend.Set(context.Background(), "Device.Firewall.Enable", wusp.Bool(false)); err != nil {
		t.Fatalf("Set(firewall) returned error: %v", err)
	}
	_, prefix, _ := net.ParseCIDR("fd12:3456:789a::/48")
	if err := backend.Set(context.Background(), "Device.IP.ULAPrefix", wusp.IP6Prefix(prefix)); err != nil {
		t.Fatalf("Set(ula prefix) returned error: %v", err)
	}
	if err := backend.Set(context.Background(), "Device.DeviceInfo.FriendlyName", wusp.String("Kitchen AP")); err != nil {
		t.Fatalf("Set(friendly name) returned error: %v", err)
	}
	if err := backend.Delete(context.Background(), "Device.DeviceInfo.FriendlyName"); err != nil {
		t.Fatalf("Delete(friendly name) returned error: %v", err)
	}

	state, err := backend.readState()
	if err != nil {
		t.Fatalf("readState returned error: %v", err)
	}
	if state.FriendlyName != "" {
		t.Fatalf("friendly name state=%q want empty", state.FriendlyName)
	}

	wantCalls := []string{
		"hostname mesh-node-1",
	}
	for _, want := range wantCalls {
		if !containsCall(calls, want) {
			t.Fatalf("missing command %q in %v", want, calls)
		}
	}

	wantUbusCalls := []string{
		"uci.set",
		"uci.commit",
		"uci.apply",
		"uci.set",
		"uci.set",
		"uci.commit",
		"uci.apply",
		"uci.set",
		"uci.commit",
		"uci.apply",
		"uci.set",
		"uci.commit",
		"uci.apply",
	}
	if len(ubusCalls) != len(wantUbusCalls) {
		t.Fatalf("ubusCalls=%v want %v", ubusCalls, wantUbusCalls)
	}
	for i := range wantUbusCalls {
		if ubusCalls[i] != wantUbusCalls[i] {
			t.Fatalf("ubusCalls[%d]=%q want %q", i, ubusCalls[i], wantUbusCalls[i])
		}
	}
}

func assertTimeField(t *testing.T, msg *wusp.Message, path string, want time.Time) {
	t.Helper()
	got, ok := msg.Get(path)
	if !ok {
		t.Fatalf("%s missing from message", path)
	}
	if !got.AsTime().Equal(want) {
		t.Fatalf("%s=%s want %s", path, got.AsTime().UTC().Format(time.RFC3339), want.UTC().Format(time.RFC3339))
	}
}
