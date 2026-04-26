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

// TestOpenWrtBackendSetAndDelete verifies that Set/Delete mutate the on-disk
// /etc/config/* files directly (no uci CLI, no ubus). The historical version
// of this test asserted the ubus-first behaviour; that path is now a fallback
// only — file writes are authoritative because uci/ubus may be missing on
// stripped builds (LEDE forks, GL.iNet, custom firmwares).
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
		var object, method string
		if len(req.Params) >= 3 {
			_ = json.Unmarshal(req.Params[1], &object)
			_ = json.Unmarshal(req.Params[2], &method)
		}
		ubusCalls = append(ubusCalls, object+"."+method)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[0,{}]}`))
	}))
	defer server.Close()

	hostnamePath := filepath.Join(root, "proc", "hostname")
	etcHostnamePath := filepath.Join(root, "etc", "hostname")
	tzPath := filepath.Join(root, "etc", "TZ")

	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir:    configDir,
		StatePath:       filepath.Join(root, "state.json"),
		HostnamePath:    hostnamePath,
		EtcHostnamePath: etcHostnamePath,
		TZPath:          tzPath,
		UbusURL:         server.URL,
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

	// /proc/sys/kernel/hostname mirror was written directly — no `hostname`
	// CLI shell-out needed.
	procData, err := os.ReadFile(hostnamePath)
	if err != nil {
		t.Fatalf("read hostname proc mirror: %v", err)
	}
	if got := strings.TrimSpace(string(procData)); got != "mesh-node-1" {
		t.Fatalf("proc hostname=%q want %q", got, "mesh-node-1")
	}

	// /etc/hostname is the persistent file every non-procd init reads at
	// boot (BusyBox, Alpine, Debian, containers). Without this, a reboot
	// would revert the hostname even if UCI was updated.
	etcData, err := os.ReadFile(etcHostnamePath)
	if err != nil {
		t.Fatalf("read /etc/hostname mirror: %v", err)
	}
	if got := strings.TrimSpace(string(etcData)); got != "mesh-node-1" {
		t.Fatalf("/etc/hostname=%q want %q", got, "mesh-node-1")
	}

	// /etc/config/system now contains `option hostname 'mesh-node-1'` AND
	// the timeserver section was updated in place.
	systemData, err := os.ReadFile(filepath.Join(configDir, "system"))
	if err != nil {
		t.Fatalf("read system config: %v", err)
	}
	systemText := string(systemData)
	if !strings.Contains(systemText, "option hostname 'mesh-node-1'") {
		t.Fatalf("system config missing hostname:\n%s", systemText)
	}
	if !strings.Contains(systemText, "option enabled '1'") {
		t.Fatalf("system config missing time enabled='1':\n%s", systemText)
	}
	if !strings.Contains(systemText, "option enable_server '1'") {
		t.Fatalf("system config missing time enable_server='1':\n%s", systemText)
	}

	// /etc/config/firewall didn't exist before — Set(Device.Firewall.Enable)
	// should have created it with a `config defaults` block.
	firewallData, err := os.ReadFile(filepath.Join(configDir, "firewall"))
	if err != nil {
		t.Fatalf("read firewall config: %v", err)
	}
	firewallText := string(firewallData)
	if !strings.Contains(firewallText, "config defaults") {
		t.Fatalf("firewall config missing defaults section:\n%s", firewallText)
	}
	if !strings.Contains(firewallText, "option disabled '1'") {
		t.Fatalf("firewall config missing disabled='1':\n%s", firewallText)
	}

	// /etc/config/network's existing `globals` section was updated with the
	// new ULA prefix.
	networkData, err := os.ReadFile(filepath.Join(configDir, "network"))
	if err != nil {
		t.Fatalf("read network config: %v", err)
	}
	if !strings.Contains(string(networkData), "option ula_prefix 'fd12:3456:789a::/48'") {
		t.Fatalf("network config missing ula_prefix:\n%s", networkData)
	}

	state, err := backend.readState()
	if err != nil {
		t.Fatalf("readState returned error: %v", err)
	}
	if state.FriendlyName != "" {
		t.Fatalf("friendly name state=%q want empty", state.FriendlyName)
	}

	// File-first contract: NO `hostname` shell-out, NO ubus calls — both are
	// only fallbacks for when the file write itself fails.
	for _, c := range calls {
		if strings.HasPrefix(c, "hostname ") || strings.HasPrefix(c, "uci ") {
			t.Fatalf("unexpected legacy CLI call %q (file write should win)", c)
		}
	}
	if len(ubusCalls) != 0 {
		t.Fatalf("unexpected ubus calls %v (file write should win)", ubusCalls)
	}
}

// TestOpenWrtHostnameDirectWrite locks the contract that hostname persistence
// uses a direct os.WriteFile path instead of tmp+rename. This matters for
// container runtimes (Docker, Podman, LXC) where /etc/hostname is a bind mount
// from /var/lib/<runtime>/containers/<id>/hostname — a rename(2) onto the
// bind-mount target returns EBUSY/EXDEV and historically caused every Set to
// silently fail inside containers.
//
// We pre-create /etc/hostname with a sentinel value and verify a Set
// overwrites that exact inode (no .tmp file lingers, the rename path was
// never taken).
func TestOpenWrtHostnameDirectWrite(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "config")
	mustWriteFile(t, filepath.Join(configDir, "system"), "config system\n")

	hostnamePath := filepath.Join(root, "proc", "hostname")
	etcHostnamePath := filepath.Join(root, "etc", "hostname")
	// Pre-create the file (simulating Docker's pre-mounted /etc/hostname).
	mustWriteFile(t, etcHostnamePath, "container-default\n")

	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir:    configDir,
		StatePath:       filepath.Join(root, "state.json"),
		HostnamePath:    hostnamePath,
		EtcHostnamePath: etcHostnamePath,
		CommandRunner: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return nil, errors.New("no shell-out allowed")
		},
	})

	if err := backend.Set(context.Background(), "Device.DeviceInfo.HostName", wusp.String("via-direct-write")); err != nil {
		t.Fatalf("Set(hostname): %v", err)
	}

	got, err := os.ReadFile(etcHostnamePath)
	if err != nil {
		t.Fatalf("read /etc/hostname: %v", err)
	}
	if want := "via-direct-write\n"; string(got) != want {
		t.Fatalf("/etc/hostname=%q want %q", got, want)
	}

	// The rename-based path would have left an /etc/hostname.tmp behind on
	// failure; a direct WriteFile leaves no temp file. This is the canary
	// that locks the no-rename invariant.
	if _, err := os.Stat(etcHostnamePath + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no leftover %s.tmp; stat err=%v", etcHostnamePath, err)
	}
}

// TestOpenWrtHostnamePersistenceErrorSurfaces guarantees a failed /etc/hostname
// write propagates back to the caller (which transitively becomes the agent's
// Set response error visible in the dashboard) instead of silently succeeding.
// Historical behaviour discarded the error and let the dashboard show the new
// kernel hostname while /etc/hostname stayed stale — exactly the "lying
// transmission protocol" the user observed.
func TestOpenWrtHostnamePersistenceErrorSurfaces(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "config")
	mustWriteFile(t, filepath.Join(configDir, "system"), "config system\n")

	// Point /etc/hostname at a *directory* — WriteFile against a directory
	// returns EISDIR, simulating any unwritable destination (RO bind mount,
	// permission denied, missing dir without MkdirAll rights).
	etcHostnamePath := filepath.Join(root, "etc", "hostname")
	if err := os.MkdirAll(etcHostnamePath, 0o755); err != nil {
		t.Fatalf("mkdir hostname-as-dir: %v", err)
	}

	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir:    configDir,
		StatePath:       filepath.Join(root, "state.json"),
		HostnamePath:    filepath.Join(root, "proc", "hostname"),
		EtcHostnamePath: etcHostnamePath,
		CommandRunner: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return nil, nil
		},
	})

	err := backend.Set(context.Background(), "Device.DeviceInfo.HostName", wusp.String("would-be-lost"))
	if err == nil {
		t.Fatal("expected persistence error to propagate, got nil — agent would silently lie about success")
	}
	if !strings.Contains(err.Error(), "hostname") {
		t.Fatalf("expected error to mention hostname path, got %v", err)
	}
}

// TestOpenWrtUCIRewrite locks the line-oriented UCI editor's invariants:
// existing comments and ordering are preserved, options are replaced in
// place, missing sections are appended, and empty values delete options.
func TestOpenWrtUCIRewrite(t *testing.T) {
	t.Run("replace existing option preserves comments", func(t *testing.T) {
		input := "# top comment\nconfig system\n\t# preserved\n\toption hostname 'old'\n\toption timezone 'UTC'\n"
		got, err := uciRewrite([]byte(input), "@system[0]", "hostname", "new")
		if err != nil {
			t.Fatalf("uciRewrite: %v", err)
		}
		want := "# top comment\nconfig system\n\t# preserved\n\toption hostname 'new'\n\toption timezone 'UTC'\n"
		if string(got) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("insert missing option in existing section", func(t *testing.T) {
		input := "config system\n\toption timezone 'UTC'\n"
		got, err := uciRewrite([]byte(input), "@system[0]", "hostname", "router")
		if err != nil {
			t.Fatalf("uciRewrite: %v", err)
		}
		want := "config system\n\toption timezone 'UTC'\n\toption hostname 'router'\n"
		if string(got) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("append missing section to empty file", func(t *testing.T) {
		got, err := uciRewrite(nil, "@defaults[0]", "disabled", "1")
		if err != nil {
			t.Fatalf("uciRewrite: %v", err)
		}
		want := "config defaults\n\toption disabled '1'\n"
		if string(got) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("named section ref matches by name", func(t *testing.T) {
		input := "config globals 'globals'\n"
		got, err := uciRewrite([]byte(input), "globals", "ula_prefix", "fd00::/48")
		if err != nil {
			t.Fatalf("uciRewrite: %v", err)
		}
		want := "config globals 'globals'\n\toption ula_prefix 'fd00::/48'\n"
		if string(got) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("empty value deletes option", func(t *testing.T) {
		input := "config system\n\toption hostname 'old'\n\toption timezone 'UTC'\n"
		got, err := uciRewrite([]byte(input), "@system[0]", "hostname", "")
		if err != nil {
			t.Fatalf("uciRewrite: %v", err)
		}
		want := "config system\n\toption timezone 'UTC'\n"
		if string(got) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("value with embedded quotes is escaped", func(t *testing.T) {
		input := "config system\n"
		got, err := uciRewrite([]byte(input), "@system[0]", "description", "Bob's router")
		if err != nil {
			t.Fatalf("uciRewrite: %v", err)
		}
		want := "config system\n\toption description 'Bob'\\''s router'\n"
		if string(got) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})
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
