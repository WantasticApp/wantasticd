package platforms

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

func TestOpenWrtServiceFieldsExposeOperatorFacingNetworkConfig(t *testing.T) {
	configDir := t.TempDir()
	mustWriteFile(t, filepath.Join(configDir, "system"), "config timeserver 'ntp'\n\toption enabled '1'\n\tlist server '0.pool.ntp.org'\n\tlist server '1.pool.ntp.org'\n")
	mustWriteFile(t, filepath.Join(configDir, "network"), "config interface 'lan'\n\toption device 'br-lan'\n\toption proto 'static'\n\toption ipaddr '192.168.10.1'\n\toption netmask '255.255.255.0'\n\tlist dns '1.1.1.1'\n\tlist dns '9.9.9.9'\n")
	mustWriteFile(t, filepath.Join(configDir, "dhcp"), "config dhcp 'lan'\n\toption interface 'lan'\n\toption start '100'\n\toption limit '50'\n\toption leasetime '12h'\n")

	backend := NewOpenWrtBackend(OpenWrtBackendOptions{UCIConfigDir: configDir})
	msg := &wusp.Message{}
	msg.Set("Device.IP.Interface.1.Name", wusp.String("br-lan"))
	msg.Set("Device.IP.Interface.1.IPv4Address.1.AddressingType", wusp.String("DHCP"))

	backend.appendOpenWrtServiceFields(msg)

	assertStringField(t, msg, "Device.IP.Interface.1.IPv4Address.1.AddressingType", "Static")
	assertBoolField(t, msg, "Device.DNS.Client.Enable", true)
	assertUintField(t, msg, "Device.DNS.Client.ServerNumberOfEntries", 2)
	assertStringField(t, msg, "Device.DNS.Client.Server.1.DNSServer", "1.1.1.1")
	assertStringField(t, msg, "Device.DNS.Client.Server.2.DNSServer", "9.9.9.9")
	assertBoolField(t, msg, "Device.DHCPv4.Server.Enable", true)
	assertUintField(t, msg, "Device.DHCPv4.Server.PoolNumberOfEntries", 1)
	assertStringField(t, msg, "Device.DHCPv4.Server.Pool.1.Interface", "Device.IP.Interface.1.")
	assertValueText(t, msg, "Device.DHCPv4.Server.Pool.1.MinAddress", "192.168.10.100")
	assertValueText(t, msg, "Device.DHCPv4.Server.Pool.1.MaxAddress", "192.168.10.149")
	assertValueText(t, msg, "Device.DHCPv4.Server.Pool.1.SubnetMask", "255.255.255.0")
	assertIntField(t, msg, "Device.DHCPv4.Server.Pool.1.LeaseTime", 12*60*60)
	assertBoolField(t, msg, "Device.Time.Client.1.Enable", true)
	assertValueText(t, msg, "Device.Time.Client.1.Servers", "0.pool.ntp.org,1.pool.ntp.org")

	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast(service fields): %v", err)
	}
}

func assertValueText(t *testing.T, msg *wusp.Message, path, want string) {
	t.Helper()
	got, ok := msg.Get(path)
	if !ok {
		t.Fatalf("%s missing from message", path)
	}
	if text := wusp.ValueToString(got); text != want {
		t.Fatalf("%s=%q want %q", path, text, want)
	}
}

func TestOpenWrtServiceSetPersistsTimeDNSAndDHCP(t *testing.T) {
	configDir := t.TempDir()
	mustWriteFile(t, filepath.Join(configDir, "system"), "config timeserver 'ntp'\n\toption enabled '1'\n\tlist server 'old.pool.ntp.org'\n")
	mustWriteFile(t, filepath.Join(configDir, "network"), "config interface 'lan'\n\toption device 'br-lan'\n\tlist dns '1.1.1.1'\n\tlist dns '9.9.9.9'\n")
	mustWriteFile(t, filepath.Join(configDir, "dhcp"), "config dhcp 'lan'\n\toption interface 'lan'\n\toption ignore '0'\n\toption leasetime '12h'\n")

	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir: configDir,
		CommandRunner: func(context.Context, string, ...string) ([]byte, error) {
			return nil, nil
		},
	})

	if err := backend.Set(context.Background(), "Device.Time.Client.1.Servers", wusp.List(wusp.String("time.cloudflare.com"), wusp.String("time.google.com"))); err != nil {
		t.Fatalf("set NTP servers: %v", err)
	}
	if err := backend.Set(context.Background(), "Device.DNS.Client.Server.2.DNSServer", wusp.String("8.8.8.8")); err != nil {
		t.Fatalf("set DNS server: %v", err)
	}
	if err := backend.Set(context.Background(), "Device.DHCPv4.Server.Pool.1.Enable", wusp.Bool(false)); err != nil {
		t.Fatalf("disable DHCP pool: %v", err)
	}
	if err := backend.Set(context.Background(), "Device.DHCPv4.Server.Pool.1.LeaseTime", wusp.Int(7200)); err != nil {
		t.Fatalf("set DHCP lease: %v", err)
	}

	systemBytes, _ := os.ReadFile(filepath.Join(configDir, "system"))
	if got := string(systemBytes); !strings.Contains(got, "list server 'time.cloudflare.com'") || !strings.Contains(got, "list server 'time.google.com'") || strings.Contains(got, "old.pool.ntp.org") {
		t.Fatalf("unexpected system UCI:\n%s", got)
	}
	networkBytes, _ := os.ReadFile(filepath.Join(configDir, "network"))
	if got := string(networkBytes); !strings.Contains(got, "list dns '1.1.1.1'") || !strings.Contains(got, "list dns '8.8.8.8'") || strings.Contains(got, "9.9.9.9") {
		t.Fatalf("unexpected network UCI:\n%s", got)
	}
	dhcpBytes, _ := os.ReadFile(filepath.Join(configDir, "dhcp"))
	if got := string(dhcpBytes); !strings.Contains(got, "option ignore '1'") || !strings.Contains(got, "option leasetime '7200s'") {
		t.Fatalf("unexpected DHCP UCI:\n%s", got)
	}

	// Prove the full control loop: values accepted by Set must be reported by
	// the next WUSP collection, not merely written to an implementation file.
	readback := wusp.NewMessage()
	readback.Set("Device.IP.Interface.1.Name", wusp.String("br-lan"))
	backend.appendOpenWrtServiceFields(readback)
	assertValueText(t, readback, "Device.Time.Client.1.Servers", "time.cloudflare.com,time.google.com")
	assertStringField(t, readback, "Device.DNS.Client.Server.2.DNSServer", "8.8.8.8")
	assertBoolField(t, readback, "Device.DHCPv4.Server.Pool.1.Enable", false)
	assertIntField(t, readback, "Device.DHCPv4.Server.Pool.1.LeaseTime", 7200)
	if err := wusp.ValidateMessageFast(readback); err != nil {
		t.Fatalf("ValidateMessageFast(service readback): %v", err)
	}
}

func TestUCIRewriteListPreservesUnrelatedOptions(t *testing.T) {
	input := "config timeserver 'ntp'\n\toption enabled '1'\n\tlist server 'old-a'\n\toption enable_server '0'\n\tlist server 'old-b'\n"
	got, err := uciRewriteList([]byte(input), "ntp", "server", []string{"new-a", "new-b"})
	if err != nil {
		t.Fatalf("uciRewriteList: %v", err)
	}
	want := "config timeserver 'ntp'\n\toption enabled '1'\n\toption enable_server '0'\n\tlist server 'new-a'\n\tlist server 'new-b'\n"
	if string(got) != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}
