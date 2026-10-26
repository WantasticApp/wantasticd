package platforms

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// testNTPEnv points NTP detection at a temp root; nothing under the real
// /proc or /etc is read.
func testNTPEnv(root string) *ntpEnv {
	return &ntpEnv{
		procDir:         filepath.Join(root, "proc"),
		timesyncdConf:   filepath.Join(root, "etc/systemd/timesyncd.conf"),
		timesyncdDropIn: filepath.Join(root, "etc/systemd/timesyncd.conf.d/90-wantastic-ntp.conf"),
		chronyConfs:     []string{filepath.Join(root, "etc/chrony/chrony.conf")},
		ntpConf:         filepath.Join(root, "etc/ntp.conf"),
		initDir:         filepath.Join(root, "etc/init.d"),
		systemdRunDir:   filepath.Join(root, "run/systemd/system"),
		lookPath:        func(string) (string, error) { return "", errors.New("not found") },
	}
}

func writeTestProcess(t *testing.T, root string, pid, comm string, args ...string) {
	t.Helper()
	dir := filepath.Join(root, "proc", pid)
	mustWriteFile(t, filepath.Join(dir, "comm"), comm+"\n")
	mustWriteFile(t, filepath.Join(dir, "cmdline"), strings.Join(args, "\x00")+"\x00")
}

func newTestNTPHost(t *testing.T, root string, calls *[]string) *hostBackend {
	t.Helper()
	b := newHostBackend(KindLinux, Options{
		StatePath: filepath.Join(root, "state.json"),
		CommandRunner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			*calls = append(*calls, name+" "+joinArgs(args))
			if name == "timedatectl" {
				return nil, errors.New("timedatectl: not found")
			}
			return nil, nil
		},
	})
	b.ntp = testNTPEnv(root)
	return b
}

func TestNTPDetectsEachClient(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, root string)
		kind    string
		running bool
		servers string
	}{
		{"busybox", func(t *testing.T, root string) {
			writeTestProcess(t, root, "412", "ntpd", "/usr/sbin/ntpd", "-n", "-p", "0.openwrt.pool.ntp.org", "-p", "1.openwrt.pool.ntp.org")
		}, ntpClientBusybox, true, "0.openwrt.pool.ntp.org,1.openwrt.pool.ntp.org"},
		{"ntp.org", func(t *testing.T, root string) {
			writeTestProcess(t, root, "500", "ntpd", "/usr/sbin/ntpd", "-p", "/var/run/ntpd.pid", "-g")
			mustWriteFile(t, filepath.Join(root, "etc/ntp.conf"), "driftfile /var/lib/ntp/drift\npool 0.debian.pool.ntp.org iburst\nserver 10.0.0.1\n")
		}, ntpClientNTPd, true, "0.debian.pool.ntp.org,10.0.0.1"},
		{"chrony", func(t *testing.T, root string) {
			writeTestProcess(t, root, "600", "chronyd", "/usr/sbin/chronyd")
			mustWriteFile(t, filepath.Join(root, "etc/chrony/chrony.conf"), "pool 2.debian.pool.ntp.org iburst\nsourcedir "+filepath.Join(root, "etc/chrony/sources.d")+"\n")
			mustWriteFile(t, filepath.Join(root, "etc/chrony/sources.d/dhcp.sources"), "server 192.168.1.1 iburst\n")
		}, ntpClientChrony, true, "2.debian.pool.ntp.org,192.168.1.1"},
		{"timesyncd stopped", func(t *testing.T, root string) {
			mustWriteFile(t, filepath.Join(root, "etc/systemd/timesyncd.conf"), "[Time]\n#NTP=\nFallbackNTP=time1.google.com\n")
		}, ntpClientTimesyncd, false, "time1.google.com"},
		{"none", func(*testing.T, string) {}, "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.setup(t, root)
			st := testNTPEnv(root).detect()
			if st.Kind != tc.kind || st.Running != tc.running || strings.Join(st.Servers, ",") != tc.servers {
				t.Fatalf("detect = %+v, want kind=%q running=%v servers=%q", st, tc.kind, tc.running, tc.servers)
			}
		})
	}
}

func TestNTPCollectReportsClientWithoutTimedated(t *testing.T) {
	root := t.TempDir()
	writeTestProcess(t, root, "412", "ntpd", "ntpd", "-p", "time.cloudflare.com")
	var calls []string
	b := newTestNTPHost(t, root, &calls)

	msg, err := b.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertBoolField(t, msg, "Device.Time.Enable", true)
	assertStringField(t, msg, "Device.Time.NTPServer1", "time.cloudflare.com")
	assertStringField(t, msg, "Device.Time.NTPServer2", "")
	assertBoolField(t, msg, "Device.Time.Client.1.Enable", true)
	assertValueText(t, msg, "Device.Time.Client.1.Servers", "time.cloudflare.com")
}

func TestNTPTimesyncdDropInAndNTPServerIndex(t *testing.T) {
	root := t.TempDir()
	writeTestProcess(t, root, "300", "systemd-timesyn", "/lib/systemd/systemd-timesyncd")
	mustWriteFile(t, filepath.Join(root, "etc/systemd/timesyncd.conf"), "[Time]\nNTP=a.example b.example\n")
	if err := os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	var calls []string
	b := newTestNTPHost(t, root, &calls)

	if err := b.Set(context.Background(), "Device.Time.NTPServer2", wusp.String("time.google.com")); err != nil {
		t.Fatalf("Set NTPServer2: %v", err)
	}
	dropIn, _ := os.ReadFile(filepath.Join(root, "etc/systemd/timesyncd.conf.d/90-wantastic-ntp.conf"))
	if !strings.Contains(string(dropIn), "NTP=a.example time.google.com\n") {
		t.Fatalf("drop-in = %q", dropIn)
	}
	if !containsCall(calls, "systemctl try-restart systemd-timesyncd") {
		t.Fatalf("timesyncd not restarted: %v", calls)
	}
	if got := strings.Join(b.ntp.detect().Servers, ","); got != "a.example,time.google.com" {
		t.Fatalf("read back %q", got)
	}
	state, _ := b.readState()
	if strings.Join(state.NTPServers, ",") != "a.example,time.google.com" {
		t.Fatalf("state %v", state.NTPServers)
	}

	// Empty list removes the drop-in: back to the distribution servers.
	if err := b.Set(context.Background(), "Device.Time.Client.1.Servers", wusp.List()); err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	if fileExists(filepath.Join(root, "etc/systemd/timesyncd.conf.d/90-wantastic-ntp.conf")) {
		t.Fatal("drop-in not removed")
	}
}

func TestNTPChronySourcedir(t *testing.T) {
	root := t.TempDir()
	writeTestProcess(t, root, "600", "chronyd", "/usr/sbin/chronyd")
	sources := filepath.Join(root, "etc/chrony/sources.d")
	conf := "pool 2.debian.pool.ntp.org iburst\nsourcedir " + sources + "\n"
	mustWriteFile(t, filepath.Join(root, "etc/chrony/chrony.conf"), conf)
	if err := os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	var calls []string
	b := newTestNTPHost(t, root, &calls)

	if err := b.Set(context.Background(), "Device.Time.Client.1.Servers", wusp.List(wusp.String("ntp1.example"))); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(sources, "wantastic.sources"))
	if !strings.Contains(string(got), "server ntp1.example iburst") {
		t.Fatalf("sources = %q", got)
	}
	confNow, _ := os.ReadFile(filepath.Join(root, "etc/chrony/chrony.conf"))
	if !strings.Contains(string(confNow), ntpDisabledMark+"pool 2.debian.pool.ntp.org") {
		t.Fatalf("default pool not disabled: %q", confNow)
	}
	if st := b.ntp.detect(); strings.Join(st.Servers, ",") != "ntp1.example" {
		t.Fatalf("read back %v", st.Servers)
	}

	if err := b.Set(context.Background(), "Device.Time.Client.1.Servers", wusp.List()); err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	confNow, _ = os.ReadFile(filepath.Join(root, "etc/chrony/chrony.conf"))
	if string(confNow) != conf {
		t.Fatalf("chrony.conf not restored: %q", confNow)
	}
}

func TestNTPConfManagedBlockIsIdempotent(t *testing.T) {
	orig := "driftfile /var/lib/ntp/drift\npool 0.debian.pool.ntp.org iburst\nrestrict default nomodify\n"
	once := rewriteNTPConfServers(orig, []string{"a.example", "b.example"}, true)
	twice := rewriteNTPConfServers(once, []string{"a.example", "b.example"}, true)
	if once != twice {
		t.Fatalf("not idempotent:\n%s\n---\n%s", once, twice)
	}
	if got := parseNTPConfServers(once); strings.Join(got, ",") != "a.example,b.example" {
		t.Fatalf("servers %v in\n%s", got, once)
	}
	if restored := rewriteNTPConfServers(once, nil, true); restored != orig {
		t.Fatalf("restore = %q", restored)
	}
}

func TestNTPBusyboxWithoutConfRestartsWithPeers(t *testing.T) {
	root := t.TempDir()
	writeTestProcess(t, root, "412", "ntpd", "ntpd", "-n", "-p", "old.example")
	var calls []string
	b := newTestNTPHost(t, root, &calls)

	if err := b.Set(context.Background(), "Device.Time.NTPServer1", wusp.String("new.example")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !containsCall(calls, "kill 412") || !containsCall(calls, "ntpd -p new.example") {
		t.Fatalf("calls %v", calls)
	}
}

func TestNTPEnableUsesServiceForNonTimesyncd(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "etc/chrony/chrony.conf"), "pool pool.ntp.org\n")
	if err := os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	var calls []string
	b := newTestNTPHost(t, root, &calls)
	if err := b.Set(context.Background(), "Device.Time.Enable", wusp.Bool(true)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !containsCall(calls, "systemctl enable --now chronyd") {
		t.Fatalf("calls %v", calls)
	}
	if containsCall(calls, "timedatectl set-ntp true") {
		t.Fatalf("timedatectl must not drive chrony: %v", calls)
	}
}

func TestNTPSetWithoutClientFails(t *testing.T) {
	var calls []string
	b := newTestNTPHost(t, t.TempDir(), &calls)
	if err := b.Set(context.Background(), "Device.Time.NTPServer1", wusp.String("a.example")); err == nil {
		t.Fatal("expected error without an NTP client")
	}
	if _, err := normalizeNTPServers([]string{"bad host"}); err == nil {
		t.Fatal("expected invalid server error")
	}
}

func TestOpenWrtNTPServerIndexReadAndSet(t *testing.T) {
	configDir := t.TempDir()
	mustWriteFile(t, filepath.Join(configDir, "system"), "config timeserver 'ntp'\n\toption enabled '1'\n\tlist server '0.pool.ntp.org'\n\tlist server '1.pool.ntp.org'\n")
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir:  configDir,
		CommandRunner: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
	})
	if err := backend.Set(context.Background(), "Device.Time.NTPServer2", wusp.String("time.cloudflare.com")); err != nil {
		t.Fatalf("Set NTPServer2: %v", err)
	}
	msg := wusp.NewMessage()
	backend.appendOpenWrtTimeClientFields(msg)
	assertStringField(t, msg, "Device.Time.NTPServer1", "0.pool.ntp.org")
	assertStringField(t, msg, "Device.Time.NTPServer2", "time.cloudflare.com")
	assertStringField(t, msg, "Device.Time.NTPServer3", "")
	assertValueText(t, msg, "Device.Time.Client.1.Servers", "0.pool.ntp.org,time.cloudflare.com")
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast: %v", err)
	}
}
