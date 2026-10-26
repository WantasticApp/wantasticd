//go:build linux

package dns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestResolvFileControlVolatileSymlinkRoundTrip(t *testing.T) {
	env := newDNSTestEnv(t)
	oldLegacy := legacyResolvBackup
	t.Cleanup(func() { legacyResolvBackup = oldLegacy })
	legacyResolvBackup = filepath.Join(env.dir, "etc", "resolv.conf.wantastic-auto")
	target := filepath.Join(env.dir, "var", "run", "resolv.conf")
	env.linkResolv(t, target, "nameserver 10.0.0.1\n")
	ctx := context.Background()

	st := ReadControl(ctx)
	if !st.Supported || st.Method != "resolv.conf" || st.Manual || !sameServers(st.Effective, []string{"10.0.0.1"}) {
		t.Fatalf("initial state %+v", st)
	}
	if err := SetServers(ctx, []string{"9.9.9.9", "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(resolvConfPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("resolv.conf symlink was replaced")
	}
	if _, err := os.Stat(target + resolvBackupSuffix); err != nil {
		t.Fatalf("automatic backup not kept beside the target: %v", err)
	}
	st = ReadControl(ctx)
	if !st.Manual || !sameServers(st.Servers, []string{"9.9.9.9", "1.1.1.1"}) || !sameServers(st.Effective, st.Servers) {
		t.Fatalf("manual state %+v", st)
	}

	// A DHCP client rewriting the file returns the device to automatic.
	env.write(t, target, "nameserver 10.0.0.2\n")
	if st = ReadControl(ctx); st.Manual {
		t.Fatalf("rewritten file still reported manual: %+v", st)
	}

	if err := SetServers(ctx, []string{"9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	if err := SetServers(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := readResolvNameservers(target); !sameServers(got, []string{"10.0.0.2"}) {
		t.Fatalf("restored nameservers = %v", got)
	}
	if st = ReadControl(ctx); st.Manual {
		t.Fatalf("restored state %+v", st)
	}
}

func TestResolvFileControlReportsReadOnlyFilesystem(t *testing.T) {
	env := newDNSTestEnv(t)
	env.write(t, resolvConfPath, "nameserver 10.0.0.1\n")
	oldWrite := writeFile
	t.Cleanup(func() { writeFile = oldWrite })
	writeFile = func(string, []byte, os.FileMode) error {
		return &os.PathError{Op: "open", Path: resolvConfPath, Err: syscall.EROFS}
	}
	err := SetServers(context.Background(), []string{"9.9.9.9"})
	if err == nil || !strings.Contains(err.Error(), "read-only filesystem") {
		t.Fatalf("err = %v", err)
	}
	if st := ReadControl(context.Background()); st.Manual {
		t.Fatalf("failed write reported as manual: %+v", st)
	}
}

func TestDnsmasqControlReportsUpstreamsWithoutWriting(t *testing.T) {
	env := newDNSTestEnv(t)
	env.write(t, resolvConfPath, "nameserver 127.0.0.1\n")
	upstream := filepath.Join(env.dir, "data", "dnsmasq.resolv")
	env.write(t, upstream, "nameserver 10.20.0.1\n")
	env.process(t, "5", "dnsmasq", "dnsmasq", "-C", filepath.Join(env.dir, "none.conf"), "-r", upstream)

	st := ReadControl(context.Background())
	if st.Supported || st.Method != "unsupported" || st.Reason == "" || !sameServers(st.Effective, []string{"10.20.0.1"}) {
		t.Fatalf("dnsmasq state %+v", st)
	}
	if err := SetServers(context.Background(), []string{"9.9.9.9"}); err == nil {
		t.Fatal("dnsmasq-owned resolver was written")
	}
	if got := readResolvNameservers(resolvConfPath); !sameServers(got, []string{"127.0.0.1"}) {
		t.Fatalf("resolv.conf changed: %v", got)
	}
}
