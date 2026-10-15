//go:build darwin

package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteDarwinResolverAndRemoveManagedFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "resolver")
	path := filepath.Join(dir, "wantastic")
	servers := []string{"10.255.255.33", "1.1.1.1"}

	changed, err := writeDarwinResolver(path, servers)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first resolver write did not report a change")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := darwinResolverMarker + "domain wantastic\nnameserver 10.255.255.33\nnameserver 1.1.1.1\n"
	if string(data) != want {
		t.Fatalf("resolver contents = %q, want %q", data, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("resolver mode = %o, want 644", info.Mode().Perm())
	}

	changed, err = writeDarwinResolver(path, servers)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("identical resolver write reported a change")
	}

	oldDir := darwinResolverDir
	darwinResolverDir = dir
	t.Cleanup(func() { darwinResolverDir = oldDir })
	if err := removeTunnel(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("managed resolver still exists: %v", err)
	}
}

func TestWriteDarwinResolverRejectsSymlink(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "resolver")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "wantastic")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := writeDarwinResolver(path, []string{"10.255.255.33"}); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("symlink write error = %v", err)
	}
}

func TestRemoveTunnelKeepsUnmanagedResolver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wantastic")
	if err := os.WriteFile(path, []byte("domain wantastic\nnameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldDir := darwinResolverDir
	darwinResolverDir = dir
	t.Cleanup(func() { darwinResolverDir = oldDir })
	if err := removeTunnel(""); err == nil || !strings.Contains(err.Error(), "unmanaged") {
		t.Fatalf("unmanaged resolver cleanup error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unmanaged resolver was removed: %v", err)
	}
}

func TestValidDarwinServers(t *testing.T) {
	t.Parallel()
	servers, err := validDarwinServers([]string{"10.255.255.33", " 1.1.1.1 ", "10.255.255.33"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(servers, ",") != "10.255.255.33,1.1.1.1" {
		t.Fatalf("servers = %v", servers)
	}
	if _, err := validDarwinServers([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid DNS server was accepted")
	}
}
