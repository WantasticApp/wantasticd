package dns

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDesiredServersDedupeOrder(t *testing.T) {
	got := desiredServers(Request{
		Servers:               []string{"10.0.0.1", "1.1.1.1", "10.0.0.1"},
		IncludeExisting:       true,
		IncludePublicFallback: true,
	}, []string{"9.9.9.9", "1.1.1.1"})
	want := []string{"10.0.0.1", "1.1.1.1", "9.9.9.9", "8.8.8.8"}
	if !sameServers(got, want) {
		t.Fatalf("desired servers = %v, want %v", got, want)
	}
}

func TestWriteResolvFileIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := writeResolvFile(path, []string{"9.9.9.9"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("expected no change for matching nameservers")
	}

	result, err = writeResolvFile(path, []string{"10.0.0.1", "9.9.9.9"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed {
		t.Fatal("expected changed result")
	}
	got := readResolvNameservers(path)
	want := []string{"10.0.0.1", "9.9.9.9"}
	if !sameServers(got, want) {
		t.Fatalf("nameservers = %v, want %v", got, want)
	}
}

func TestEnsureBootstrapSkipsWhenResolverWorks(t *testing.T) {
	oldLookup := lookupHost
	t.Cleanup(func() { lookupHost = oldLookup })
	lookupHost = func(context.Context, string) ([]string, error) {
		return []string{"1.1.1.1"}, nil
	}
	result := EnsureBootstrap(context.Background())
	if result.Skipped || result.Changed || result.Method != "system-resolver" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestEnsureBootstrapAttemptsApplyOnLookupFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("force-file bootstrap apply is implemented by the Linux adapter")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	oldLookup := lookupHost
	oldPath := resolvConfPath
	oldLookPath := lookPath
	oldMode := os.Getenv("WANTASTIC_DNS_MODE")
	t.Cleanup(func() {
		lookupHost = oldLookup
		resolvConfPath = oldPath
		lookPath = oldLookPath
		_ = os.Setenv("WANTASTIC_DNS_MODE", oldMode)
	})
	lookupHost = func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "test failure"}
	}
	resolvConfPath = path
	lookPath = func(string) (string, error) {
		return "", os.ErrNotExist
	}
	if err := os.Setenv("WANTASTIC_DNS_MODE", "force-file"); err != nil {
		t.Fatal(err)
	}

	result := EnsureBootstrap(context.Background())
	if !result.Changed || result.Method != "resolv.conf" {
		t.Fatalf("unexpected result: %+v", result)
	}
	got := readResolvNameservers(path)
	want := []string{"1.1.1.1", "8.8.8.8"}
	if !sameServers(got, want) {
		t.Fatalf("nameservers = %v, want %v", got, want)
	}
}
