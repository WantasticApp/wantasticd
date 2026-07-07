package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	resolvConfPath = "/etc/resolv.conf"
	lookupHost     = net.DefaultResolver.LookupHost
	lstatPath      = os.Lstat
	readFile       = os.ReadFile
	writeFile      = os.WriteFile
	removePath     = os.Remove
	lookPath       = exec.LookPath
)

// Request describes a DNS apply operation. The package deliberately treats
// direct resolver-file writes as the last adapter because most modern systems
// generate /etc/resolv.conf from a platform DNS manager.
type Request struct {
	Servers               []string
	IncludeExisting       bool
	IncludePublicFallback bool
	Reason                string
}

type Result struct {
	Changed bool
	Skipped bool
	Method  string
	Reason  string
	Servers []string
}

func EnsureBootstrap(ctx context.Context) Result {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := lookupHost(ctx, "one.one.one.one"); err == nil {
		return Result{Method: "system-resolver", Reason: "resolver already works"}
	}
	result, err := Apply(ctx, Request{
		Servers:               []string{"1.1.1.1", "8.8.8.8"},
		IncludeExisting:       true,
		IncludePublicFallback: false,
		Reason:                "bootstrap endpoint resolution",
	})
	if err != nil {
		log.Printf("DNS: bootstrap DNS apply failed: %v", err)
		return Result{Skipped: true, Reason: err.Error()}
	}
	if result.Skipped {
		log.Printf("DNS: bootstrap DNS apply skipped (%s)", result.Reason)
	}
	return result
}

func ApplyTunnel(ctx context.Context, servers []string) Result {
	result, err := Apply(ctx, Request{
		Servers:               servers,
		IncludeExisting:       true,
		IncludePublicFallback: true,
		Reason:                "tunnel DNS",
	})
	if err != nil {
		log.Printf("DNS: tunnel DNS apply failed: %v", err)
		return Result{Skipped: true, Reason: err.Error()}
	}
	if result.Changed {
		log.Printf("DNS: applied %s via %s: %v", result.Reason, result.Method, result.Servers)
	} else if result.Skipped {
		log.Printf("DNS: skipped %s (%s)", result.Reason, result.Reason)
	}
	return result
}

func desiredServers(req Request, existing []string) []string {
	out := make([]string, 0, len(req.Servers)+len(existing)+2)
	seen := make(map[string]struct{})
	add := func(server string) {
		server = strings.TrimSpace(server)
		if server == "" {
			return
		}
		if _, ok := seen[server]; ok {
			return
		}
		seen[server] = struct{}{}
		out = append(out, server)
	}
	for _, server := range req.Servers {
		add(server)
	}
	if req.IncludeExisting {
		for _, server := range existing {
			add(server)
		}
	}
	if req.IncludePublicFallback {
		add("1.1.1.1")
		add("8.8.8.8")
	}
	return out
}

func readResolvNameservers(path string) []string {
	data, err := readFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}

func sameServers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func writeResolvFile(path string, servers []string, reason string) (Result, error) {
	existing := readResolvNameservers(path)
	if sameServers(existing, servers) {
		return Result{Method: "resolv.conf", Reason: "already current", Servers: servers}, nil
	}

	var b strings.Builder
	b.WriteString("# Managed by wantasticd")
	if reason != "" {
		b.WriteString(" for ")
		b.WriteString(reason)
	}
	b.WriteByte('\n')
	for _, server := range servers {
		b.WriteString("nameserver ")
		b.WriteString(server)
		b.WriteByte('\n')
	}
	b.WriteString("options timeout:1 attempts:1\n")

	if fi, err := lstatPath(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil && !isManagedResolvTarget(target) {
			_ = removePath(path)
		}
	}
	if err := writeFile(path, []byte(b.String()), 0o644); err != nil {
		return Result{}, fmt.Errorf("write %s: %w", path, err)
	}
	return Result{Changed: true, Method: "resolv.conf", Reason: reason, Servers: servers}, nil
}

func isManagedResolvTarget(target string) bool {
	target = filepath.Clean(strings.TrimSpace(target))
	if target == "" {
		return false
	}
	managedParts := []string{
		"systemd/resolve",
		"NetworkManager",
		"resolvconf",
		"/tmp/resolv.conf",
		"/tmp/resolv.conf.d",
	}
	for _, part := range managedParts {
		if strings.Contains(target, part) {
			return true
		}
	}
	return false
}

func dnsMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("WANTASTIC_DNS_MODE")))
	if mode == "" {
		return "auto"
	}
	return mode
}

func commandAvailable(name string) bool {
	_, err := lookPath(name)
	return err == nil
}
