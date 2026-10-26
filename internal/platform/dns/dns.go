package dns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	resolvConfPath  = "/etc/resolv.conf"
	lookupHost      = net.DefaultResolver.LookupHost
	lookupViaServer = lookupHostWithServer
	lstatPath       = os.Lstat
	readFile        = os.ReadFile
	writeFile       = os.WriteFile
	removePath      = os.Remove
	lookPath        = exec.LookPath
)

func lookupHostWithServer(ctx context.Context, server, host string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
		},
	}
	return resolver.LookupHost(ctx, host)
}

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

// EnsureBootstrapHost repairs a resolver list poisoned by an unavailable
// tunnel DNS. Existing servers are probed concurrently and only servers that
// can resolve the actual bootstrap host are retained, preserving their order.
func EnsureBootstrapHost(ctx context.Context, host string) Result {
	host = strings.TrimSpace(host)
	if host == "" {
		return EnsureBootstrap(ctx)
	}
	checkCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if _, err := lookupHost(checkCtx, host); err == nil {
		return Result{Method: "system-resolver", Reason: "resolver already works"}
	}
	existing := readResolvNameservers(resolvConfPath)
	reachable := probeResolverServers(checkCtx, existing, host)
	if len(reachable) == 0 {
		return EnsureBootstrap(ctx)
	}
	result, err := Apply(ctx, Request{Servers: reachable, Reason: "bootstrap endpoint resolution"})
	if err != nil {
		log.Printf("DNS: reachable bootstrap DNS apply failed: %v", err)
		return Result{Skipped: true, Reason: err.Error()}
	}
	if result.Changed {
		log.Printf("DNS: selected reachable bootstrap resolvers for %s: %v", host, reachable)
	}
	return result
}

func probeResolverServers(ctx context.Context, servers []string, host string) []string {
	ok := make([]bool, len(servers))
	var wg sync.WaitGroup
	for i, server := range servers {
		i, server := i, strings.TrimSpace(server)
		if net.ParseIP(server) == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			_, err := lookupViaServer(probeCtx, server, host)
			ok[i] = err == nil
		}()
	}
	wg.Wait()
	out := make([]string, 0, len(servers))
	for i, server := range servers {
		if ok[i] {
			out = append(out, strings.TrimSpace(server))
		}
	}
	return out
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
	} else if result.Skipped && logTunnelSkipOnce(result.Reason) {
		log.Printf("DNS: tunnel DNS not written (%s)", result.Reason)
	}
	return result
}

var lastTunnelSkip struct {
	mu     sync.Mutex
	reason string
}

// logTunnelSkipOnce reports a skip reason only when it changes: ApplyTunnel
// re-runs every two minutes and an unchanged, intended skip (a DNS manager
// owns resolv.conf) is not news.
func logTunnelSkipOnce(reason string) bool {
	lastTunnelSkip.mu.Lock()
	defer lastTunnelSkip.mu.Unlock()
	if lastTunnelSkip.reason == reason {
		return false
	}
	lastTunnelSkip.reason = reason
	return true
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

// manualMarker records the console's manual resolver list inside the file
// itself, so the reported Mode/Servers follow what is really in effect: a
// DHCP client or vendor daemon that rewrites the file drops the marker, and
// the agent's own periodic tunnel rewrites carry it over.
const manualMarker = "# wantasticd-manual:"

// controlReason is the header reason for a console-applied manual list.
const controlReason = "DNS control"

func writeResolvFile(path string, servers []string, reason string) (Result, error) {
	return writeResolvFileManual(path, servers, reason, readManualMarker(path))
}

// writeResolvFileManual writes servers to path, recording manual (the
// console's list, empty for automatic) in the file. A symlinked resolv.conf
// (OE/QTI images link it into /var/run or /run) is written through so the
// link and the volatile design survive; only a dangling link whose target
// directory is gone is replaced by a regular file.
func writeResolvFileManual(path string, servers []string, reason string, manual []string) (Result, error) {
	existing := readResolvNameservers(path)
	if sameServers(existing, servers) && sameServers(readManualMarker(path), manual) {
		return Result{Method: "resolv.conf", Reason: "already current", Servers: servers}, nil
	}

	var b strings.Builder
	b.WriteString("# Managed by wantasticd")
	if reason != "" {
		b.WriteString(" for ")
		b.WriteString(reason)
	}
	b.WriteByte('\n')
	if len(manual) > 0 {
		b.WriteString(manualMarker)
		b.WriteByte(' ')
		b.WriteString(strings.Join(manual, " "))
		b.WriteByte('\n')
	}
	for _, server := range servers {
		b.WriteString("nameserver ")
		b.WriteString(server)
		b.WriteByte('\n')
	}
	b.WriteString("options timeout:1 attempts:1\n")

	target := resolvWriteTarget(path)
	if err := writeFile(target, []byte(b.String()), 0o644); err != nil {
		return Result{}, describeWriteError(target, err)
	}
	return Result{Changed: true, Method: "resolv.conf", Reason: reason, Servers: servers}, nil
}

// resolvWriteTarget returns the file a write to path must go to: path itself,
// or the target of a symlinked resolv.conf.
func resolvWriteTarget(path string) string {
	fi, err := lstatPath(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return path
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	link, err := os.Readlink(path)
	if err != nil {
		return path
	}
	if !filepath.IsAbs(link) {
		link = filepath.Join(filepath.Dir(path), link)
	}
	if st, err := os.Stat(filepath.Dir(link)); err == nil && st.IsDir() {
		return link
	}
	_ = removePath(path)
	return path
}

// describeWriteError makes a read-only root filesystem obvious instead of a
// bare EROFS.
func describeWriteError(path string, err error) error {
	if errors.Is(err, syscall.EROFS) {
		return fmt.Errorf("write %s: read-only filesystem; remount it read-write or manage DNS through the platform resolver: %w", path, err)
	}
	return fmt.Errorf("write %s: %w", path, err)
}

// readManualMarker returns the console's manual list recorded in path. Files
// written by older agents carry only the DNS-control header; their nameserver
// lines are the manual list.
func readManualMarker(path string) []string {
	data, err := readFile(path)
	if err != nil {
		return nil
	}
	legacy := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, manualMarker) {
			return strings.Fields(strings.TrimPrefix(line, manualMarker))
		}
		if line == "# Managed by wantasticd for "+controlReason {
			legacy = true
		}
	}
	if legacy {
		return readResolvNameservers(path)
	}
	return nil
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
