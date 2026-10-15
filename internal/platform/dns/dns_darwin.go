//go:build darwin

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const darwinResolverMarker = "# Managed by Wantastic; remove when the tunnel stops\n"

var darwinResolverDir = "/etc/resolver"

func Apply(ctx context.Context, req Request) (Result, error) {
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	default:
	}

	// A scoped resolver is appropriate only for the tunnel namespace. It must
	// never be used as a substitute for repairing the system-wide bootstrap DNS.
	if req.Reason != "tunnel DNS" {
		return Result{Skipped: true, Method: "macos-scoped-resolver", Reason: "system DNS is managed by macOS"}, nil
	}
	if os.Geteuid() != 0 {
		return Result{}, errors.New("macOS scoped DNS requires the privileged tunnel helper")
	}

	servers, err := validDarwinServers(req.Servers)
	if err != nil {
		return Result{}, err
	}
	if len(servers) == 0 {
		return Result{Skipped: true, Method: "macos-scoped-resolver", Reason: "no DNS servers requested"}, nil
	}
	changed, err := writeDarwinResolver(filepath.Join(darwinResolverDir, "wantastic"), servers)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Changed: changed,
		Method:  "macos-scoped-resolver",
		Reason:  req.Reason,
		Servers: servers,
	}, nil
}

func validDarwinServers(requested []string) ([]string, error) {
	servers := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, server := range requested {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if net.ParseIP(server) == nil {
			return nil, fmt.Errorf("invalid DNS server %q", server)
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		servers = append(servers, server)
	}
	return servers, nil
}

func darwinResolverContents(servers []string) []byte {
	var out strings.Builder
	out.WriteString(darwinResolverMarker)
	out.WriteString("domain wantastic\n")
	for _, server := range servers {
		out.WriteString("nameserver ")
		out.WriteString(server)
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

func writeDarwinResolver(path string, servers []string) (bool, error) {
	dir := filepath.Dir(path)
	if err := ensureDarwinResolverDir(dir); err != nil {
		return false, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return false, fmt.Errorf("refuse unsafe resolver path %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect resolver path %s: %w", path, err)
	}

	contents := darwinResolverContents(servers)
	if current, err := os.ReadFile(path); err == nil && string(current) == string(contents) {
		return false, nil
	}

	tmp, err := os.CreateTemp(dir, ".wantastic-*")
	if err != nil {
		return false, fmt.Errorf("create scoped resolver: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return false, fmt.Errorf("secure scoped resolver: %w", err)
	}
	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return false, fmt.Errorf("write scoped resolver: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, fmt.Errorf("sync scoped resolver: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close scoped resolver: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return false, fmt.Errorf("install scoped resolver: %w", err)
	}
	return true, nil
}

func ensureDarwinResolverDir(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return fmt.Errorf("create resolver directory: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect resolver directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refuse unsafe resolver directory %s", dir)
	}
	return nil
}

func removeTunnel(string) error {
	path := filepath.Join(darwinResolverDir, "wantastic")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect scoped resolver: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refuse unsafe resolver cleanup path %s", path)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read scoped resolver before cleanup: %w", err)
	}
	if !strings.HasPrefix(string(contents), darwinResolverMarker) {
		return fmt.Errorf("refuse to remove unmanaged resolver %s", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove scoped resolver: %w", err)
	}
	return nil
}
