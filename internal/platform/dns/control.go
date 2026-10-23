package dns

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Resolver control: read and change the device's own DNS servers through
// the platform's DNS manager, so changes are live without restarting
// networking and survive the manager's next rewrite.

// MaxServers bounds a manual resolver list.
const MaxServers = 4

const controlTimeout = 20 * time.Second

// ControlState describes the device resolver configuration.
type ControlState struct {
	Supported bool
	Method    string
	Manual    bool
	Servers   []string // manual servers (empty when automatic)
	Effective []string // servers in use now
	Reason    string   // why control is unsupported
}

// runCommand runs a command with optional stdin; replaceable in tests.
var runCommand = func(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errOut.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.String(), fmt.Errorf("%s: %s", name, msg)
	}
	return out.String(), nil
}

// NormalizeServers validates and de-duplicates a manual resolver list.
func NormalizeServers(servers []string) ([]string, error) {
	out := make([]string, 0, len(servers))
	seen := map[string]bool{}
	for _, raw := range servers {
		server := strings.TrimSpace(raw)
		if server == "" {
			continue
		}
		ip := net.ParseIP(server)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, fmt.Errorf("%q is not a valid DNS server address", server)
		}
		server = ip.String()
		if seen[server] {
			continue
		}
		seen[server] = true
		out = append(out, server)
	}
	if len(out) > MaxServers {
		return nil, fmt.Errorf("at most %d DNS servers are supported", MaxServers)
	}
	return out, nil
}

func splitFamilies(servers []string) (v4, v6 []string) {
	for _, s := range servers {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	return
}

func parseNameserverLines(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}
