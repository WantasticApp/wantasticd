//go:build darwin

package dns

import (
	"context"
	"errors"
	"strings"
)

// macOS: DNS belongs to the primary network service (the one carrying the
// default route); networksetup applies it live.

func ReadControl(ctx context.Context) ControlState {
	service, err := macPrimaryService(ctx)
	if err != nil {
		return ControlState{Method: "macos-networksetup", Reason: err.Error()}
	}
	st := ControlState{Supported: true, Method: "macos-networksetup", Effective: readResolvNameservers(resolvConfPath)}
	out, _ := runCommand(ctx, "", "networksetup", "-getdnsservers", service)
	if !strings.Contains(out, "aren't any") {
		st.Servers = strings.Fields(out)
		st.Manual = len(st.Servers) > 0
	}
	return st
}

func SetServers(ctx context.Context, servers []string) error {
	servers, err := NormalizeServers(servers)
	if err != nil {
		return err
	}
	service, err := macPrimaryService(ctx)
	if err != nil {
		return err
	}
	args := append([]string{"-setdnsservers", service}, servers...)
	if len(servers) == 0 {
		args = []string{"-setdnsservers", service, "Empty"}
	}
	_, err = runCommand(ctx, "", "networksetup", args...)
	return err
}

func macPrimaryService(ctx context.Context) (string, error) {
	out, err := runCommand(ctx, "", "route", "-n", "get", "default")
	if err != nil {
		return "", err
	}
	device := ""
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k == "interface" {
			device = strings.TrimSpace(v)
		}
	}
	if device == "" {
		return "", errors.New("no default route")
	}
	order, err := runCommand(ctx, "", "networksetup", "-listnetworkserviceorder")
	if err != nil {
		return "", err
	}
	return macServiceForDevice(order, device)
}

// macServiceForDevice maps "en0" to its service name from
// `networksetup -listnetworkserviceorder` output.
func macServiceForDevice(order, device string) (string, error) {
	lines := strings.Split(order, "\n")
	for i := 1; i < len(lines); i++ {
		if strings.Contains(lines[i], "Device: "+device+")") {
			name := strings.TrimSpace(lines[i-1])
			if _, rest, ok := strings.Cut(name, ") "); ok {
				return strings.TrimSpace(rest), nil
			}
		}
	}
	return "", errors.New("no network service for " + device)
}
