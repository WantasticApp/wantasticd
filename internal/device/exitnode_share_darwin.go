//go:build darwin
// +build darwin

package device

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
)

const (
	darwinLocalAccessAnchor = "com.apple/wantastic"
	darwinPFCTLPath         = "/sbin/pfctl"
	darwinRoutePath         = "/sbin/route"
	darwinSysctlPath        = "/usr/sbin/sysctl"
)

var darwinLocalAccessState struct {
	sync.Mutex
	active            bool
	forwardingWasOn   bool
	packetFilterToken string
}

func enableExitNodeSharingOS(tunName string) (string, error) {
	return "", fmt.Errorf("exit-node sharing requires a Network Extension with managed NAT on macOS")
}

func disableExitNodeSharingOS(tunName string) error {
	return nil
}

func enableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	rules, err := buildDarwinLocalAccessRules(tunName, routes, sources, darwinRouteInterface)
	if err != nil {
		return err
	}

	darwinLocalAccessState.Lock()
	defer darwinLocalAccessState.Unlock()
	if darwinLocalAccessState.active {
		return nil
	}

	forwardingWasOn, err := darwinIPv4ForwardingEnabled()
	if err != nil {
		return err
	}
	pfWasOn, err := darwinPFEnabled()
	if err != nil {
		return err
	}

	var token string
	if !pfWasOn {
		token, err = enableDarwinPF()
		if err != nil {
			return err
		}
	}
	rollbackPF := func() {
		_ = flushDarwinLocalAccessAnchor()
		if token != "" {
			_, _ = exec.Command(darwinPFCTLPath, "-X", token).CombinedOutput()
		}
	}
	if err := loadDarwinLocalAccessAnchor(rules); err != nil {
		rollbackPF()
		return err
	}
	if !forwardingWasOn {
		if err := setDarwinIPv4Forwarding(true); err != nil {
			rollbackPF()
			return err
		}
	}

	darwinLocalAccessState.active = true
	darwinLocalAccessState.forwardingWasOn = forwardingWasOn
	darwinLocalAccessState.packetFilterToken = token
	return nil
}

func disableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	darwinLocalAccessState.Lock()
	defer darwinLocalAccessState.Unlock()
	if !darwinLocalAccessState.active {
		// Clear rules left by a helper that was terminated before normal cleanup.
		return flushDarwinLocalAccessAnchor()
	}

	var errs []error
	if err := flushDarwinLocalAccessAnchor(); err != nil {
		errs = append(errs, err)
	}
	if !darwinLocalAccessState.forwardingWasOn {
		if err := setDarwinIPv4Forwarding(false); err != nil {
			errs = append(errs, err)
		}
	}
	if darwinLocalAccessState.packetFilterToken != "" {
		if output, err := exec.Command(
			darwinPFCTLPath,
			"-X",
			darwinLocalAccessState.packetFilterToken,
		).CombinedOutput(); err != nil {
			errs = append(errs, fmt.Errorf("release Wantastic packet-filter reference: %w: %s", err, strings.TrimSpace(string(output))))
		}
	}
	darwinLocalAccessState.active = false
	darwinLocalAccessState.forwardingWasOn = false
	darwinLocalAccessState.packetFilterToken = ""
	return errors.Join(errs...)
}

type darwinRouteResolver func(netip.Prefix) (string, error)

func buildDarwinLocalAccessRules(
	tunName string,
	routes, sources []string,
	resolve darwinRouteResolver,
) (string, error) {
	if !validDarwinInterfaceName(tunName) {
		return "", fmt.Errorf("invalid tunnel interface %q", tunName)
	}
	parsedSources, err := parseLocalAccessRoutes(sources)
	if err != nil {
		return "", fmt.Errorf("validate local-access source routes: %w", err)
	}
	parsedRoutes, err := parseLocalAccessRoutes(routes)
	if err != nil {
		return "", err
	}
	if len(parsedSources) == 0 || len(parsedRoutes) == 0 {
		return "", fmt.Errorf("local-access routes and overlay sources are required")
	}

	var rules strings.Builder
	for _, route := range parsedRoutes {
		for _, source := range parsedSources {
			if route.Overlaps(source) {
				return "", fmt.Errorf("local-access route %s overlaps overlay source %s", route, source)
			}
		}
		egress, err := resolve(route)
		if err != nil {
			return "", fmt.Errorf("resolve local route %s: %w", route, err)
		}
		if !validDarwinInterfaceName(egress) || egress == tunName {
			return "", fmt.Errorf("local route %s does not use a safe LAN interface", route)
		}
		for _, source := range parsedSources {
			fmt.Fprintf(
				&rules,
				"nat on %s inet from %s to %s -> (%s)\n",
				egress,
				source,
				route,
				egress,
			)
			fmt.Fprintf(
				&rules,
				"pass in quick on %s inet from %s to %s keep state\n",
				tunName,
				source,
				route,
			)
		}
	}
	return rules.String(), nil
}

func validDarwinInterfaceName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func darwinRouteInterface(prefix netip.Prefix) (string, error) {
	output, err := exec.Command(darwinRoutePath, "-n", "get", prefix.Addr().String()).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route lookup: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && key == "interface" {
			return strings.TrimSpace(value), nil
		}
	}
	return "", fmt.Errorf("route lookup did not return an interface")
}

func darwinIPv4ForwardingEnabled() (bool, error) {
	output, err := exec.Command(darwinSysctlPath, "-n", "net.inet.ip.forwarding").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("read macOS IPv4 forwarding state: %w: %s", err, strings.TrimSpace(string(output)))
	}
	value := strings.TrimSpace(string(output))
	if value != "0" && value != "1" {
		return false, fmt.Errorf("unexpected macOS IPv4 forwarding state %q", value)
	}
	return value == "1", nil
}

func setDarwinIPv4Forwarding(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	output, err := exec.Command(darwinSysctlPath, "-w", "net.inet.ip.forwarding="+value).CombinedOutput()
	if err != nil {
		return fmt.Errorf("set macOS IPv4 forwarding: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func darwinPFEnabled() (bool, error) {
	output, err := exec.Command(darwinPFCTLPath, "-s", "info").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("read macOS packet-filter state: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "Status:" {
			return fields[1] == "Enabled", nil
		}
	}
	return false, fmt.Errorf("macOS packet-filter status was not reported")
}

func enableDarwinPF() (string, error) {
	output, err := exec.Command(darwinPFCTLPath, "-E").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("enable macOS packet filter: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		if before, after, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(before) == "Token" {
			token := strings.TrimSpace(after)
			if token != "" {
				return token, nil
			}
		}
	}
	return "", fmt.Errorf("enable macOS packet filter: reference token was not reported")
}

func loadDarwinLocalAccessAnchor(rules string) error {
	cmd := exec.Command(darwinPFCTLPath, "-a", darwinLocalAccessAnchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install Wantastic packet-filter rules: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func flushDarwinLocalAccessAnchor() error {
	output, err := exec.Command(darwinPFCTLPath, "-a", darwinLocalAccessAnchor, "-F", "all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove Wantastic packet-filter rules: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
