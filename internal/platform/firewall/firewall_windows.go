//go:build windows

package firewall

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// AllowApp lets inbound UDP reach exePath on every network profile, so
// peers can reach this device directly instead of through the relay.
func AllowApp(exePath string) error {
	return replaceRule(AppRuleName, fmt.Sprintf(`dir=in action=allow enable=yes profile=any protocol=UDP program="%s" description="Direct peer-to-peer connections for Wantastic"`, exePath))
}

// AllowOverlay lets any inbound traffic addressed to this device's overlay
// IPs through. Such packets only ever arrive over the tunnel, whose adapter
// Windows classifies as an unidentified public network and blocks.
func AllowOverlay(addrs []netip.Prefix) error {
	var ips []string
	for _, p := range addrs {
		if p.IsValid() {
			ips = append(ips, p.Addr().String())
		}
	}
	if len(ips) == 0 {
		return nil
	}
	return replaceRule(OverlayRuleName, fmt.Sprintf(`dir=in action=allow enable=yes profile=any protocol=any localip=%s description="Traffic from Wantastic peers over the tunnel"`, strings.Join(ips, ",")))
}

// Remove deletes the rules AllowApp and AllowOverlay create.
func Remove() error {
	var firstErr error
	for _, name := range []string{AppRuleName, OverlayRuleName} {
		if exists(name) {
			if err := netsh(fmt.Sprintf(`delete rule name="%s"`, name)); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// replaceRule deletes every rule with this name (including ones an older
// installer made) and adds one with the given settings.
func replaceRule(name, settings string) error {
	if exists(name) {
		if err := netsh(fmt.Sprintf(`delete rule name="%s"`, name)); err != nil {
			return err
		}
	}
	return netsh(fmt.Sprintf(`add rule name="%s" %s`, name, settings))
}

func exists(name string) bool {
	return netsh(fmt.Sprintf(`show rule name="%s"`, name)) == nil
}

// netsh runs "netsh advfirewall firewall <args>". The command line is passed
// verbatim: netsh parses key="value with spaces" itself, which Go's argument
// quoting would break.
func netsh(args string) error {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
	cmd := exec.Command(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:    `"` + exe + `" advfirewall firewall ` + args,
		HideWindow: true,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh advfirewall firewall %s: %v: %s", strings.SplitN(args, " ", 2)[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}
