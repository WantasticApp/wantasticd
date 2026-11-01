//go:build windows

package firewall

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
)

// AllowApp lets inbound UDP reach exePath on every network profile, so
// peers can reach this device directly instead of through the relay.
func AllowApp(exePath string) error {
	return replaceRule(AppRuleID, AppRuleName, "Direct peer-to-peer connections for Wantastic",
		"-Protocol UDP -Program "+psQuote(exePath))
}

// AllowOverlay lets any inbound traffic addressed to this device's overlay
// IPs through. Such packets only ever arrive over the tunnel, whose adapter
// Windows classifies as an unidentified public network and blocks.
func AllowOverlay(addrs []netip.Prefix) error {
	var ips []string
	for _, p := range addrs {
		if p.IsValid() {
			ips = append(ips, psQuote(p.Addr().String()))
		}
	}
	if len(ips) == 0 {
		return nil
	}
	return replaceRule(OverlayRuleID, OverlayRuleName, "Traffic from Wantastic peers over the tunnel",
		"-Protocol Any -LocalAddress @("+strings.Join(ips, ",")+")")
}

// Remove deletes the rules AllowApp and AllowOverlay create.
func Remove() error {
	return powershell(removeScript(AppRuleID, AppRuleName) + removeScript(OverlayRuleID, OverlayRuleName))
}

func replaceRule(id, name, description, match string) error {
	return powershell(removeScript(id, name) + fmt.Sprintf(
		"New-NetFirewallRule -Name %s -DisplayName %s -Description %s -Direction Inbound -Action Allow -Profile Any -Enabled True %s | Out-Null\n",
		psQuote(id), psQuote(name), psQuote(description), match))
}

// removeScript drops rules by ID and by display name (older netsh-made rules
// have only the latter).
func removeScript(id, name string) string {
	return fmt.Sprintf("Get-NetFirewallRule -Name %s -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n"+
		"Get-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n",
		psQuote(id), psQuote(name))
}

func exists(id string) bool {
	return powershell(fmt.Sprintf("if (-not (Get-NetFirewallRule -Name %s -ErrorAction SilentlyContinue)) { exit 3 }\n", psQuote(id))) == nil
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// powershell runs script with -EncodedCommand (UTF-16LE base64), so no
// value in it goes through command-line quoting.
func powershell(script string) error {
	script = "$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n" + script
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.Command(exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", base64.StdEncoding.EncodeToString(b))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("windows firewall: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
