//go:build darwin
// +build darwin

package device

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const socketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

var allowAppFirewallOnce sync.Once

// allowInboundThroughAppFirewall adds the daemon to the macOS Application
// Firewall allow list when the firewall is on. The root daemon is not listed
// by default and, with stealth mode, unsolicited inbound UDP (the peer's
// first hole-punch packets) is dropped, so direct paths could never open.
// Best effort: failures are logged and never stop the tunnel.
func allowInboundThroughAppFirewall() {
	allowAppFirewallOnce.Do(func() {
		out, err := exec.Command(socketFilterFW, "--getglobalstate").CombinedOutput()
		if err != nil || !appFirewallEnabled(string(out)) {
			return
		}
		exe, err := os.Executable()
		if err != nil {
			return
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		if out, err := exec.Command(socketFilterFW, "--add", exe).CombinedOutput(); err != nil {
			log.Printf("[P2P] Could not add %s to the application firewall: %v %s", exe, err, strings.TrimSpace(string(out)))
			return
		}
		if out, err := exec.Command(socketFilterFW, "--unblockapp", exe).CombinedOutput(); err != nil {
			log.Printf("[P2P] Could not allow %s through the application firewall: %v %s", exe, err, strings.TrimSpace(string(out)))
			return
		}
		log.Printf("[P2P] Allowed incoming connections for %s in the application firewall", exe)
	})
}

// appFirewallEnabled parses `socketfilterfw --getglobalstate`, e.g.
// "Firewall is enabled. (State = 1)".
func appFirewallEnabled(output string) bool {
	output = strings.ToLower(output)
	return strings.Contains(output, "enabled") && !strings.Contains(output, "disabled")
}
