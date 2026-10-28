//go:build darwin

package runner

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

const (
	daemonLaunchdLabel = "com.wantastic.wantasticd"
	trayAgentLabel     = "com.wantastic.tray"
	trayAgentPlist     = "/Library/LaunchAgents/" + trayAgentLabel + ".plist"
	noTrayMarker       = "/Library/Application Support/Wantastic/no-tray"
)

// EnsureTrayAgent installs the menu-bar LaunchAgent when the daemon runs as
// the launchd service and the agent is missing: installs from before the
// menu-bar app existed get it on their first update. An admin opt-out
// (install.sh --no-tray) leaves a marker that is respected.
func EnsureTrayAgent() {
	if os.Geteuid() != 0 || os.Getenv("XPC_SERVICE_NAME") != daemonLaunchdLabel {
		return
	}
	if _, err := os.Stat(noTrayMarker); err == nil {
		return
	}
	if _, err := os.Stat(trayAgentPlist); err == nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	plist := trayAgentPlistContent(exe)
	if err := os.MkdirAll(filepath.Dir(trayAgentPlist), 0o755); err != nil {
		log.Printf("tray agent: %v", err)
		return
	}
	tmp := trayAgentPlist + ".tmp"
	if err := os.WriteFile(tmp, []byte(plist), 0o644); err != nil {
		log.Printf("tray agent: %v", err)
		return
	}
	if err := os.Rename(tmp, trayAgentPlist); err != nil {
		os.Remove(tmp)
		log.Printf("tray agent: %v", err)
		return
	}
	log.Printf("Installed menu-bar agent %s", trayAgentPlist)

	// Start it now for the logged-in user; otherwise it starts at next login.
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return
	}
	domain := "gui/" + strconv.FormatUint(uint64(st.Uid), 10)
	if out, err := exec.Command("launchctl", "bootstrap", domain, trayAgentPlist).CombinedOutput(); err != nil {
		log.Printf("tray agent: bootstrap %s: %v: %s", domain, err, out)
	}
}

func trayAgentPlistContent(exe string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array><string>%s</string><string>tray</string></array>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Interactive</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
</dict></plist>
`, trayAgentLabel, xmlEscape(exe))
}

func xmlEscape(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			b = append(b, "&amp;"...)
		case '<':
			b = append(b, "&lt;"...)
		case '>':
			b = append(b, "&gt;"...)
		default:
			b = append(b, c)
		}
	}
	return string(b)
}
