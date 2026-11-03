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

// Launchd jobs and paths shared by install.sh, the daemon and uninstall.
const (
	DaemonLaunchdLabel = "com.wantastic.wantasticd"
	TrayAgentLabel     = "com.wantastic.tray"
	TrayAgentPlist     = "/Library/LaunchAgents/" + TrayAgentLabel + ".plist"
	NoTrayMarker       = "/Library/Application Support/Wantastic/no-tray"
)

// EnsureTrayAgent installs the menu-bar LaunchAgent when the daemon runs as
// the launchd service and the agent is missing: installs from before the
// menu-bar app existed get it on their first update. An admin opt-out
// (install.sh --no-tray) leaves a marker that is respected.
func EnsureTrayAgent() {
	if os.Geteuid() != 0 || os.Getenv("XPC_SERVICE_NAME") != DaemonLaunchdLabel {
		return
	}
	if _, err := os.Stat(NoTrayMarker); err == nil {
		return
	}
	if _, err := os.Stat(TrayAgentPlist); err == nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if err := writeTrayAgentPlist(exe); err != nil {
		log.Printf("tray agent: %v", err)
		return
	}
	log.Printf("Installed menu-bar agent %s", TrayAgentPlist)

	// Start it now for the logged-in user; otherwise it starts at next login.
	if _, err := StartTrayAgent(); err != nil {
		log.Printf("tray agent: %v", err)
	}
}

// InstallTrayAgent (re)writes the menu-bar LaunchAgent for exe, clears the
// --no-tray opt-out and starts it for the logged-in user. started is false
// when nobody is logged in at the screen; it then starts at the next login.
func InstallTrayAgent(exe string) (started bool, err error) {
	if err := os.Remove(NoTrayMarker); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := writeTrayAgentPlist(exe); err != nil {
		return false, err
	}
	return StartTrayAgent()
}

// StartTrayAgent restarts the menu-bar app for the user at the screen.
func StartTrayAgent() (started bool, err error) {
	uid, ok := ConsoleUID()
	if !ok {
		return false, nil
	}
	domain := "gui/" + strconv.FormatUint(uint64(uid), 10)
	_ = exec.Command("launchctl", "bootout", domain+"/"+TrayAgentLabel).Run()
	if out, err := exec.Command("launchctl", "bootstrap", domain, TrayAgentPlist).CombinedOutput(); err != nil {
		return false, fmt.Errorf("bootstrap %s: %v: %s", domain, err, out)
	}
	return true, nil
}

// RemoveTrayAgent stops the menu-bar app and removes its LaunchAgent; with
// optOut the daemon will not put it back (the install.sh --no-tray marker).
func RemoveTrayAgent(optOut bool) error {
	if uid, ok := ConsoleUID(); ok {
		_ = exec.Command("launchctl", "bootout", "gui/"+strconv.FormatUint(uint64(uid), 10)+"/"+TrayAgentLabel).Run()
	}
	if err := os.Remove(TrayAgentPlist); err != nil && !os.IsNotExist(err) {
		return err
	}
	if !optOut {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(NoTrayMarker), 0o755); err != nil {
		return err
	}
	return os.WriteFile(NoTrayMarker, nil, 0o644)
}

func writeTrayAgentPlist(exe string) error {
	if err := os.MkdirAll(filepath.Dir(TrayAgentPlist), 0o755); err != nil {
		return err
	}
	tmp := TrayAgentPlist + ".tmp"
	if err := os.WriteFile(tmp, []byte(trayAgentPlistContent(exe)), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, TrayAgentPlist); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// DaemonPlistContent is the launchd daemon install.sh writes: the agent
// connects with configPath at boot and launchd restarts it if it exits.
func DaemonPlistContent(exe, configPath, logPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>connect</string>
    <string>--config</string><string>%s</string>
    <string>--tray=false</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>AbandonProcessGroup</key><true/>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, DaemonLaunchdLabel, xmlEscape(exe), xmlEscape(configPath), xmlEscape(logPath), xmlEscape(logPath))
}

// ConsoleUID is the user logged in at the Mac's screen, if any.
func ConsoleUID() (uint32, bool) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return 0, false
	}
	return st.Uid, true
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
`, TrayAgentLabel, xmlEscape(exe))
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
