package platforms

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/platform/systemd"
	"wantastic-agent/internal/wusp"
)

// NTP client control on generic Linux. timedatectl only covers
// systemd-timesyncd; embedded images (QTI/Quectel, busybox, Yocto) run
// chrony, ntp.org ntpd or busybox ntpd instead, so the client is detected
// from its running process first and its installed configuration second,
// and servers are written to the file that client actually reads.

const (
	ntpClientTimesyncd = "systemd-timesyncd"
	ntpClientChrony    = "chrony"
	ntpClientNTPd      = "ntpd"
	ntpClientBusybox   = "busybox-ntpd"

	// ntpMaxServers matches Device.Time.NTPServer1..5.
	ntpMaxServers = 5

	ntpBlockBegin   = "# BEGIN wantasticd NTP servers"
	ntpBlockEnd     = "# END wantasticd NTP servers"
	ntpDisabledMark = "#wantasticd-disabled: "

	ntpProcessCacheTTL = 30 * time.Second
)

// ntpEnv holds the paths NTP detection reads; tests point it at a temp dir.
// A nil env (backends built with an injected command runner) disables
// detection so tests never inspect the real system.
type ntpEnv struct {
	procDir         string
	timesyncdConf   string
	timesyncdDropIn string // file the agent owns inside timesyncd.conf.d
	timesyncdUnits  []string
	chronyConfs     []string
	ntpConf         string
	initDir         string
	systemdRunDir   string // exists when systemd is PID 1
	lookPath        func(string) (string, error)

	mu        sync.Mutex
	scannedAt time.Time
	procs     []ntpProcess
}

type ntpProcess struct {
	pid  int
	kind string
	args []string
}

// ntpClientState is the detected client, whether it runs and its servers.
type ntpClientState struct {
	Kind    string
	Running bool
	Servers []string
	pid     int
}

func defaultNTPEnv() *ntpEnv {
	return &ntpEnv{
		procDir:         "/proc",
		timesyncdConf:   "/etc/systemd/timesyncd.conf",
		timesyncdDropIn: "/etc/systemd/timesyncd.conf.d/90-wantastic-ntp.conf",
		timesyncdUnits: []string{
			"/lib/systemd/system/systemd-timesyncd.service",
			"/usr/lib/systemd/system/systemd-timesyncd.service",
			"/etc/systemd/system/systemd-timesyncd.service",
		},
		chronyConfs:   []string{"/etc/chrony/chrony.conf", "/etc/chrony.conf"},
		ntpConf:       "/etc/ntp.conf",
		initDir:       "/etc/init.d",
		systemdRunDir: "/run/systemd/system",
		lookPath:      exec.LookPath,
	}
}

func (e *ntpEnv) invalidate() {
	e.mu.Lock()
	e.scannedAt = time.Time{}
	e.mu.Unlock()
}

// processes scans /proc for NTP daemons, cached so a Collect every few
// seconds does not walk /proc each time.
func (e *ntpEnv) processes() []ntpProcess {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.scannedAt.IsZero() && time.Since(e.scannedAt) < ntpProcessCacheTTL {
		return e.procs
	}
	e.procs = scanNTPProcesses(e.procDir)
	e.scannedAt = time.Now()
	return e.procs
}

func scanNTPProcesses(procDir string) []ntpProcess {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil
	}
	var out []ntpProcess
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		dir := filepath.Join(procDir, entry.Name())
		comm := strings.TrimSpace(readTextFile(filepath.Join(dir, "comm")))
		if comm != "chronyd" && comm != "ntpd" && comm != "systemd-timesyn" && comm != "systemd-timesyncd" {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		proc := ntpProcess{pid: pid, args: args}
		switch comm {
		case "chronyd":
			proc.kind = ntpClientChrony
		case "ntpd":
			proc.kind = ntpClientNTPd
			exe, _ := os.Readlink(filepath.Join(dir, "exe"))
			if filepath.Base(exe) == "busybox" || isBusyboxNTPdArgs(args) {
				proc.kind = ntpClientBusybox
			}
		default:
			proc.kind = ntpClientTimesyncd
		}
		out = append(out, proc)
	}
	return out
}

// isBusyboxNTPdArgs tells busybox ntpd ("-p <peer>") from ntp.org ntpd,
// whose -p takes a pidfile path.
func isBusyboxNTPdArgs(args []string) bool {
	peers := busyboxNTPPeers(args)
	return len(peers) > 0 && !strings.HasPrefix(peers[0], "/")
}

func busyboxNTPPeers(args []string) []string {
	var peers []string
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-p" && i+1 < len(args):
			peers = append(peers, args[i+1])
			i++
		case strings.HasPrefix(arg, "-p") && len(arg) > 2:
			peers = append(peers, arg[2:])
		case strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.HasSuffix(arg, "p") && i+1 < len(args):
			// Combined flags such as "-nqp host".
			peers = append(peers, args[i+1])
			i++
		}
	}
	return peers
}

func (e *ntpEnv) chronyConf() string {
	for _, path := range e.chronyConfs {
		if fileExists(path) {
			return path
		}
	}
	return ""
}

func (e *ntpEnv) timesyncdInstalled() bool {
	if fileExists(e.timesyncdConf) {
		return true
	}
	for _, unit := range e.timesyncdUnits {
		if fileExists(unit) {
			return true
		}
	}
	return false
}

func (e *ntpEnv) hasSystemd() bool {
	info, err := os.Stat(e.systemdRunDir)
	return err == nil && info.IsDir()
}

// detect returns the active NTP client: a running daemon wins over an
// installed but stopped one.
func (e *ntpEnv) detect() ntpClientState {
	if e == nil {
		return ntpClientState{}
	}
	for _, kind := range []string{ntpClientChrony, ntpClientTimesyncd, ntpClientNTPd, ntpClientBusybox} {
		for _, proc := range e.processes() {
			if proc.kind == kind {
				st := ntpClientState{Kind: kind, Running: true, pid: proc.pid}
				st.Servers = e.readServers(kind, proc.args)
				return st
			}
		}
	}
	st := ntpClientState{}
	switch {
	case e.chronyConf() != "":
		st.Kind = ntpClientChrony
	case e.timesyncdInstalled():
		st.Kind = ntpClientTimesyncd
	default:
		if e.lookPath == nil {
			return st
		}
		path, err := e.lookPath("ntpd")
		if err != nil {
			return st
		}
		st.Kind = ntpClientNTPd
		if resolved, err := filepath.EvalSymlinks(path); err == nil && filepath.Base(resolved) == "busybox" {
			st.Kind = ntpClientBusybox
		}
	}
	st.Servers = e.readServers(st.Kind, nil)
	return st
}

func (e *ntpEnv) readServers(kind string, args []string) []string {
	switch kind {
	case ntpClientTimesyncd:
		return e.readTimesyncdServers()
	case ntpClientChrony:
		conf := e.chronyConf()
		data := readTextFile(conf)
		servers := parseNTPConfServers(data)
		for _, dir := range chronySourceDirs(data) {
			matches, _ := filepath.Glob(filepath.Join(dir, "*.sources"))
			for _, match := range matches {
				servers = append(servers, parseNTPConfServers(readTextFile(match))...)
			}
		}
		return uniqueNTPServers(servers)
	case ntpClientNTPd:
		return uniqueNTPServers(parseNTPConfServers(readTextFile(e.ntpConf)))
	case ntpClientBusybox:
		if peers := busyboxNTPPeers(args); len(peers) > 0 {
			return uniqueNTPServers(peers)
		}
		return uniqueNTPServers(parseNTPConfServers(readTextFile(e.ntpConf)))
	}
	return nil
}

// readTimesyncdServers applies timesyncd's precedence: drop-ins (sorted)
// override timesyncd.conf, and FallbackNTP only counts without any NTP=.
func (e *ntpEnv) readTimesyncdServers() []string {
	files := []string{e.timesyncdConf}
	if dir := filepath.Dir(e.timesyncdDropIn); dir != "" {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
		files = append(files, matches...)
	}
	var ntp, fallback []string
	for _, file := range files {
		for _, line := range strings.Split(readTextFile(file), "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "NTP="):
				ntp = strings.Fields(strings.TrimPrefix(line, "NTP="))
			case strings.HasPrefix(line, "FallbackNTP="):
				fallback = strings.Fields(strings.TrimPrefix(line, "FallbackNTP="))
			}
		}
	}
	if len(ntp) > 0 {
		return uniqueNTPServers(ntp)
	}
	return uniqueNTPServers(fallback)
}

// parseNTPConfServers reads server/pool lines (chrony, ntp.org, busybox
// ntp.conf syntax).
func parseNTPConfServers(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && (fields[0] == "server" || fields[0] == "pool") {
			out = append(out, fields[1])
		}
	}
	return out
}

func chronySourceDirs(conf string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "sourcedir" {
			out = append(out, fields[1])
		}
	}
	return out
}

func uniqueNTPServers(servers []string) []string {
	out := make([]string, 0, len(servers))
	seen := map[string]bool{}
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" || seen[server] {
			continue
		}
		seen[server] = true
		out = append(out, server)
	}
	return out
}

// normalizeNTPServers validates a host name or IP list for NTPServerN and
// Client.1.Servers.
func normalizeNTPServers(servers []string) ([]string, error) {
	out := uniqueNTPServers(servers)
	for _, server := range out {
		if len(server) > 64 {
			return nil, fmt.Errorf("NTP server %q is longer than 64 characters", server)
		}
		for _, r := range server {
			if !(r == '.' || r == '-' || r == ':' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
				return nil, fmt.Errorf("NTP server %q is not a host name or IP address", server)
			}
		}
	}
	if len(out) > ntpMaxServers {
		return nil, fmt.Errorf("at most %d NTP servers are supported", ntpMaxServers)
	}
	return out, nil
}

// rewriteNTPConfServers replaces the server/pool lines of a chrony or ntp
// config with a managed block. Original lines are commented out with a
// marker and restored when the list is emptied, so Automatic returns the
// distribution defaults. writeBlock=false only comments out (chrony then
// gets the list from its sourcedir file).
func rewriteNTPConfServers(data string, servers []string, writeBlock bool) string {
	var lines []string
	inBlock := false
	for _, line := range strings.Split(strings.TrimRight(data, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == ntpBlockBegin:
			inBlock = true
			continue
		case trimmed == ntpBlockEnd:
			inBlock = false
			continue
		case inBlock:
			continue
		case strings.HasPrefix(line, ntpDisabledMark):
			line = strings.TrimPrefix(line, ntpDisabledMark)
		}
		lines = append(lines, line)
	}
	if len(servers) > 0 {
		for i, line := range lines {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 2 && (fields[0] == "server" || fields[0] == "pool") {
				lines[i] = ntpDisabledMark + line
			}
		}
		if writeBlock {
			lines = append(lines, ntpBlockBegin)
			for _, server := range servers {
				lines = append(lines, "server "+server+" iburst")
			}
			lines = append(lines, ntpBlockEnd)
		}
	}
	out := strings.Join(lines, "\n")
	if strings.TrimSpace(out) == "" {
		return ""
	}
	return out + "\n"
}

func writeFileIfChanged(path, data string) (bool, error) {
	if current, err := os.ReadFile(path); err == nil && string(current) == data {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, []byte(data), 0o644)
}

func removeFileIfExists(path string) (bool, error) {
	err := os.Remove(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// ntpServiceNames lists the systemd units / init scripts per client.
func ntpServiceNames(kind string) []string {
	switch kind {
	case ntpClientTimesyncd:
		return []string{"systemd-timesyncd"}
	case ntpClientChrony:
		return []string{"chronyd", "chrony"}
	case ntpClientNTPd:
		return []string{"ntpd", "ntp"}
	case ntpClientBusybox:
		return []string{"sysntpd", "ntpd", "busybox-ntpd"}
	}
	return nil
}

func hostKindSupportsNTPControl(kind Kind) bool {
	return kind == KindLinux || kind == KindONU
}

func (b *hostBackend) ntpClient() ntpClientState {
	if b.ntp == nil || !hostKindSupportsNTPControl(b.kind) {
		return ntpClientState{}
	}
	return b.ntp.detect()
}

// appendNTPClientFields reports the legacy NTPServerN list and the
// Time.Client.1 row, mirroring the OpenWrt backend.
func appendNTPClientFields(msg *wusp.Message, enabled bool, servers []string) {
	for i := 1; i <= ntpMaxServers; i++ {
		server := ""
		if i <= len(servers) {
			server = servers[i-1]
		}
		appendField(msg, fmt.Sprintf("Device.Time.NTPServer%d", i), wusp.String(server))
	}
	appendField(msg, "Device.Time.ClientNumberOfEntries", wusp.Uint(1))
	appendField(msg, "Device.Time.Client.1.Enable", wusp.Bool(enabled))
	appendField(msg, "Device.Time.Client.1.Status", wusp.String(ntpClientStatus(enabled)))
	appendField(msg, "Device.Time.Client.1.Alias", wusp.String("system-ntp"))
	appendField(msg, "Device.Time.Client.1.Mode", wusp.String("Unicast"))
	appendField(msg, "Device.Time.Client.1.Port", wusp.Uint(123))
	appendField(msg, "Device.Time.Client.1.Version", wusp.Uint(4))
	values := make([]wusp.Value, 0, len(servers))
	for _, server := range servers {
		values = append(values, wusp.String(server))
	}
	appendField(msg, "Device.Time.Client.1.Servers", wusp.List(values...))
}

// ntpServerIndex parses Device.Time.NTPServerN.
func ntpServerIndex(path string) (int, bool) {
	rest, ok := strings.CutPrefix(path, "Device.Time.NTPServer")
	if !ok {
		return 0, false
	}
	index, err := strconv.Atoi(rest)
	return index, err == nil && index >= 1 && index <= ntpMaxServers
}

// replaceNTPServerAt sets entry index (1-based) of servers; an empty value
// removes it.
func replaceNTPServerAt(servers []string, index int, value string) []string {
	out := append([]string(nil), servers...)
	value = strings.TrimSpace(value)
	for len(out) < index {
		out = append(out, "")
	}
	out[index-1] = value
	return uniqueNTPServers(out)
}

func (b *hostBackend) setNTPServerIndex(ctx context.Context, index int, value string) error {
	current := b.ntpClient()
	if current.Kind == "" {
		return errors.New("no NTP client (systemd-timesyncd, chrony, ntpd or busybox ntpd) found on this device")
	}
	return b.applyNTPServers(ctx, current, replaceNTPServerAt(current.Servers, index, value))
}

func (b *hostBackend) setNTPServers(ctx context.Context, value wusp.Value) error {
	current := b.ntpClient()
	if current.Kind == "" {
		return errors.New("no NTP client (systemd-timesyncd, chrony, ntpd or busybox ntpd) found on this device")
	}
	return b.applyNTPServers(ctx, current, valueStringList(value))
}

// applyNTPServers writes servers where the detected client reads them and
// restarts only that client. An empty list restores its defaults.
func (b *hostBackend) applyNTPServers(ctx context.Context, client ntpClientState, servers []string) error {
	servers, err := normalizeNTPServers(servers)
	if err != nil {
		return err
	}
	env := b.ntp
	defer env.invalidate()
	changed := false
	switch client.Kind {
	case ntpClientTimesyncd:
		if len(servers) == 0 {
			changed, err = removeFileIfExists(env.timesyncdDropIn)
		} else {
			body := "# Managed by wantasticd (NTP control from the console)\n[Time]\nNTP=" + strings.Join(servers, " ") + "\n"
			changed, err = writeFileIfChanged(env.timesyncdDropIn, body)
		}
	case ntpClientChrony:
		conf := env.chronyConf()
		if conf == "" {
			return errors.New("chrony configuration file not found")
		}
		data := readTextFile(conf)
		dirs := chronySourceDirs(data)
		if len(dirs) > 0 {
			sources := filepath.Join(dirs[0], "wantastic.sources")
			var sourcesChanged bool
			if len(servers) == 0 {
				sourcesChanged, err = removeFileIfExists(sources)
			} else {
				var body strings.Builder
				body.WriteString("# Managed by wantasticd (NTP control from the console)\n")
				for _, server := range servers {
					body.WriteString("server " + server + " iburst\n")
				}
				sourcesChanged, err = writeFileIfChanged(sources, body.String())
			}
			if err != nil {
				return err
			}
			confChanged, err := writeFileIfChanged(conf, rewriteNTPConfServers(data, servers, false))
			if err != nil {
				return err
			}
			if sourcesChanged && !confChanged && client.Running {
				// sourcedir changes are picked up without a restart.
				if _, err := b.commandRunner(ctx, "chronyc", "reload", "sources"); err == nil {
					return b.persistNTPServers(servers)
				}
			}
			changed = sourcesChanged || confChanged
		} else {
			changed, err = writeFileIfChanged(conf, rewriteNTPConfServers(data, servers, true))
		}
	case ntpClientNTPd:
		changed, err = writeFileIfChanged(env.ntpConf, rewriteNTPConfServers(readTextFile(env.ntpConf), servers, true))
	case ntpClientBusybox:
		if fileExists(env.ntpConf) || b.ntpInitScript(client.Kind) != "" {
			// Busybox ntpd reads /etc/ntp.conf when started without -p.
			changed, err = writeFileIfChanged(env.ntpConf, rewriteNTPConfServers(readTextFile(env.ntpConf), servers, true))
		} else {
			if err := b.persistNTPServers(servers); err != nil {
				return err
			}
			return b.restartBusyboxNTPd(ctx, client, servers)
		}
	default:
		return errors.New("no NTP client found on this device")
	}
	if err != nil {
		return err
	}
	if err := b.persistNTPServers(servers); err != nil {
		return err
	}
	if !changed || !client.Running {
		return nil
	}
	return b.restartNTPService(ctx, client)
}

func (b *hostBackend) persistNTPServers(servers []string) error {
	return b.updateState(func(state *hostState) { state.NTPServers = servers })
}

func (b *hostBackend) ntpInitScript(kind string) string {
	if b.ntp == nil {
		return ""
	}
	for _, name := range ntpServiceNames(kind) {
		path := filepath.Join(b.ntp.initDir, name)
		if fileExists(path) {
			return path
		}
	}
	return ""
}

// restartNTPService restarts the running client through systemd when it is
// the init system, else through its init script.
func (b *hostBackend) restartNTPService(ctx context.Context, client ntpClientState) error {
	if b.ntp.hasSystemd() {
		var lastErr error
		for _, name := range ntpServiceNames(client.Kind) {
			if b.useSystemd && systemd.ReloadOrTryRestartUnit(ctx, name+".service") == nil {
				return nil
			}
			if _, err := b.commandRunner(ctx, "systemctl", "try-restart", name); err != nil {
				lastErr = err
				continue
			}
			return nil
		}
		if lastErr != nil {
			return fmt.Errorf("restart %s: %w", client.Kind, lastErr)
		}
	}
	if script := b.ntpInitScript(client.Kind); script != "" {
		_, err := b.commandRunner(ctx, script, "restart")
		return err
	}
	if client.Kind == ntpClientBusybox {
		state, _ := b.readState()
		return b.restartBusyboxNTPd(ctx, client, state.NTPServers)
	}
	return fmt.Errorf("no service manager found to restart %s", client.Kind)
}

// restartBusyboxNTPd relaunches a busybox ntpd that was started by hand
// (no init script, no ntp.conf) with the requested peers.
func (b *hostBackend) restartBusyboxNTPd(ctx context.Context, client ntpClientState, servers []string) error {
	if client.Running && client.pid > 0 {
		if _, err := b.commandRunner(ctx, "kill", strconv.Itoa(client.pid)); err != nil {
			return fmt.Errorf("stop busybox ntpd: %w", err)
		}
	}
	if len(servers) == 0 {
		servers = []string{"pool.ntp.org"}
	}
	args := make([]string, 0, len(servers)*2)
	for _, server := range servers {
		args = append(args, "-p", server)
	}
	_, err := b.commandRunner(ctx, "ntpd", args...)
	return err
}

// setNTPServiceEnabled enables (and starts) or disables (and stops) the
// detected non-timesyncd client.
func (b *hostBackend) setNTPServiceEnabled(ctx context.Context, client ntpClientState, enabled bool) error {
	defer b.ntp.invalidate()
	if b.ntp.hasSystemd() {
		var lastErr error
		for _, name := range ntpServiceNames(client.Kind) {
			args := []string{"disable", "--now", name}
			if enabled {
				args[0] = "enable"
			}
			if _, err := b.commandRunner(ctx, "systemctl", args...); err != nil {
				lastErr = err
				continue
			}
			return nil
		}
		if lastErr != nil && b.ntpInitScript(client.Kind) == "" {
			return fmt.Errorf("%s %s: %w", map[bool]string{true: "enable", false: "disable"}[enabled], client.Kind, lastErr)
		}
	}
	if script := b.ntpInitScript(client.Kind); script != "" {
		if enabled {
			_, _ = b.commandRunner(ctx, script, "enable")
			_, err := b.commandRunner(ctx, script, "start")
			return err
		}
		_, err := b.commandRunner(ctx, script, "stop")
		_, _ = b.commandRunner(ctx, script, "disable")
		return err
	}
	if client.Kind == ntpClientBusybox {
		if enabled {
			if client.Running {
				return nil
			}
			state, _ := b.readState()
			return b.restartBusyboxNTPd(ctx, client, firstNonEmptyList(state.NTPServers, client.Servers))
		}
		if client.Running && client.pid > 0 {
			_, err := b.commandRunner(ctx, "kill", strconv.Itoa(client.pid))
			return err
		}
		return nil
	}
	return fmt.Errorf("no service manager found to control %s", client.Kind)
}

func firstNonEmptyList(lists ...[]string) []string {
	for _, list := range lists {
		if len(list) > 0 {
			return list
		}
	}
	return nil
}

// reapplyPersistedNTP restores the console's list on a hand-started busybox
// ntpd, the one client whose peers live only on its command line and are
// lost on reboot.
func (b *hostBackend) reapplyPersistedNTP(ctx context.Context, client ntpClientState) {
	if client.Kind != ntpClientBusybox || !client.Running || b.ntpInitScript(client.Kind) != "" || fileExists(b.ntp.ntpConf) {
		return
	}
	b.ntpReapplyOnce.Do(func() {
		state, _ := b.readState()
		if len(state.NTPServers) == 0 || sameStringSlice(state.NTPServers, client.Servers) {
			return
		}
		if err := b.restartBusyboxNTPd(ctx, client, state.NTPServers); err != nil {
			fmt.Fprintf(os.Stderr, "[USP] NTP re-apply failed: %v\n", err)
		}
		b.ntp.invalidate()
	})
}
