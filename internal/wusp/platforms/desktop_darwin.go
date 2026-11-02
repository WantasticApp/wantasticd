//go:build darwin

package platforms

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// macSlowRefresh bounds how often port names, the computer name and the
// network-time setting (systemsetup is slow) are re-read.
const macSlowRefresh = 5 * time.Minute

type macProbe struct {
	run CommandRunner

	mu       sync.Mutex
	hw       macHardwareOverview
	hwDone   bool
	slowAt   time.Time
	ports    map[string]string
	computer string
	ntp      timeState
	servers  []string
}

func newDesktopProbe(run CommandRunner) desktopProbe { return &macProbe{run: run} }

func (p *macProbe) output(ctx context.Context, timeout time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := p.run(ctx, name, args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (p *macProbe) collect(ctx context.Context) *desktopSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()

	slow := time.Since(p.slowAt) > macSlowRefresh
	// Read once; a Mac (or VM) that reports no model retries only with the
	// slow refresh, not on every collect.
	if !p.hwDone || slow && p.hw.MachineModel == "" {
		p.hw = parseSPHardware([]byte(p.output(ctx, 10*time.Second, "system_profiler", "SPHardwareDataType", "-json")))
		p.hwDone = true
	}
	if slow {
		p.ports = parseHardwarePorts(p.output(ctx, 5*time.Second, "networksetup", "-listallhardwareports"))
		p.computer = p.output(ctx, 3*time.Second, "scutil", "--get", "ComputerName")
		switch out := strings.ToLower(p.output(ctx, 10*time.Second, "systemsetup", "-getusingnetworktime")); {
		case strings.HasSuffix(out, ": on"):
			p.ntp = timeState{Enabled: true, Known: true}
		case strings.HasSuffix(out, ": off"):
			p.ntp = timeState{Enabled: false, Known: true}
		}
		p.servers = parseNTPConfServers(readTextFile("/etc/ntp.conf"))
		p.slowAt = time.Now()
	}

	model, _ := unix.Sysctl("hw.model")
	osVersion, _ := unix.Sysctl("kern.osproductversion")
	osBuild, _ := unix.Sysctl("kern.osversion")
	arch, _ := unix.Sysctl("hw.machine")
	cpu, _ := unix.Sysctl("machdep.cpu.brand_string")
	memBytes, _ := unix.SysctlUint64("hw.memsize")

	snap := &desktopSnapshot{
		Manufacturer:    "Apple",
		ModelName:       firstNonEmpty(p.hw.MachineName, "Mac"),
		ModelNumber:     firstNonEmpty(p.hw.ModelNumber, p.hw.MachineModel, model),
		HardwareVersion: firstNonEmpty(p.hw.MachineModel, model),
		SoftwareVersion: osVersion,
		SerialNumber:    p.hw.Serial,
		ComputerName:    p.computer,
		ProcessorModel:  firstNonEmpty(p.hw.Chip, cpu, p.hw.CPU),
		Architecture:    arch,
		MemTotalKiB:     memBytes / 1024,
		Time:            p.ntp,
		NTPServers:      p.servers,
		Interfaces:      make(map[string]desktopInterface),
	}
	if osVersion != "" {
		snap.Description = "macOS " + osVersion
		if osBuild != "" {
			snap.Description += " (" + osBuild + ")"
		}
	}
	if host, err := os.Hostname(); err == nil {
		snap.Hostname = strings.TrimSuffix(host, ".local")
	}
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil && tv.Sec > 0 {
		snap.UptimeSeconds = int64(time.Since(time.Unix(tv.Sec, int64(tv.Usec)*1000)).Seconds())
	}
	if pageSize, freePages := parseVMStat(p.output(ctx, 3*time.Second, "vm_stat")); pageSize > 0 {
		snap.MemFreeKiB = pageSize * freePages / 1024
	}
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		snap.TimeZone = zoneFromLocaltime(target)
	}

	counters := parseNetstatIBN(p.output(ctx, 5*time.Second, "netstat", "-ibn"))
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		info := desktopInterface{
			Wireless: p.ports[iface.Name] == "Wi-Fi",
			Tunnel:   strings.HasPrefix(iface.Name, "utun") || strings.HasPrefix(iface.Name, "ipsec") || strings.HasPrefix(iface.Name, "gif") || strings.HasPrefix(iface.Name, "stf"),
		}
		if c, ok := counters[iface.Name]; ok {
			info.Stats, info.StatsKnown = c, true
		}
		snap.Interfaces[iface.Name] = info
	}
	snap.WiFi = p.wifi(ctx, ifaces)
	return snap
}

// wifi reads the Wi-Fi adapters. wdutil describes the primary one; any other
// (a USB adapter) gets its power state only.
func (p *macProbe) wifi(ctx context.Context, ifaces []net.Interface) []desktopWiFi {
	var devices []string
	for dev, port := range p.ports {
		if port == "Wi-Fi" {
			devices = append(devices, dev)
		}
	}
	if len(devices) == 0 {
		return nil
	}
	sort.Strings(devices)
	primary := parseWdutilWiFi(p.output(ctx, 10*time.Second, "wdutil", "info"))
	byName := make(map[string]net.Interface, len(ifaces))
	for _, iface := range ifaces {
		byName[iface.Name] = iface
	}
	out := make([]desktopWiFi, 0, len(devices))
	for _, dev := range devices {
		w := desktopWiFi{Interface: dev}
		if primary.Interface == dev {
			w = primary
		} else {
			w.PowerOn = strings.HasSuffix(p.output(ctx, 3*time.Second, "networksetup", "-getairportpower", dev), ": On")
		}
		if iface, ok := byName[dev]; ok && len(iface.HardwareAddr) == 6 {
			w.MAC = iface.HardwareAddr
		}
		out = append(out, w)
	}
	return out
}

func (p *macProbe) invalidate() {
	p.mu.Lock()
	p.slowAt = time.Time{}
	p.mu.Unlock()
}

// setHostname sets the three macOS names: ComputerName keeps what the user
// typed, LocalHostName (Bonjour) and HostName take its hostname form.
func (p *macProbe) setHostname(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	label := desktopHostnameLabel(name)
	if err := validDesktopHostname(label); err != nil {
		return err
	}
	defer p.invalidate()
	for _, args := range [][]string{
		{"--set", "ComputerName", name},
		{"--set", "LocalHostName", label},
		{"--set", "HostName", label},
	} {
		if _, err := p.run(ctx, "scutil", args...); err != nil {
			return err
		}
	}
	return nil
}

func (p *macProbe) setTimeZone(ctx context.Context, zone string) error {
	zone = strings.TrimSpace(zone)
	if zone == "" || strings.Contains(zone, "..") || strings.HasPrefix(zone, "/") || !fileExists(filepath.Join("/usr/share/zoneinfo", zone)) {
		return errors.New("unknown time zone " + strconv.Quote(zone) + "; use an IANA name such as Europe/Paris")
	}
	_, err := p.run(ctx, "systemsetup", "-settimezone", zone)
	return err
}

func (p *macProbe) setTimeEnabled(ctx context.Context, on bool) error {
	defer p.invalidate()
	value := "off"
	if on {
		value = "on"
	}
	_, err := p.run(ctx, "systemsetup", "-setusingnetworktime", value)
	return err
}

// setNTPServers points timed at servers. systemsetup takes one server and
// rewrites /etc/ntp.conf, so the full list is written after it.
func (p *macProbe) setNTPServers(ctx context.Context, servers []string) error {
	servers, err := normalizeNTPServers(servers)
	if err != nil {
		return err
	}
	if len(servers) == 0 {
		servers = []string{"time.apple.com"}
	}
	defer p.invalidate()
	if _, err := p.run(ctx, "systemsetup", "-setnetworktimeserver", servers[0]); err != nil {
		return err
	}
	if len(servers) > 1 {
		var body strings.Builder
		for _, server := range servers {
			body.WriteString("server " + server + "\n")
		}
		if _, err := writeFileIfChanged("/etc/ntp.conf", body.String()); err != nil {
			return err
		}
	}
	return nil
}

func (p *macProbe) setWiFiRadio(ctx context.Context, ifname string, on bool) error {
	value := "on"
	if !on {
		if err := ensureNotLastUplink(ifname); err != nil {
			return err
		}
		value = "off"
	}
	_, err := p.run(ctx, "networksetup", "-setairportpower", ifname, value)
	return err
}
