package platforms

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"wantastic-agent/internal/wusp"
)

// desktopProbe is the native macOS / Windows collector: it reads the system
// through its own APIs and tools instead of the Linux files and the one
// PowerShell process per value the generic host backend falls back to, and
// applies console changes the way each OS expects.
type desktopProbe interface {
	collect(ctx context.Context) *desktopSnapshot
	setHostname(ctx context.Context, name string) error
	setTimeZone(ctx context.Context, zone string) error
	setTimeEnabled(ctx context.Context, on bool) error
	setNTPServers(ctx context.Context, servers []string) error
	setWiFiRadio(ctx context.Context, ifname string, on bool) error
}

// desktopSnapshot is one reading of a desktop. Zero values mean unknown and
// are left out of the data model.
type desktopSnapshot struct {
	Manufacturer    string
	ModelName       string
	ModelNumber     string
	HardwareVersion string
	SoftwareVersion string
	Description     string // e.g. "macOS 27.0.1 (26A434)", "Windows 11 Pro 23H2 (22631.4317)"
	SerialNumber    string
	Hostname        string
	ComputerName    string // the user-facing name, the FriendlyName default

	ProcessorModel string
	Architecture   string

	MemTotalKiB   uint64
	MemFreeKiB    uint64
	UptimeSeconds int64

	TimeZone   string
	Time       timeState
	NTPServers []string

	// Interfaces is keyed by the net.Interfaces() name.
	Interfaces map[string]desktopInterface
	WiFi       []desktopWiFi
}

type desktopInterface struct {
	Wireless   bool
	Tunnel     bool
	SpeedMbps  uint64
	Stats      desktopCounters
	StatsKnown bool
}

type desktopCounters struct {
	BytesReceived, BytesSent       uint64
	PacketsReceived, PacketsSent   uint64
	ErrorsReceived, ErrorsSent     uint64
	DiscardsReceived, DiscardsSent uint64
}

// desktopWiFi is a Wi-Fi adapter in station mode.
type desktopWiFi struct {
	Interface  string
	MAC        net.HardwareAddr
	PowerOn    bool
	Connected  bool
	SSID       string
	BSSID      net.HardwareAddr
	RSSI       int
	RSSIKnown  bool
	Noise      int
	NoiseKnown bool
	Channel    int
	Band       string // TR-181: 2.4GHz, 5GHz, 6GHz
	WidthMHz   int
	Standard   string // TR-181 OperatingStandards: a, b, g, n, ac, ax, be
	TxRateKbps uint64
	RxRateKbps uint64
	Security   string // TR-181 ModeEnabled, e.g. WPA2-Personal
}

// desktopKind reports whether kind is the desktop OS this binary runs on, so
// tests building a macOS backend on Linux keep the generic path.
func desktopKind(kind Kind) bool {
	return (kind == KindMacOS && runtime.GOOS == "darwin") || (kind == KindWindows && runtime.GOOS == "windows")
}

// collectDesktop is collectAll for a native desktop probe.
func (b *hostBackend) collectDesktop(ctx context.Context, snap *desktopSnapshot) *wusp.Message {
	state, stateErr := b.readState()
	logCollectorError("host.state", stateErr)
	now := b.now()

	msg := wusp.NewMessage()
	msg.Set("Device.RootDataModelVersion", wusp.String(wusp.BroadbandRootDataModelVersion))
	set := func(path, value string) {
		if value = strings.TrimSpace(value); value != "" {
			msg.Set(path, wusp.String(value))
		}
	}
	set("Device.DeviceInfo.Manufacturer", snap.Manufacturer)
	if oui := b.readManufacturerOUI(); len(oui) == 6 {
		msg.Set("Device.DeviceInfo.ManufacturerOUI", wusp.String(oui))
	}
	set("Device.DeviceInfo.ModelName", snap.ModelName)
	set("Device.DeviceInfo.ModelNumber", firstNonEmpty(snap.ModelNumber, snap.ModelName, snap.HardwareVersion))
	set("Device.DeviceInfo.Description", firstNonEmpty(snap.Description, strings.Join(nonEmptyStrings(b.productClass(), snap.SoftwareVersion), " / ")))
	set("Device.DeviceInfo.ProductClass", b.productClass())
	set("Device.DeviceInfo.SerialNumber", snap.SerialNumber)
	set("Device.DeviceInfo.HardwareVersion", snap.HardwareVersion)
	set("Device.DeviceInfo.SoftwareVersion", snap.SoftwareVersion)
	set("Device.DeviceInfo.ProvisioningCode", state.ProvisioningCode)
	if snap.UptimeSeconds > 0 {
		msg.Set("Device.DeviceInfo.UpTime", wusp.Uint(uint64(snap.UptimeSeconds)))
	}
	set("Device.DeviceInfo.HostName", snap.Hostname)
	set("Device.DeviceInfo.FriendlyName", firstNonEmpty(state.FriendlyName, snap.ComputerName, snap.Hostname))
	if snap.MemTotalKiB > 0 {
		msg.Set("Device.DeviceInfo.MemoryStatus.Total", wusp.Uint(snap.MemTotalKiB))
	}
	if snap.MemFreeKiB > 0 {
		msg.Set("Device.DeviceInfo.MemoryStatus.Free", wusp.Uint(snap.MemFreeKiB))
	}
	msg.Set("Device.DeviceInfo.NetworkProperties.TCPImplementation", wusp.List(wusp.String(b.readTCPImplementation(ctx))))
	if snap.Architecture != "" || snap.ProcessorModel != "" {
		msg.Set("Device.DeviceInfo.ProcessorNumberOfEntries", wusp.Uint(1))
		set("Device.DeviceInfo.Processor.1.Architecture", tr181Architecture(snap.Architecture))
		set("Device.DeviceInfo.Processor.1.Alias", desktopProcessorAlias(snap.ProcessorModel))
	}

	if snap.Time.Known {
		msg.Set("Device.Time.Enable", wusp.Bool(snap.Time.Enabled))
		msg.Set("Device.Time.Status", wusp.String(ntpClientStatus(snap.Time.Enabled)))
	}
	msg.Set("Device.Time.CurrentLocalTime", wusp.Time(now))
	set("Device.Time.LocalTimeZone", firstNonEmpty(snap.TimeZone, now.Location().String()))
	if snap.Time.Known || len(snap.NTPServers) > 0 {
		appendNTPClientFields(msg, snap.Time.Enabled, snap.NTPServers)
	}

	msg.Set("Device.IP.IPv4Capable", wusp.Bool(true))
	msg.Set("Device.IP.IPv4Enable", wusp.Bool(true))
	msg.Set("Device.IP.IPv4Status", wusp.String("Enabled"))
	msg.Set("Device.IP.IPv6Capable", wusp.Bool(true))
	msg.Set("Device.IP.IPv6Enable", wusp.Bool(true))
	msg.Set("Device.IP.IPv6Status", wusp.String("Enabled"))

	_ = runCollector("desktop.interfaces", func() error {
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		appendDesktopInterfaceFields(msg, ifaces, snap)
		return nil
	})
	if hostKindSupportsDNSControl(b.kind) {
		_ = runCollector("dns.control", func() error {
			b.reapplyPersistedDNS(ctx)
			appendDNSControlFields(msg, cachedDNSControl(ctx))
			return nil
		})
	}
	_ = runCollector("firewall", func() error { collectHostFirewallStatic(ctx, b.commandRunner, msg); return nil })
	return msg
}

// lastDesktopSnapshot is the reading the console last saw, so a Set resolves
// indexes the way they were reported and does not re-collect inside its
// request deadline.
func (b *hostBackend) lastDesktopSnapshot(ctx context.Context) *desktopSnapshot {
	if snap := b.desktopLast.Load(); snap != nil {
		return snap
	}
	return b.desktop.collect(ctx)
}

// desktopCommandRunner is defaultCommandRunner for the desktop probes, with
// a WaitDelay: system_profiler and friends start helpers that can keep the
// output pipe open after the timeout, which would otherwise block forever
// while the probe holds its lock.
func desktopCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 2 * time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

// setDesktop applies the settings a desktop probe owns; handled is false for
// paths the generic host backend applies (DNS, firewall, IP interfaces).
func (b *hostBackend) setDesktop(ctx context.Context, path string, value wusp.Value) (handled bool, err error) {
	switch path {
	case "Device.DeviceInfo.HostName":
		return true, b.desktop.setHostname(ctx, value.AsString())
	case "Device.Time.Enable", "Device.Time.Client.1.Enable":
		return true, b.desktop.setTimeEnabled(ctx, value.AsBool())
	case "Device.Time.LocalTimeZone":
		return true, b.desktop.setTimeZone(ctx, value.AsString())
	case "Device.Time.Client.1.Servers":
		return true, b.desktop.setNTPServers(ctx, valueStringList(value))
	}
	if index, ok := ntpServerIndex(path); ok {
		var current []string
		if snap := b.lastDesktopSnapshot(ctx); snap != nil {
			current = snap.NTPServers
		}
		return true, b.desktop.setNTPServers(ctx, replaceNTPServerAt(current, index, wusp.ValueToString(value)))
	}
	for _, table := range []string{"Device.WiFi.Radio.", "Device.WiFi.SSID.", "Device.WiFi.EndPoint."} {
		index, leaf, ok := parseIndexedPath(path, table)
		if !ok || leaf != "Enable" {
			continue
		}
		snap := b.lastDesktopSnapshot(ctx)
		if snap == nil || index == 0 || index > uint64(len(snap.WiFi)) {
			return true, wusp.ErrUSPPathNotFound
		}
		return true, b.desktop.setWiFiRadio(ctx, snap.WiFi[index-1].Interface, value.AsBool())
	}
	return false, nil
}

// tr181Architecture maps uname -m / OS names onto the Processor
// Architecture enum, which has no 64-bit ARM value; unknown values are
// dropped rather than failing validation.
func tr181Architecture(arch string) string {
	switch a := strings.ToLower(strings.TrimSpace(arch)); {
	case a == "x86_64" || a == "amd64":
		return "x86_64"
	case a == "i386" || a == "i486" || a == "i586" || a == "i686" || a == "x86":
		return "i386"
	case a == "arm64" || a == "aarch64" || strings.HasPrefix(a, "armv") || a == "arm":
		return "arm"
	case a == "mips" || a == "mips64":
		// uname -m says "mips" for both byte orders; this binary knows.
		if strings.HasSuffix(runtime.GOARCH, "le") {
			return "mipsel"
		}
		return "mipseb"
	case a == "mipseb":
		return "mipseb"
	case a == "mipsel" || a == "mipsle":
		return "mipsel"
	case a == "ppc" || a == "ppc64" || a == "ppc64le" || a == "powerpc":
		return "powerpc"
	}
	return ""
}

// desktopProcessorAlias fits the CPU name into a TR-181 Alias (64 chars).
func desktopProcessorAlias(model string) string {
	model = strings.Join(strings.Fields(model), " ")
	for len(model) > 64 {
		_, size := utf8.DecodeLastRuneInString(model)
		model = model[:len(model)-size]
	}
	return strings.TrimSpace(model)
}

// ipInterfaceOrder is the Device.IP.Interface.{i} order, shared by the
// collectors and setIPInterfaceParam so an index always names the same NIC.
func ipInterfaceOrder(ifaces []net.Interface) []net.Interface {
	out := make([]net.Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 && !isCellularNetdev(iface.Name) {
			continue
		}
		out = append(out, iface)
	}
	return out
}

// appendDesktopInterfaceFields reports IP interfaces with their counters and
// links each to its Wi-Fi SSID or Ethernet interface (LowerLayers), the
// TR-181 way of saying which NIC is wireless.
func appendDesktopInterfaceFields(msg *wusp.Message, ifaces []net.Interface, snap *desktopSnapshot) {
	ssidIndex := make(map[string]int, len(snap.WiFi))
	for i, wifi := range snap.WiFi {
		ssidIndex[wifi.Interface] = i + 1
	}
	ipIfaces := ipInterfaceOrder(ifaces)
	ethernetCount := 0
	for i, iface := range ipIfaces {
		info := snap.Interfaces[iface.Name]
		prefix := fmt.Sprintf("Device.IP.Interface.%d.", i+1)
		msg.Set(prefix+"Name", wusp.String(iface.Name))
		msg.Set(prefix+"Enable", wusp.Bool(iface.Flags&net.FlagUp != 0))
		msg.Set(prefix+"Status", wusp.String(ifaceStatus(iface.Flags)))
		kind := ifaceType(iface.Name)
		if info.Tunnel {
			kind = "Tunnel"
		}
		msg.Set(prefix+"Type", wusp.String(kind))
		msg.Set(prefix+"MaxMTUSize", wusp.Uint(uint64(iface.MTU)))
		if info.StatsKnown {
			appendDesktopCounters(msg, prefix+"Stats.", info.Stats)
		}

		switch {
		case ssidIndex[iface.Name] > 0:
			msg.Set(prefix+"LowerLayers", wusp.List(wusp.String(fmt.Sprintf("Device.WiFi.SSID.%d.", ssidIndex[iface.Name]))))
		case kind == "Normal" && !info.Wireless:
			ethernetCount++
			eth := fmt.Sprintf("Device.Ethernet.Interface.%d.", ethernetCount)
			msg.Set(prefix+"LowerLayers", wusp.List(wusp.String(eth)))
			msg.Set(eth+"Enable", wusp.Bool(iface.Flags&net.FlagUp != 0))
			msg.Set(eth+"Status", wusp.String(ifaceStatus(iface.Flags)))
			msg.Set(eth+"Name", wusp.String(iface.Name))
			if len(iface.HardwareAddr) == 6 {
				msg.Set(eth+"MACAddress", wusp.MAC(iface.HardwareAddr))
			}
			if info.SpeedMbps > 0 {
				msg.Set(eth+"CurrentBitRate", wusp.Uint(info.SpeedMbps))
			}
			if info.StatsKnown {
				appendDesktopCounters(msg, eth+"Stats.", info.Stats)
			}
		}

		if addrs, err := iface.Addrs(); err == nil {
			v4, v6 := 0, 0
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				if ip4 := ipNet.IP.To4(); ip4 != nil {
					v4++
					p := fmt.Sprintf("%sIPv4Address.%d.", prefix, v4)
					msg.Set(p+"IPAddress", wusp.IP4(ip4))
					msg.Set(p+"SubnetMask", wusp.IP4(net.IP(ipNet.Mask).To4()))
					msg.Set(p+"AddressingType", wusp.String("DHCP"))
				} else if ip6 := ipNet.IP.To16(); ip6 != nil {
					v6++
					p := fmt.Sprintf("%sIPv6Address.%d.", prefix, v6)
					msg.Set(p+"IPAddress", wusp.IP6(ip6))
					ones, _ := ipNet.Mask.Size()
					msg.Set(p+"Prefix", wusp.String(fmt.Sprintf("%s/%d", ipNet.IP.Mask(ipNet.Mask).String(), ones)))
				}
			}
		}
	}
	msg.Set("Device.IP.InterfaceNumberOfEntries", wusp.Uint(uint64(len(ipIfaces))))
	msg.Set("Device.Ethernet.InterfaceNumberOfEntries", wusp.Uint(uint64(ethernetCount)))
	appendDesktopWiFiFields(msg, snap.WiFi)
}

func appendDesktopCounters(msg *wusp.Message, prefix string, c desktopCounters) {
	msg.Set(prefix+"BytesReceived", wusp.Uint(c.BytesReceived))
	msg.Set(prefix+"BytesSent", wusp.Uint(c.BytesSent))
	msg.Set(prefix+"PacketsReceived", wusp.Uint(c.PacketsReceived))
	msg.Set(prefix+"PacketsSent", wusp.Uint(c.PacketsSent))
	msg.Set(prefix+"ErrorsReceived", wusp.Uint(c.ErrorsReceived))
	msg.Set(prefix+"ErrorsSent", wusp.Uint(c.ErrorsSent))
	msg.Set(prefix+"DiscardPacketsReceived", wusp.Uint(c.DiscardsReceived))
	msg.Set(prefix+"DiscardPacketsSent", wusp.Uint(c.DiscardsSent))
}

// appendDesktopWiFiFields reports each adapter as a Radio, its SSID and a
// station EndPoint with the link quality.
func appendDesktopWiFiFields(msg *wusp.Message, adapters []desktopWiFi) {
	for i, w := range adapters {
		radio := fmt.Sprintf("Device.WiFi.Radio.%d.", i+1)
		ssid := fmt.Sprintf("Device.WiFi.SSID.%d.", i+1)
		ep := fmt.Sprintf("Device.WiFi.EndPoint.%d.", i+1)

		msg.Set(radio+"Enable", wusp.Bool(w.PowerOn))
		msg.Set(radio+"Status", wusp.String(wifiStatusValue(w.PowerOn, w.PowerOn)))
		msg.Set(radio+"Name", wusp.String(w.Interface))
		if w.Band != "" {
			msg.Set(radio+"OperatingFrequencyBand", wusp.String(w.Band))
		}
		if w.Channel > 0 {
			msg.Set(radio+"Channel", wusp.Uint(uint64(w.Channel)))
		}
		if w.WidthMHz > 0 {
			msg.Set(radio+"CurrentOperatingChannelBandwidth", wusp.String(strconv.Itoa(w.WidthMHz)+"MHz"))
		}
		if w.Standard != "" {
			msg.Set(radio+"OperatingStandards", wusp.List(wusp.String(w.Standard)))
		}
		if w.NoiseKnown {
			msg.Set(radio+"Stats.Noise", wusp.Int(int64(w.Noise)))
		}

		msg.Set(ssid+"Enable", wusp.Bool(w.PowerOn))
		msg.Set(ssid+"Status", wusp.String(wifiStatusValue(w.PowerOn, w.Connected)))
		msg.Set(ssid+"Name", wusp.String(w.Interface))
		msg.Set(ssid+"LowerLayers", wusp.List(wusp.String(radio)))
		if len(w.MAC) == 6 {
			msg.Set(ssid+"MACAddress", wusp.MAC(w.MAC))
		}
		if w.Connected && w.SSID != "" {
			msg.Set(ssid+"SSID", wusp.String(w.SSID))
		}
		if w.Connected && len(w.BSSID) == 6 {
			msg.Set(ssid+"BSSID", wusp.MAC(w.BSSID))
		}

		msg.Set(ep+"Enable", wusp.Bool(w.PowerOn))
		msg.Set(ep+"Status", wusp.String(desktopEndPointStatus(w)))
		msg.Set(ep+"SSIDReference", wusp.String(ssid))
		if w.Connected {
			if w.RSSIKnown {
				msg.Set(ep+"Stats.SignalStrength", wusp.Int(int64(w.RSSI)))
			}
			if w.RxRateKbps > 0 {
				msg.Set(ep+"Stats.LastDataDownlinkRate", wusp.Uint(endPointRateKbps(w.RxRateKbps)))
			}
			if w.TxRateKbps > 0 {
				msg.Set(ep+"Stats.LastDataUplinkRate", wusp.Uint(endPointRateKbps(w.TxRateKbps)))
			}
			msg.Set(ep+"ProfileNumberOfEntries", wusp.Uint(1))
			msg.Set(ep+"ProfileReference", wusp.String(ep+"Profile.1."))
			msg.Set(ep+"Profile.1.Enable", wusp.Bool(true))
			msg.Set(ep+"Profile.1.Status", wusp.String("Active"))
			if w.SSID != "" {
				msg.Set(ep+"Profile.1.SSID", wusp.String(w.SSID))
			}
			if w.Security != "" {
				msg.Set(ep+"Profile.1.Security.ModeEnabled", wusp.String(w.Security))
			}
		} else {
			msg.Set(ep+"ProfileNumberOfEntries", wusp.Uint(0))
		}
	}
	msg.Set("Device.WiFi.RadioNumberOfEntries", wusp.Uint(uint64(len(adapters))))
	msg.Set("Device.WiFi.SSIDNumberOfEntries", wusp.Uint(uint64(len(adapters))))
	msg.Set("Device.WiFi.EndPointNumberOfEntries", wusp.Uint(uint64(len(adapters))))
	msg.Set("Device.WiFi.AccessPointNumberOfEntries", wusp.Uint(0))
}

// endPointRateKbps fits a link rate into the EndPoint.Stats range
// (1 to 600 Mbit/s); Wi-Fi 6 and 7 links run faster than the schema allows.
func endPointRateKbps(kbps uint64) uint64 {
	return min(max(kbps, 1000), 600000)
}

func desktopEndPointStatus(w desktopWiFi) string {
	if !w.PowerOn {
		return "Disabled"
	}
	return "Enabled"
}

// errLastUplink refuses a remote change that would leave the device with no
// connected network, and so cut the console's only way back to it.
var errLastUplink = errors.New("refusing to turn off the only connected network: the device would go offline and could not be reached to turn it back on")

// isLastUplink reports whether name is the only interface still carrying an
// IPv4 address other than link-local, loopback and tunnels.
func isLastUplink(name string, ifaces []net.Interface, addrs func(net.Interface) ([]net.Addr, error)) bool {
	connected := func(iface net.Interface) bool {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 || virtualAdapter(iface.Name) {
			return false
		}
		list, err := addrs(iface)
		if err != nil {
			return false
		}
		for _, addr := range list {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipNet.IP.To4(); ip4 != nil && !ip4.IsLinkLocalUnicast() && !ip4.IsLoopback() {
					return true
				}
			}
		}
		return false
	}
	target := false
	for _, iface := range ifaces {
		if !connected(iface) {
			continue
		}
		if iface.Name == name {
			target = true
			continue
		}
		return false
	}
	return target
}

// virtualAdapter names host-only and VM networks (Hyper-V/WSL vEthernet,
// macOS bridge100 for Internet Sharing and VMs, VMware, VirtualBox, Docker):
// they carry an address but no way out, so they are not an uplink.
func virtualAdapter(name string) bool {
	n := strings.ToLower(name)
	for _, prefix := range []string{"vethernet", "bridge", "vmnet", "vboxnet", "docker", "veth", "virbr", "awdl", "llw", "anpi", "ap1"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return strings.Contains(n, "virtualbox") || strings.Contains(n, "vmware") || strings.Contains(n, "hyper-v")
}

func ensureNotLastUplink(name string) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	if isLastUplink(name, ifaces, func(i net.Interface) ([]net.Addr, error) { return i.Addrs() }) {
		return errLastUplink
	}
	return nil
}

// validDesktopHostname accepts one DNS label, the form macOS LocalHostName
// and Windows computer names require.
func validDesktopHostname(name string) error {
	if len(name) == 0 || len(name) > 63 {
		return &wusp.ValidationError{Path: "Device.DeviceInfo.HostName", Reason: "a hostname is 1 to 63 characters"}
	}
	digits := true
	for i, r := range name {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			digits = false
		case r == '-' && i > 0 && i < len(name)-1:
			digits = false
		default:
			return &wusp.ValidationError{Path: "Device.DeviceInfo.HostName", Reason: "use letters, digits and inner hyphens only"}
		}
	}
	if digits {
		return &wusp.ValidationError{Path: "Device.DeviceInfo.HostName", Reason: "a hostname cannot be only digits"}
	}
	return nil
}

// desktopHostnameLabel turns a free-form name ("Karim's MacBook Pro") into a
// hostname label ("Karims-MacBook-Pro").
func desktopHostnameLabel(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.TrimSpace(name) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			b.WriteRune(r)
			dash = false
		case r == '\'' || r == '’':
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	label := strings.Trim(b.String(), "-")
	if len(label) > 63 {
		label = strings.TrimRight(label[:63], "-")
	}
	return label
}

// --- macOS parsers ---------------------------------------------------------

// parseWdutilWiFi reads the WIFI section of `wdutil info`. Recent macOS
// redacts SSID, BSSID and MAC addresses even for root.
func parseWdutilWiFi(out string) desktopWiFi {
	var w desktopWiFi
	inWiFi := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "—") || strings.HasPrefix(line, "-") {
			continue
		}
		if !strings.Contains(line, ":") {
			inWiFi = line == "WIFI"
			continue
		}
		if !inWiFi {
			continue
		}
		key, value, _ := strings.Cut(line, ":")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if redacted(value) {
			continue
		}
		switch key {
		case "Interface Name":
			w.Interface = value
		case "MAC Address":
			w.MAC, _ = net.ParseMAC(strings.Fields(value)[0])
		case "Power":
			w.PowerOn = strings.HasPrefix(value, "On")
		case "SSID":
			w.SSID = value
		case "BSSID":
			w.BSSID, _ = net.ParseMAC(value)
		case "RSSI":
			w.RSSI, w.RSSIKnown = parseDBM(value)
		case "Noise":
			w.Noise, w.NoiseKnown = parseDBM(value)
		case "Tx Rate":
			w.TxRateKbps = parseMbpsToKbps(value)
		case "Security":
			w.Security = macSecurityMode(value)
		case "PHY Mode":
			w.Standard = wifiStandardFromPHY(value)
		case "Channel":
			w.Channel, w.Band, w.WidthMHz = parseMacChannel(value)
		}
	}
	// An associated station always has a channel; "None" security is still
	// a connection.
	w.Connected = w.PowerOn && w.Channel > 0
	return w
}

func redacted(value string) bool {
	return value == "" || strings.Contains(value, "<redacted>")
}

func parseDBM(value string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "dBm")))
	if err != nil || n < -120 || n > 0 {
		return 0, false
	}
	return n, true
}

func parseMbpsToKbps(value string) uint64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "Mbps")), 64)
	if err != nil || f <= 0 {
		return 0
	}
	return uint64(f * 1000)
}

// parseMacChannel reads "5g60/160", "2g6/20" or "6g37/320".
func parseMacChannel(value string) (channel int, band string, width int) {
	value = strings.TrimSpace(value)
	if len(value) < 3 || value[1] != 'g' {
		return 0, "", 0
	}
	switch value[0] {
	case '2':
		band = "2.4GHz"
	case '5':
		band = "5GHz"
	case '6':
		band = "6GHz"
	}
	chText, widthText, _ := strings.Cut(value[2:], "/")
	channel, _ = strconv.Atoi(chText)
	width, _ = strconv.Atoi(widthText)
	return channel, band, width
}

// wifiStandardFromPHY maps "11ax", "802.11ac" or Windows PHY types to TR-181.
func wifiStandardFromPHY(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(strings.TrimPrefix(value, "802."), "11")
	switch value {
	case "a", "b", "g", "n", "ac", "ax", "be":
		return value
	}
	return ""
}

func macSecurityMode(value string) string {
	v := strings.ToLower(value)
	enterprise := strings.Contains(v, "enterprise")
	mode := func(base string) string {
		if enterprise {
			return base + "-Enterprise"
		}
		return base + "-Personal"
	}
	switch {
	case strings.Contains(v, "wpa3") && strings.Contains(v, "wpa2"):
		return mode("WPA2-WPA3")
	case strings.Contains(v, "wpa3"):
		return mode("WPA3")
	case strings.Contains(v, "wpa2") && strings.Contains(v, "wpa/"):
		return mode("WPA-WPA2")
	case strings.Contains(v, "wpa2"):
		return mode("WPA2")
	case strings.Contains(v, "wpa"):
		return mode("WPA")
	case strings.Contains(v, "wep"):
		return "WEP-128"
	case strings.Contains(v, "none"), strings.Contains(v, "open"):
		return "None"
	}
	return ""
}

// parseNetstatIBN reads the <Link#N> rows of `netstat -ibn`, which carry the
// per-interface counters.
func parseNetstatIBN(out string) map[string]desktopCounters {
	counters := make(map[string]desktopCounters)
	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		return counters
	}
	header := strings.Fields(lines[0])
	col := make(map[string]int, len(header))
	for i, name := range header {
		col[name] = i
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasPrefix(fields[2], "<Link#") {
			continue
		}
		// Rows without a MAC have one column fewer than the header.
		shift := 0
		if len(fields) == len(header)-1 {
			shift = -1
		}
		get := func(name string) uint64 {
			i, ok := col[name]
			if !ok || i+shift < 0 || i+shift >= len(fields) {
				return 0
			}
			n, _ := strconv.ParseUint(fields[i+shift], 10, 64)
			return n
		}
		name := strings.TrimSuffix(fields[0], "*")
		counters[name] = desktopCounters{
			PacketsReceived: get("Ipkts"), ErrorsReceived: get("Ierrs"), BytesReceived: get("Ibytes"),
			PacketsSent: get("Opkts"), ErrorsSent: get("Oerrs"), BytesSent: get("Obytes"),
			DiscardsReceived: get("Idrop"), DiscardsSent: get("Odrop"),
		}
	}
	return counters
}

// parseHardwarePorts maps devices to their port names from
// `networksetup -listallhardwareports` ("en0" -> "Wi-Fi").
func parseHardwarePorts(out string) map[string]string {
	ports := make(map[string]string)
	port := ""
	for _, raw := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Hardware Port":
			port = strings.TrimSpace(value)
		case "Device":
			if dev := strings.TrimSpace(value); dev != "" && port != "" {
				ports[dev] = port
			}
		}
	}
	return ports
}

type macHardwareOverview struct {
	MachineName  string `json:"machine_name"`
	MachineModel string `json:"machine_model"`
	ModelNumber  string `json:"model_number"`
	Serial       string `json:"serial_number"`
	Chip         string `json:"chip_type"`
	CPU          string `json:"cpu_type"`
}

// parseSPHardware reads `system_profiler SPHardwareDataType -json`.
func parseSPHardware(out []byte) macHardwareOverview {
	var doc struct {
		Items []macHardwareOverview `json:"SPHardwareDataType"`
	}
	if json.Unmarshal(out, &doc) != nil || len(doc.Items) == 0 {
		return macHardwareOverview{}
	}
	return doc.Items[0]
}

// zoneFromLocaltime turns the /etc/localtime link target into an IANA name.
func zoneFromLocaltime(target string) string {
	if _, zone, ok := strings.Cut(target, "zoneinfo/"); ok {
		return zone
	}
	return ""
}

// --- Windows parsers -------------------------------------------------------

// parseW32TimeServers reads W32Time's NtpServer value: "a,0x9 b,0x8".
func parseW32TimeServers(value string) []string {
	var servers []string
	for _, entry := range strings.Fields(value) {
		host, _, _ := strings.Cut(entry, ",")
		if host = strings.TrimSpace(host); host != "" {
			servers = append(servers, host)
		}
	}
	return servers
}

// windowsProductName corrects ProductName, which still reads "Windows 10" on
// Windows 11 (build 22000 and later).
func windowsProductName(name string, build int) string {
	if build >= 22000 {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	return name
}

// smbiosPlaceholder filters the fill-in values OEMs leave in SMBIOS.
func smbiosPlaceholder(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "none", "default string", "to be filled by o.e.m.", "system serial number",
		"system product name", "system manufacturer", "not applicable", "not specified", "123456789", "chassis serial number":
		return true
	}
	return false
}

// parseSMBIOSSerial returns the system (type 1) or baseboard (type 2) serial
// number from a raw SMBIOS table (GetSystemFirmwareTable 'RSMB' data after
// its 8-byte header).
func parseSMBIOSSerial(table []byte) string {
	var board string
	for len(table) >= 4 {
		kind, length := table[0], int(table[1])
		if length < 4 || length > len(table) {
			return board
		}
		formatted := table[:length]
		rest := table[length:]
		end := 0
		for end+1 < len(rest) && !(rest[end] == 0 && rest[end+1] == 0) {
			end++
		}
		var strs []string
		if end > 0 {
			strs = strings.Split(string(rest[:end]), "\x00")
		}
		str := func(offset int) string {
			if offset >= len(formatted) {
				return ""
			}
			i := int(formatted[offset])
			if i == 0 || i > len(strs) {
				return ""
			}
			return strings.TrimSpace(strs[i-1])
		}
		switch kind {
		case 1:
			if serial := str(0x07); !smbiosPlaceholder(serial) {
				return serial
			}
		case 2:
			if serial := str(0x07); !smbiosPlaceholder(serial) && board == "" {
				board = serial
			}
		case 127:
			return board
		}
		if end+2 > len(rest) {
			return board
		}
		table = rest[end+2:]
	}
	return board
}

// rawSMBIOSTable strips the RawSMBIOSData header.
func rawSMBIOSTable(data []byte) []byte {
	if len(data) < 8 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(data[4:8]))
	if n > len(data)-8 {
		n = len(data) - 8
	}
	return data[8 : 8+n]
}

// windowsWiFiStandard maps DOT11_PHY_TYPE to TR-181.
func windowsWiFiStandard(phy uint32) string {
	switch phy {
	case 4:
		return "a"
	case 5:
		return "b"
	case 6:
		return "g"
	case 7:
		return "n"
	case 8:
		return "ac"
	case 10:
		return "ax"
	case 11:
		return "be"
	}
	return ""
}

// windowsWiFiBand derives the band from channel and PHY: 6 GHz channels
// reuse 5 GHz numbers, so only Wi-Fi 6E/7 PHYs above channel 14 can be
// 6 GHz and those are reported from the frequency when it is known.
func windowsWiFiBand(channel int, freqKHz uint32) string {
	if freqKHz > 0 {
		return wifiBandTR181FromFrequency(int(freqKHz / 1000))
	}
	switch {
	case channel >= 1 && channel <= 14:
		return "2.4GHz"
	case channel > 14:
		return "5GHz"
	}
	return ""
}

// windowsSecurityMode maps DOT11_AUTH_ALGORITHM to TR-181 ModeEnabled.
func windowsSecurityMode(auth uint32, encrypted bool) string {
	switch auth {
	case 1: // 802.11 open
		if encrypted {
			return "WEP-128"
		}
		return "None"
	case 2: // shared key
		return "WEP-128"
	case 3:
		return "WPA-Enterprise"
	case 4:
		return "WPA-Personal"
	case 6: // RSNA
		return "WPA2-Enterprise"
	case 7: // RSNA-PSK
		return "WPA2-Personal"
	case 8, 11: // WPA3 enterprise (192-bit / standard)
		return "WPA3-Enterprise"
	case 9: // SAE
		return "WPA3-Personal"
	case 10: // OWE
		return "None"
	}
	return ""
}
