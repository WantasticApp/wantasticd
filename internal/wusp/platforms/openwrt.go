package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/netctl"
	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/platforms/ubus"
)

type OpenWrtBackendOptions struct {
	UCIConfigDir          string
	StatePath             string
	HostnamePath          string
	EtcHostnamePath       string
	TZPath                string
	ZoneInfoDir           string
	UptimePath            string
	MemInfoPath           string
	IPv6DisablePath       string
	TCPImplementationPath string
	OpenWrtReleasePath    string
	OSReleasePath         string
	SerialNumberPath      string
	NetClassDir           string
	UbusURL               string
	UbusSessionID         string
	UbusTimeout           time.Duration
	UbusCaller            func(string, string, time.Duration) ([]byte, error)
	UbusClient            *ubus.Client
	CommandRunner         func(context.Context, string, ...string) ([]byte, error)
	Now                   func() time.Time
}

type OpenWrtBackend struct {
	uciConfigDir          string
	statePath             string
	hostnamePath          string
	etcHostnamePath       string
	tzPath                string
	zoneInfoDir           string
	uptimePath            string
	memInfoPath           string
	ipv6DisablePath       string
	tcpImplementationPath string
	openWrtReleasePath    string
	osReleasePath         string
	serialNumberPath      string
	netClassDir           string
	ubusClient            *ubus.Client
	ubusTimeout           time.Duration
	ubusCaller            func(string, string, time.Duration) ([]byte, error)
	commandRunner         func(context.Context, string, ...string) ([]byte, error)
	now                   func() time.Time
}

type openWrtState struct {
	FriendlyName     string `json:"friendly_name,omitempty"`
	ProvisioningCode string `json:"provisioning_code,omitempty"`
}

type openWrtBoardInfo struct {
	Hostname  string `json:"hostname"`
	Model     string `json:"model"`
	BoardName string `json:"board_name"`
	System    string `json:"system"`
	Kernel    string `json:"kernel"`
	Release   struct {
		Distribution string `json:"distribution"`
		Version      string `json:"version"`
		Revision     string `json:"revision"`
		Target       string `json:"target"`
		Description  string `json:"description"`
	} `json:"release"`
}

type openWrtSystemInfo struct {
	LocalTime int64   `json:"localtime"`
	Uptime    float64 `json:"uptime"`
	Memory    struct {
		Total     uint64 `json:"total"`
		Free      uint64 `json:"free"`
		Available uint64 `json:"available"`
	} `json:"memory"`
}

type openWrtInterfaceDump struct {
	Interfaces []openWrtInterfaceStatus `json:"interface"`
}

type openWrtInterfaceStatus struct {
	Interface string `json:"interface"`
	Up        bool   `json:"up"`
}

type openWrtUCIConfig struct {
	Sections []openWrtUCISection
}

type openWrtUCISection struct {
	Type    string
	Name    string
	Options map[string]string
	Lists   map[string][]string
}

type openWrtSnapshot struct {
	state              openWrtState
	board              openWrtBoardInfo
	release            map[string]string
	hostname           string
	uptimeSeconds      int64
	memTotal           uint64
	memFree            uint64
	ipv6Enabled        bool
	tcpImplementation  string
	serialNumber       string
	currentLocalTime   time.Time
	localTimeZone      string
	timeEnabled        bool
	timeStatus         string
	timeClientCount    int
	timeServerCount    int
	ulaPrefix          string
	interfaceCount     int
	firewallEnabled    bool
	firewallLastChange time.Time
}

type openWrtWirelessRadioStatus struct {
	Up         bool                         `json:"up"`
	Disabled   bool                         `json:"disabled"`
	Interfaces []openWrtWirelessIfaceStatus `json:"interfaces"`
	Config     map[string]any               `json:"config"`
}

type openWrtWirelessIfaceStatus struct {
	Section string         `json:"section"`
	IfName  string         `json:"ifname"`
	Up      bool           `json:"up"`
	Config  map[string]any `json:"config"`
}

type openWrtWiFiStation struct {
	MAC   string `json:"mac"`
	RSSI  int    `json:"rssi"`
	Iface string `json:"iface"`
}

var _ wusp.DataBackend = (*OpenWrtBackend)(nil)

func NewOpenWrtBackend(opts OpenWrtBackendOptions) *OpenWrtBackend {
	backend := &OpenWrtBackend{
		uciConfigDir:          coalesceString(opts.UCIConfigDir, "/etc/config"),
		statePath:             coalesceString(opts.StatePath, defaultWantasticStatePath("usp-openwrt.json")),
		hostnamePath:          coalesceString(opts.HostnamePath, "/proc/sys/kernel/hostname"),
		etcHostnamePath:       coalesceString(opts.EtcHostnamePath, "/etc/hostname"),
		tzPath:                coalesceString(opts.TZPath, "/etc/TZ"),
		zoneInfoDir:           coalesceString(opts.ZoneInfoDir, "/usr/share/zoneinfo"),
		uptimePath:            coalesceString(opts.UptimePath, "/proc/uptime"),
		memInfoPath:           coalesceString(opts.MemInfoPath, "/proc/meminfo"),
		ipv6DisablePath:       coalesceString(opts.IPv6DisablePath, "/proc/sys/net/ipv6/conf/all/disable_ipv6"),
		tcpImplementationPath: coalesceString(opts.TCPImplementationPath, "/proc/sys/net/ipv4/tcp_congestion_control"),
		openWrtReleasePath:    coalesceString(opts.OpenWrtReleasePath, "/etc/openwrt_release"),
		osReleasePath:         coalesceString(opts.OSReleasePath, "/etc/os-release"),
		serialNumberPath:      coalesceString(opts.SerialNumberPath, "/proc/device-tree/serial-number"),
		netClassDir:           coalesceString(opts.NetClassDir, "/sys/class/net"),
		ubusClient:            opts.UbusClient,
		ubusTimeout:           opts.UbusTimeout,
		ubusCaller:            opts.UbusCaller,
		commandRunner:         opts.CommandRunner,
		now:                   opts.Now,
	}
	if backend.ubusTimeout <= 0 {
		backend.ubusTimeout = 3 * time.Second
	}
	if backend.ubusClient == nil {
		backend.ubusClient = ubus.NewClient(ubus.Options{
			URL:       opts.UbusURL,
			SessionID: opts.UbusSessionID,
		})
	}
	if backend.ubusCaller == nil {
		backend.ubusCaller = func(object, method string, timeout time.Duration) ([]byte, error) {
			return backend.ubusClient.Call(context.Background(), object, method, nil, timeout)
		}
	}
	if backend.commandRunner == nil {
		backend.commandRunner = defaultOpenWrtCommandRunner
	}
	if backend.now == nil {
		backend.now = time.Now
	}
	return backend
}

func newOpenWrtBackendFromOptions(opts Options) wusp.DataBackend {
	return NewOpenWrtBackend(OpenWrtBackendOptions{
		UCIConfigDir:          opts.UCIConfigDir,
		StatePath:             opts.StatePath,
		HostnamePath:          opts.HostnamePath,
		UptimePath:            opts.UptimePath,
		MemInfoPath:           opts.MemInfoPath,
		IPv6DisablePath:       opts.IPv6DisablePath,
		TCPImplementationPath: opts.TCPImplementationPath,
		OpenWrtReleasePath:    opts.OpenWrtReleasePath,
		OSReleasePath:         opts.OSReleasePath,
		SerialNumberPath:      opts.SerialNumberPath,
		NetClassDir:           opts.NetClassDir,
		UbusURL:               opts.UbusURL,
		UbusSessionID:         opts.UbusSessionID,
		UbusTimeout:           opts.UbusTimeout,
		UbusCaller:            opts.UbusCaller,
		UbusClient:            opts.UbusClient,
		CommandRunner:         opts.CommandRunner,
		Now:                   opts.Now,
	})
}

func (b *OpenWrtBackend) Collect(ctx context.Context, paths ...string) (*wusp.Message, error) {
	msg, err := b.collectAll(ctx)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return msg, nil
	}
	return subsetPlatformMessageByPaths(msg, paths...), nil
}

func (b *OpenWrtBackend) Set(ctx context.Context, path string, value wusp.Value) error {
	path = strings.TrimSpace(path)
	switch path {
	case "Device.DeviceInfo.HostName":
		return b.setHostname(ctx, value.AsString())
	case "Device.DeviceInfo.FriendlyName":
		return b.updateState(func(state *openWrtState) {
			state.FriendlyName = value.AsString()
		})
	case "Device.DeviceInfo.ProvisioningCode":
		return b.updateState(func(state *openWrtState) {
			state.ProvisioningCode = value.AsString()
		})
	case "Device.Time.Enable":
		return b.setTimeEnabled(ctx, value.AsBool())
	case "Device.Time.LocalTimeZone":
		return b.setUCIOption(ctx, "system", "@system[0]", "timezone", value.AsString(), true, systemReloadScript)
	case "Device.IP.ULAPrefix":
		prefix, err := stringifyPrefixValue(value)
		if err != nil {
			return err
		}
		return b.setUCIOption(ctx, "network", "globals", "ula_prefix", prefix, true, networkReloadScript)
	case "Device.Firewall.Enable":
		disabled := "1"
		if value.AsBool() {
			disabled = "0"
		}
		return b.setUCIOption(ctx, "firewall", "@defaults[0]", "disabled", disabled, true, firewallReloadScript)
	default:
		// Handle dynamic instance paths for WiFi (Device.WiFi.SSID.1.SSID, etc.)
		if err := b.setWiFiParam(ctx, path, value); err != wusp.ErrUSPPathUnsupported {
			return err
		}
		return wusp.ErrUSPPathUnsupported
	}
}

func (b *OpenWrtBackend) Delete(ctx context.Context, paths ...string) error {
	for _, path := range paths {
		path = strings.TrimSpace(path)
		switch path {
		case "Device.DeviceInfo.FriendlyName":
			if err := b.updateState(func(state *openWrtState) {
				state.FriendlyName = ""
			}); err != nil {
				return err
			}
		case "Device.DeviceInfo.ProvisioningCode":
			if err := b.updateState(func(state *openWrtState) {
				state.ProvisioningCode = ""
			}); err != nil {
				return err
			}
		case "Device.IP.ULAPrefix":
			if err := b.deleteUCIOption(ctx, "network", "globals", "ula_prefix", true, networkReloadScript); err != nil {
				return err
			}
		default:
			return wusp.ErrUSPPathUnsupported
		}
	}
	return nil
}

const (
	systemReloadScript   = "/etc/init.d/system"
	networkReloadScript  = "/etc/init.d/network"
	firewallReloadScript = "/etc/init.d/firewall"
	wirelessReloadScript = "wifi"
)

func (b *OpenWrtBackend) collectAll(ctx context.Context) (*wusp.Message, error) {
	snapshot := b.collectSnapshot(ctx)

	modelName := firstNonEmpty(strings.TrimSpace(snapshot.board.Model), snapshot.release["DISTRIB_DEVICE_MODEL"], strings.TrimSpace(snapshot.board.BoardName))
	modelNumber := firstNonEmpty(strings.TrimSpace(snapshot.board.BoardName), modelName)
	productClass := firstNonEmpty(strings.TrimSpace(snapshot.board.Release.Target), snapshot.release["DISTRIB_TARGET"], modelNumber)
	hardwareVersion := firstNonEmpty(strings.TrimSpace(snapshot.board.System), snapshot.release["DISTRIB_ARCH"], modelNumber)
	softwareVersion := firstNonEmpty(strings.TrimSpace(snapshot.board.Release.Description), snapshot.release["DISTRIB_DESCRIPTION"], snapshot.release["DISTRIB_RELEASE"], strings.TrimSpace(snapshot.board.Kernel))
	description := strings.TrimSpace(strings.Join(nonEmptyStrings(modelName, softwareVersion), " / "))
	manufacturer := guessOpenWrtManufacturer(snapshot.board, snapshot.release, modelName)
	manufacturerOUI := b.readManufacturerOUI()
	friendlyName := firstNonEmpty(snapshot.state.FriendlyName, snapshot.hostname)

	msg := &wusp.Message{Fields: make([]wusp.Field, 0, 32)}
	appendField(msg, "Device.RootDataModelVersion", wusp.String(wusp.BroadbandRootDataModelVersion))
	appendField(msg, "Device.DeviceInfo.Manufacturer", wusp.String(manufacturer))
	if len(manufacturerOUI) == 6 {
		appendField(msg, "Device.DeviceInfo.ManufacturerOUI", wusp.String(manufacturerOUI))
	}
	appendField(msg, "Device.DeviceInfo.ModelName", wusp.String(modelName))
	appendField(msg, "Device.DeviceInfo.ModelNumber", wusp.String(modelNumber))
	appendField(msg, "Device.DeviceInfo.Description", wusp.String(description))
	appendField(msg, "Device.DeviceInfo.ProductClass", wusp.String(productClass))
	appendField(msg, "Device.DeviceInfo.SerialNumber", wusp.String(snapshot.serialNumber))
	appendField(msg, "Device.DeviceInfo.HardwareVersion", wusp.String(hardwareVersion))
	appendField(msg, "Device.DeviceInfo.SoftwareVersion", wusp.String(softwareVersion))
	appendField(msg, "Device.DeviceInfo.ProvisioningCode", wusp.String(snapshot.state.ProvisioningCode))
	appendField(msg, "Device.DeviceInfo.UpTime", wusp.Uint(uint64(snapshot.uptimeSeconds)))
	appendField(msg, "Device.DeviceInfo.HostName", wusp.String(snapshot.hostname))
	appendField(msg, "Device.DeviceInfo.FriendlyName", wusp.String(friendlyName))
	appendField(msg, "Device.DeviceInfo.MemoryStatus.Total", wusp.Uint(uint64(snapshot.memTotal)))
	appendField(msg, "Device.DeviceInfo.MemoryStatus.Free", wusp.Uint(uint64(snapshot.memFree)))
	appendField(msg, "Device.DeviceInfo.NetworkProperties.TCPImplementation", wusp.List(wusp.String(snapshot.tcpImplementation)))
	appendField(msg, "Device.Time.Enable", wusp.Bool(snapshot.timeEnabled))
	if snapshot.timeStatus != "" {
		appendField(msg, "Device.Time.Status", wusp.String(snapshot.timeStatus))
	}
	appendField(msg, "Device.Time.CurrentLocalTime", wusp.Time(snapshot.currentLocalTime))
	appendField(msg, "Device.Time.LocalTimeZone", wusp.String(snapshot.localTimeZone))
	appendField(msg, "Device.Time.ClientNumberOfEntries", wusp.Uint(uint64(snapshot.timeClientCount)))
	appendField(msg, "Device.Time.ServerNumberOfEntries", wusp.Uint(uint64(snapshot.timeServerCount)))
	appendField(msg, "Device.IP.IPv4Capable", wusp.Bool(true))
	appendField(msg, "Device.IP.IPv4Enable", wusp.Bool(true))
	appendField(msg, "Device.IP.IPv4Status", wusp.String("Enabled"))
	appendField(msg, "Device.IP.IPv6Capable", wusp.Bool(true))
	appendField(msg, "Device.IP.IPv6Enable", wusp.Bool(snapshot.ipv6Enabled))
	appendField(msg, "Device.IP.IPv6Status", wusp.String(boolToStatus(snapshot.ipv6Enabled)))
	appendField(msg, "Device.IP.InterfaceNumberOfEntries", wusp.Uint(uint64(snapshot.interfaceCount)))
	if _, prefix, err := net.ParseCIDR(snapshot.ulaPrefix); err == nil && prefix != nil {
		appendField(msg, "Device.IP.ULAPrefix", wusp.IP6Prefix(prefix))
	}
	appendField(msg, "Device.Firewall.Enable", wusp.Bool(snapshot.firewallEnabled))
	if !snapshot.firewallLastChange.IsZero() {
		appendField(msg, "Device.Firewall.LastChange", wusp.Time(snapshot.firewallLastChange))
	}
	appendField(msg, "Device.Firewall.Type", wusp.String("Stateful"))
	b.appendFirewallFields(msg)
	b.appendWiFiFields(msg)

	// Network interface details via getifaddrs (pure Go)
	collectNetworkInterfacesStatic(msg)
	collectCPUInfoStatic(ctx, b.commandRunner, msg)
	collectCellularStatic(msg)
	collectGPSStatic(msg)

	return msg, nil
}

func appendField(msg *wusp.Message, path string, value wusp.Value) {
	if path = strings.TrimSpace(path); path == "" {
		return
	}
	msg.Set(path, value)
}

func (b *OpenWrtBackend) collectSnapshot(ctx context.Context) openWrtSnapshot {
	state, _ := b.readState()
	board, _ := b.readBoardInfo()
	release := b.readReleaseInfo()
	systemInfo, _ := b.readSystemInfo()

	hostname := firstNonEmpty(b.readHostname(), strings.TrimSpace(board.Hostname))
	if hostname == "" {
		if host, err := os.Hostname(); err == nil {
			hostname = strings.TrimSpace(host)
		}
	}

	uptimeSeconds := int64(systemInfo.Uptime)
	if uptimeSeconds <= 0 {
		uptimeSeconds = b.readUptimeSeconds()
	}

	memTotal := systemInfo.Memory.Total
	memFree := systemInfo.Memory.Available
	if memFree == 0 {
		memFree = systemInfo.Memory.Free
	}
	if memTotal == 0 || memFree == 0 {
		fileTotal, fileFree := b.readMemInfo()
		if memTotal == 0 {
			memTotal = fileTotal
		}
		if memFree == 0 {
			memFree = fileFree
		}
	}

	currentLocalTime := b.now()
	if systemInfo.LocalTime > 0 {
		currentLocalTime = time.Unix(systemInfo.LocalTime, 0)
	}

	serialNumber := strings.TrimSpace(b.readTextFile(b.serialNumberPath))
	if serialNumber == "" {
		serialNumber = release["DISTRIB_SERIAL"]
	}

	localTimeZone := firstNonEmpty(
		b.readUCIValue(ctx, "system", "system", "timezone"),
		b.readUCIValue(ctx, "system", "system", "zonename"),
	)
	timeEnabled, timeClientCount, timeServerCount := b.readTimeSettings(ctx)
	timeStatus := ""
	if !timeEnabled {
		timeStatus = "Disabled"
	}

	return openWrtSnapshot{
		state:              state,
		board:              board,
		release:            release,
		hostname:           hostname,
		uptimeSeconds:      uptimeSeconds,
		memTotal:           memTotal,
		memFree:            memFree,
		ipv6Enabled:        b.readIPv6Enabled(),
		tcpImplementation:  sanitizeTCPImplementation(b.readTextFile(b.tcpImplementationPath)),
		serialNumber:       serialNumber,
		currentLocalTime:   currentLocalTime,
		localTimeZone:      localTimeZone,
		timeEnabled:        timeEnabled,
		timeStatus:         timeStatus,
		timeClientCount:    timeClientCount,
		timeServerCount:    timeServerCount,
		ulaPrefix:          b.readUCIValue(ctx, "network", "globals", "ula_prefix"),
		interfaceCount:     b.readInterfaceCount(),
		firewallEnabled:    b.readFirewallEnabled(ctx),
		firewallLastChange: b.readFileModTime(filepath.Join(b.uciConfigDir, "firewall")),
	}
}

func (b *OpenWrtBackend) appendWiFiFields(msg *wusp.Message) {
	radios := b.readWirelessRadioStatus()
	if len(radios) == 0 {
		radios = b.readWirelessRadioStatusFromUCI()
	}

	radioKeys := make([]string, 0, len(radios))
	for key := range radios {
		if strings.TrimSpace(key) != "" {
			radioKeys = append(radioKeys, key)
		}
	}
	sort.Strings(radioKeys)

	stationCounts := b.readWiFiStationCounts()
	defer iwinfo.Close()

	ssidCount := 0
	apCount := 0
	endPointCount := 0
	radioIndexByName := make(map[string]int, len(radioKeys))

	for i, key := range radioKeys {
		radio := radios[key]
		radioIndex := i + 1
		radioIndexByName[key] = radioIndex
		radioEnabled := !radio.Disabled && !parseOpenWrtBool(configString(radio.Config, "disabled"), false)

		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.Enable", radioIndex), wusp.Bool(radioEnabled))
		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.Status", radioIndex), wusp.String(wifiStatusValue(radioEnabled, radio.Up)))
		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.Name", radioIndex), wusp.String(key))
		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.OperatingFrequencyBand", radioIndex), wusp.String(wifiBandFromConfig(radio.Config)))
		if channel := configInt(radio.Config, "channel"); channel > 0 {
			appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.Channel", radioIndex), wusp.Uint(uint64(channel)))
		}
		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.OperatingChannelBandwidth", radioIndex), wusp.String(wifiBandwidthFromConfig(radio.Config)))

		interfaces := append([]openWrtWirelessIfaceStatus(nil), radio.Interfaces...)
		sort.SliceStable(interfaces, func(i, j int) bool {
			left := firstNonEmpty(interfaces[i].Section, interfaces[i].IfName)
			right := firstNonEmpty(interfaces[j].Section, interfaces[j].IfName)
			return left < right
		})

		for _, iface := range interfaces {
			ssidCount++
			ssidPath := fmt.Sprintf("Device.WiFi.SSID.%d.", ssidCount)

			ifName := firstNonEmpty(iface.IfName, configString(iface.Config, "ifname"), iface.Section)
			mode := strings.ToLower(firstNonEmpty(configString(iface.Config, "mode"), "ap"))
			ssidEnabled := !parseOpenWrtBool(configString(iface.Config, "disabled"), false)
			ssidValue := configString(iface.Config, "ssid")
			bssidValue := ""

			if ifName != "" && iwinfo.Available(ifName) {
				if info, err := iwinfo.GetInfo(ifName); err == nil {
					if strings.TrimSpace(info.SSID) != "" {
						ssidValue = strings.TrimSpace(info.SSID)
					}
					if strings.TrimSpace(info.BSSID) != "" {
						bssidValue = strings.TrimSpace(info.BSSID)
					}
				}
			}
			if bssidValue == "" && ifName != "" {
				bssidValue = strings.TrimSpace(b.readTextFile(filepath.Join(b.netClassDir, ifName, "address")))
			}

			appendField(msg, ssidPath+"Enable", wusp.Bool(ssidEnabled))
			appendField(msg, ssidPath+"Status", wusp.String(wifiStatusValue(ssidEnabled, iface.Up)))
			appendField(msg, ssidPath+"Name", wusp.String(firstNonEmpty(ifName, iface.Section)))
			if ssidValue != "" {
				appendField(msg, ssidPath+"SSID", wusp.String(ssidValue))
			}
			appendField(msg, ssidPath+"LowerLayers", wusp.String(fmt.Sprintf("Device.WiFi.Radio.%d.", radioIndex)))
			if mac, err := net.ParseMAC(bssidValue); err == nil && len(mac) == 6 {
				appendField(msg, ssidPath+"BSSID", wusp.MAC(mac))
			}

			if wifiInterfaceModeIsAP(mode) {
				apCount++
				apPath := fmt.Sprintf("Device.WiFi.AccessPoint.%d.", apCount)
				appendField(msg, apPath+"Enable", wusp.Bool(ssidEnabled))
				appendField(msg, apPath+"Status", wusp.String(wifiStatusValue(ssidEnabled, iface.Up)))
				appendField(msg, apPath+"SSIDReference", wusp.String(ssidPath))
				appendField(msg, apPath+"AssociatedDeviceNumberOfEntries", wusp.Uint(uint64(stationCounts[ifName])))
			} else if wifiInterfaceModeIsEndpoint(mode) {
				endPointCount++
			}
		}
	}

	appendField(msg, "Device.WiFi.RadioNumberOfEntries", wusp.Uint(uint64(len(radioKeys))))
	appendField(msg, "Device.WiFi.SSIDNumberOfEntries", wusp.Uint(uint64(ssidCount)))
	appendField(msg, "Device.WiFi.AccessPointNumberOfEntries", wusp.Uint(uint64(apCount)))
	appendField(msg, "Device.WiFi.EndPointNumberOfEntries", wusp.Uint(uint64(endPointCount)))
}

// setHostname persists the hostname via UCI and applies it live by writing
// /proc/sys/kernel/hostname directly. The kernel sysctl path needs no daemon —
// a single write updates the running hostname for the whole system, which lets
// us drop the legacy `hostname` CLI shell-out (which is missing on stripped
// builds). The applyUCIChange tier inside setUCIOption already mirrors the
// /proc write; the explicit call here is defensive in case a caller bypasses
// applyUCIChange in the future.
func (b *OpenWrtBackend) setHostname(ctx context.Context, hostname string) error {
	if err := b.setUCIOption(ctx, "system", "@system[0]", "hostname", hostname, true, systemReloadScript); err != nil {
		return err
	}
	return b.writeProcSysHostname(hostname)
}

func (b *OpenWrtBackend) setTimeEnabled(ctx context.Context, enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	section := b.resolveUCISectionRef("system", "timeserver")
	if err := b.setUCIOption(ctx, "system", section, "enabled", value, false, ""); err != nil {
		return err
	}
	if err := b.setUCIOption(ctx, "system", section, "enable_server", value, true, systemReloadScript); err != nil {
		return err
	}
	return nil
}

// setWiFiParam handles writable WiFi instance paths like:
//
//	Device.WiFi.Radio.1.Enable        → wireless.radio0.disabled
//	Device.WiFi.Radio.1.Channel       → wireless.radio0.channel
//	Device.WiFi.SSID.1.SSID           → wireless.@wifi-iface[0].ssid
//	Device.WiFi.SSID.1.Enable         → wireless.@wifi-iface[0].disabled
//	Device.WiFi.AccessPoint.1.Enable  → wireless.@wifi-iface[0].disabled
func (b *OpenWrtBackend) setWiFiParam(ctx context.Context, path string, value wusp.Value) error {
	// Parse instance path: Device.WiFi.Radio.{n}.{param}
	var objType, param string
	var idx int
	if _, err := fmt.Sscanf(path, "Device.WiFi.Radio.%d.%s", &idx, &param); err == nil {
		objType = "radio"
	} else if _, err := fmt.Sscanf(path, "Device.WiFi.SSID.%d.%s", &idx, &param); err == nil {
		objType = "ssid"
	} else if _, err := fmt.Sscanf(path, "Device.WiFi.AccessPoint.%d.%s", &idx, &param); err == nil {
		objType = "ap"
	} else {
		return wusp.ErrUSPPathUnsupported
	}

	switch objType {
	case "radio":
		section := fmt.Sprintf("radio%d", idx-1) // Radio.1 → radio0
		switch param {
		case "Enable":
			disabled := "1"
			if value.AsBool() {
				disabled = "0"
			}
			return b.setUCIOption(ctx, "wireless", section, "disabled", disabled, true, wirelessReloadScript)
		case "Channel":
			return b.setUCIOption(ctx, "wireless", section, "channel", wusp.ValueToString(value), true, wirelessReloadScript)
		case "OperatingChannelBandwidth":
			htmode := bandwidthToHTMode(wusp.ValueToString(value), section, b, ctx)
			return b.setUCIOption(ctx, "wireless", section, "htmode", htmode, true, wirelessReloadScript)
		}
	case "ssid", "ap":
		// Resolve the UCI section name for this SSID/AP index by iterating
		// the ubus wireless status in the same order as the collector.
		section := b.resolveWiFiIfaceSection(idx)
		if section == "" {
			section = fmt.Sprintf("@wifi-iface[%d]", idx-1) // fallback to positional
		}
		switch param {
		case "SSID":
			return b.setUCIOption(ctx, "wireless", section, "ssid", value.AsString(), true, wirelessReloadScript)
		case "Enable":
			disabled := "1"
			if value.AsBool() {
				disabled = "0"
			}
			return b.setUCIOption(ctx, "wireless", section, "disabled", disabled, true, wirelessReloadScript)
		}
	}
	return wusp.ErrUSPPathUnsupported
}

// resolveWiFiIfaceSection maps a WUSP SSID/AP index (1-based) to the actual UCI
// section name (e.g. "default_radio0") by iterating ubus wireless status in the
// same order as the collector. This ensures Set operations target the correct section.
func (b *OpenWrtBackend) resolveWiFiIfaceSection(ssidIndex int) string {
	radios := b.readWirelessRadioStatus()
	if len(radios) == 0 {
		return ""
	}

	// Sort radio keys to match collector order
	radioKeys := make([]string, 0, len(radios))
	for k := range radios {
		radioKeys = append(radioKeys, k)
	}
	sort.Strings(radioKeys)

	count := 0
	for _, key := range radioKeys {
		radio := radios[key]
		// Sort interfaces by section name (matches collector)
		ifaces := append([]openWrtWirelessIfaceStatus(nil), radio.Interfaces...)
		sort.SliceStable(ifaces, func(i, j int) bool {
			left := firstNonEmpty(ifaces[i].Section, ifaces[i].IfName)
			right := firstNonEmpty(ifaces[j].Section, ifaces[j].IfName)
			return left < right
		})
		for _, iface := range ifaces {
			count++
			if count == ssidIndex {
				return iface.Section
			}
		}
	}
	return ""
}

// setUCIOption persists an option=value into /etc/config/<config> and best-effort
// applies it live. Order of preference is **file edit first**: stripped-down
// OpenWrt builds may ship without `uci`, without `ubus`, or with a procd that
// doesn't restart cleanly. The plain config file is the source of truth that
// every UCI consumer (system, network, firewall, fw3/fw4, netifd, hostapd via
// /sbin/wifi) reads at startup, so writing it directly keeps every variant
// (LEDE, OpenWrt, OpenWisp, GL.iNet, Turris, etc.) happy.
//
// After the file is durable we still try ubus → uci CLI → init.d reload to
// pick up the change at runtime; failures from the apply tier are NOT propagated
// because the persistent change has already succeeded — at worst the new value
// takes effect on next reboot.
func (b *OpenWrtBackend) setUCIOption(ctx context.Context, config, section, option, value string, commit bool, reloadScript string) error {
	if err := b.writeUCIOptionViaFile(config, section, option, value); err != nil {
		// Fall back to ubus / CLI ONLY when the direct file write fails (RO
		// filesystem, missing /etc/config dir on a non-OpenWrt POSIX target,
		// etc.). This mirrors the historical behaviour for those edge cases.
		if ubusErr := b.setUCIOptionViaUbus(ctx, config, section, option, value, commit); ubusErr == nil {
			b.applyUCIChange(ctx, config, section, option, value, reloadScript)
			return nil
		}
		key := fmt.Sprintf("%s.%s.%s=%s", config, section, option, value)
		if _, cliErr := b.commandRunner(ctx, "uci", "set", key); cliErr != nil {
			return fmt.Errorf("wusp openwrt setUCIOption %s.%s.%s: file=%v cli=%v", config, section, option, err, cliErr)
		}
		if commit {
			if _, cliErr := b.commandRunner(ctx, "uci", "commit", config); cliErr != nil {
				return cliErr
			}
		}
		return b.reloadScript(ctx, reloadScript)
	}

	// File write succeeded — apply at runtime on a best-effort basis.
	if commit {
		b.applyUCIChange(ctx, config, section, option, value, reloadScript)
	}
	return nil
}

func (b *OpenWrtBackend) deleteUCIOption(ctx context.Context, config, section, option string, commit bool, reloadScript string) error {
	if err := b.writeUCIOptionViaFile(config, section, option, ""); err != nil {
		if ubusErr := b.deleteUCIOptionViaUbus(ctx, config, section, option, commit); ubusErr == nil {
			if commit {
				_ = b.reloadScript(ctx, reloadScript)
			}
			return nil
		}
		key := fmt.Sprintf("%s.%s.%s", config, section, option)
		if _, cliErr := b.commandRunner(ctx, "uci", "-q", "delete", key); cliErr != nil {
			return fmt.Errorf("wusp openwrt deleteUCIOption %s.%s.%s: file=%v cli=%v", config, section, option, err, cliErr)
		}
		if commit {
			if _, cliErr := b.commandRunner(ctx, "uci", "commit", config); cliErr != nil {
				return cliErr
			}
		}
		return b.reloadScript(ctx, reloadScript)
	}
	if commit {
		b.applyUCIChange(ctx, config, section, option, "", reloadScript)
	}
	return nil
}

// applyUCIChange best-effort propagates a config change to running services
// without depending on the OpenWrt-specific `uci` / `ubus` tools. Each tier
// fails open — a missing tool just drops to the next tier, and "no tier
// applied" is fine because the on-disk file is already authoritative.
//
// References for the live-apply paths:
//   - hostname:  /proc/sys/kernel/hostname (kernel.org sysctl docs)
//   - timezone:  /etc/TZ (BusyBox libc reads this on every libc time call)
//   - reload:    /etc/init.d/<svc> reload (procd-based, the canonical apply)
func (b *OpenWrtBackend) applyUCIChange(ctx context.Context, config, section, option, value, reloadScript string) {
	switch {
	case config == "system" && option == "hostname":
		_ = b.writeProcSysHostname(value)
	case config == "system" && option == "timezone":
		_ = b.writeEtcTZ(value)
	}
	_ = b.reloadScript(ctx, reloadScript)
}

// writeUCIOptionViaFile rewrites /etc/config/<config> in place, setting
// option=value inside the section addressed by sectionRef. An empty value
// deletes the option line. If the section doesn't exist yet, a fresh
// `config <type> [name]` block is appended to the file.
//
// The rewrite is line-oriented: every byte that doesn't belong to the
// targeted option line is preserved verbatim (comments, blank lines,
// whitespace, ordering), so users diffing /etc/config/* see only their
// actual change.
//
// Section reference forms accepted:
//   - `@type[index]` — positional (zero-based), as emitted by `resolveUCISectionRef`
//   - `name`         — named section (`config <type> 'name'`)
//   - `type`         — bare type, resolves to first section of that type
func (b *OpenWrtBackend) writeUCIOptionViaFile(config, sectionRef, option, value string) error {
	if strings.TrimSpace(option) == "" {
		return errors.New("uci: empty option name")
	}
	path := filepath.Join(b.uciConfigDir, config)
	original, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	updated, err := uciRewrite(original, sectionRef, option, value)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, updated, 0o644)
}

// writeProcSysHostname propagates a hostname change to BOTH the live kernel
// (/proc/sys/kernel/hostname) and the canonical persistent file (/etc/hostname).
// Writing both is required because they serve different consumers:
//
//   - /proc/sys/kernel/hostname — sysctl-backed, a single direct write updates
//     the running hostname instantly with no daemon involvement
//     (kernel.org sysctl docs).
//   - /etc/hostname — read at boot by every non-procd init (BusyBox, Alpine,
//     Debian, Ubuntu, systemd, OpenWrt-without-procd-running, containers).
//     Without this, a reboot would revert the hostname even if /etc/config/system
//     was updated, because no init script consumed the UCI value.
//
// Both targets are written with a direct `os.WriteFile` rather than the
// tmp+rename atomic pattern. Rationale:
//
//   - procfs (/proc/sys/kernel/hostname) doesn't support rename-onto
//     operations — sysctl pseudo-files accept writes only via O_WRONLY on
//     the entry itself.
//   - /etc/hostname is a bind-mount target inside Docker / Podman / LXC
//     containers (mounted from /var/lib/docker/containers/<id>/hostname).
//     `rename(2)` over a bind-mount returns EBUSY/EXDEV, so the historical
//     atomic-rename approach silently lost every Set inside containers.
//     A direct write hits the same inode the runtime mounted, so the value
//     becomes visible to the host and any other shell namespace.
//
// Errors from either target are aggregated so a single missing/RO path
// doesn't mask a genuine failure on the other one — important on systems
// where /etc/hostname is missing entirely (some embedded builds) but the
// kernel write must still succeed.
func (b *OpenWrtBackend) writeProcSysHostname(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	var errs []string
	if b.hostnamePath != "" {
		if err := writeAndVerify(b.hostnamePath, value); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", b.hostnamePath, err))
		}
	}
	if b.etcHostnamePath != "" {
		// Clean up any *.tmp orphan left behind by an older agent build whose
		// atomic-rename approach failed against a bind-mounted /etc/hostname
		// (Docker/Podman/LXC mount it from /var/lib/<runtime>/containers/<id>).
		// Stale .tmp files are confusing during live debugging — a `cat
		// /etc/hostname.tmp` shows the value the old code *tried* to set,
		// which looks like the agent silently took effect when in fact the
		// rename(2) returned EBUSY and the change never landed.
		_ = os.Remove(b.etcHostnamePath + ".tmp")
		if err := writeAndVerify(b.etcHostnamePath, value); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", b.etcHostnamePath, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("wusp openwrt setHostname persistence: %s", strings.Join(errs, "; "))
	}
	return nil
}

// writeAndVerify writes value+"\n" to path with a direct WriteFile (no rename
// — important for procfs and bind-mounted destinations) and reads it back to
// confirm the bytes actually landed. The readback catches the silent-failure
// modes that otherwise produce "agent says success but file unchanged":
//
//   - read-only bind mount (rare but possible with `-v src:/etc/hostname:ro`)
//   - file replaced by an external process between our write and the dashboard
//     re-reading (race rare in practice but cheap to detect)
//   - tmpfs `noexec`-style attribute oddities on stripped containers
//
// Parent-directory creation is best-effort: on real systems /proc and /etc
// always exist, so MkdirAll is a no-op; in test rigs it lets the caller point
// at a synthesized path under t.TempDir() without preflight.
func writeAndVerify(path, value string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	body := []byte(value + "\n")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return err
	}
	got, err := os.ReadFile(path)
	if err != nil {
		// Some pseudo-files (e.g. /proc/sys/kernel/hostname under unusual
		// container configs) accept writes but reject reads from this path —
		// treat the write as authoritative and skip the verify.
		return nil
	}
	gotTrimmed := strings.TrimRight(string(got), "\n")
	if gotTrimmed != value {
		return fmt.Errorf("readback mismatch: wrote %q, file now contains %q (RO bind-mount or external writer?)",
			value, gotTrimmed)
	}
	return nil
}

func (b *OpenWrtBackend) writeEtcTZ(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || b.tzPath == "" {
		return nil
	}
	// /etc/TZ holds the POSIX TZ string that BusyBox libc consults on every
	// time call. UCI stores either the IANA name (e.g. "America/New_York")
	// or the POSIX form (e.g. "EST5EDT,M3.2.0,M11.1.0"). We try to upgrade
	// IANA → POSIX by reading the trailing TZ line of the matching tzdata
	// file (the IANA Time Zone Database appends the POSIX form as the last
	// line of every binary tzfile, per RFC 8536 §3.2). On failure we just
	// write the raw value — at worst the live apply is approximate until
	// /etc/init.d/system reload runs.
	posix := value
	if b.zoneInfoDir != "" && !looksLikePOSIXTZ(value) {
		if extracted, ok := readTrailingTZ(filepath.Join(b.zoneInfoDir, value)); ok {
			posix = extracted
		}
	}
	return atomicWriteFile(b.tzPath, []byte(posix+"\n"), 0o644)
}

// atomicWriteFile writes data to a sibling temp file then renames over the
// target. Safe on overlay filesystems (jffs2/squashfs+overlay) as long as both
// paths land in the same overlay branch — which is the case for /etc/config/*
// and /etc/TZ on every OpenWrt build, since first-write triggers a copy-up
// before our temp file is created.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// uciRewrite is the pure-function core of the file-based UCI editor — no
// filesystem, no I/O. Kept package-level so it's easy to unit-test the
// preserve-comments / replace-option / append-section logic.
func uciRewrite(original []byte, sectionRef, option, value string) ([]byte, error) {
	option = strings.TrimSpace(option)
	if option == "" {
		return nil, errors.New("uci: empty option name")
	}

	lines := splitLinesPreserving(string(original))
	headerIdx, sectionEnd, err := findUCISection(lines, sectionRef)
	if err != nil {
		return nil, err
	}

	if headerIdx < 0 {
		// Section missing entirely — append a fresh block.
		appended := appendUCISection(lines, sectionRef, option, value)
		return []byte(strings.Join(appended, "")), nil
	}

	rewritten := replaceOrInsertOption(lines, headerIdx, sectionEnd, option, value)
	return []byte(strings.Join(rewritten, "")), nil
}

// splitLinesPreserving splits text on '\n' but keeps the newline as part of
// each element except for a trailing empty line (so re-joining round-trips).
func splitLinesPreserving(text string) []string {
	if text == "" {
		return nil
	}
	out := make([]string, 0, strings.Count(text, "\n")+1)
	for {
		nl := strings.IndexByte(text, '\n')
		if nl < 0 {
			if text != "" {
				out = append(out, text)
			}
			return out
		}
		out = append(out, text[:nl+1])
		text = text[nl+1:]
	}
}

// findUCISection scans the line stream for the section addressed by sectionRef.
// Returns (headerLineIndex, oneAfterLastBodyLineIndex, nil) if found, or
// (-1, -1, nil) if not found. Errors only on malformed sectionRef.
//
// sectionRef forms:
//   - `@type[idx]` — zero-based positional index of the type
//   - `name`       — matches `config <type> 'name'` or `config <type> name`
//   - `type`       — first section of that type
func findUCISection(lines []string, sectionRef string) (int, int, error) {
	sectionRef = strings.TrimSpace(sectionRef)
	if sectionRef == "" {
		return -1, -1, errors.New("uci: empty section ref")
	}

	wantType, wantName, wantIdx, indexed := parseUCISectionRef(sectionRef)

	headerIdx := -1
	typeCounts := map[string]int{}
	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if !strings.HasPrefix(trimmed, "config ") && trimmed != "config" {
			continue
		}
		secType, secName := parseConfigHeader(trimmed)
		idx := typeCounts[secType]
		typeCounts[secType] = idx + 1

		switch {
		case indexed:
			if secType == wantType && idx == wantIdx {
				headerIdx = i
			}
		case wantName != "":
			if secName == wantName {
				headerIdx = i
			}
		case wantType != "":
			if secType == wantType && headerIdx == -1 {
				headerIdx = i
			}
		}
		if headerIdx == i {
			break
		}
	}
	if headerIdx < 0 {
		return -1, -1, nil
	}

	// Body extends from the line after the header until the next `config `
	// header or EOF.
	end := len(lines)
	for j := headerIdx + 1; j < len(lines); j++ {
		if strings.HasPrefix(strings.TrimSpace(lines[j]), "config ") {
			end = j
			break
		}
	}
	return headerIdx, end, nil
}

// parseUCISectionRef extracts (type, name, index, isIndexed) from a section
// reference string. Mirrors fallbackUCISectionRef's accepted forms.
func parseUCISectionRef(ref string) (string, string, int, bool) {
	if strings.HasPrefix(ref, "@") {
		// @type[idx]
		open := strings.IndexByte(ref, '[')
		close := strings.IndexByte(ref, ']')
		if open > 1 && close > open {
			t := ref[1:open]
			idx, err := strconv.Atoi(ref[open+1 : close])
			if err == nil {
				return t, "", idx, true
			}
		}
		return strings.TrimPrefix(ref, "@"), "", 0, false
	}
	// Could be a named section ("globals") or a bare type ("system"). The
	// caller can't tell them apart syntactically, so we return both
	// candidates and let findUCISection match either.
	return ref, ref, 0, false
}

// parseConfigHeader splits a `config <type> ['name']` header line.
func parseConfigHeader(line string) (string, string) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "config" {
		return "", ""
	}
	t := strings.Trim(fields[1], `'"`)
	if len(fields) >= 3 {
		name := strings.Trim(strings.Join(fields[2:], " "), `'"`)
		return t, name
	}
	return t, ""
}

// replaceOrInsertOption walks the section body [headerIdx+1, sectionEnd) and
// either replaces the existing `option <name> ...` line with a fresh one, or
// inserts a new line just before the section ends if the option wasn't there.
// An empty value deletes the line instead.
func replaceOrInsertOption(lines []string, headerIdx, sectionEnd int, option, value string) []string {
	indent := detectSectionIndent(lines, headerIdx, sectionEnd)
	for i := headerIdx + 1; i < sectionEnd; i++ {
		stripped := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(stripped, "option ") {
			continue
		}
		name, _, ok := parseUCIAssignment(stripped, "option")
		if !ok || name != option {
			continue
		}
		if value == "" {
			// delete: drop the line entirely
			out := make([]string, 0, len(lines)-1)
			out = append(out, lines[:i]...)
			out = append(out, lines[i+1:]...)
			return out
		}
		lines[i] = indent + "option " + option + " " + uciQuote(value) + "\n"
		return lines
	}
	if value == "" {
		return lines // nothing to delete
	}
	// Insert just before sectionEnd. Trim a trailing blank line if any so the
	// new option lands inside the section block, not after a separator.
	insertAt := sectionEnd
	for insertAt > headerIdx+1 && strings.TrimSpace(lines[insertAt-1]) == "" {
		insertAt--
	}
	newLine := indent + "option " + option + " " + uciQuote(value) + "\n"
	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:insertAt]...)
	out = append(out, newLine)
	out = append(out, lines[insertAt:]...)
	return out
}

// detectSectionIndent returns the leading whitespace used by the existing
// option/list lines in this section. Defaults to a single tab (OpenWrt's
// canonical UCI style) when the section has no body yet.
func detectSectionIndent(lines []string, headerIdx, sectionEnd int) string {
	for i := headerIdx + 1; i < sectionEnd; i++ {
		s := lines[i]
		trimmed := strings.TrimLeft(s, " \t")
		if !strings.HasPrefix(trimmed, "option ") && !strings.HasPrefix(trimmed, "list ") {
			continue
		}
		return s[:len(s)-len(trimmed)]
	}
	return "\t"
}

// appendUCISection adds a fresh `config <type> [name]` block at the end of
// the file with a single option line. Used when the requested section ref
// doesn't exist anywhere in the file yet.
func appendUCISection(lines []string, sectionRef, option, value string) []string {
	wantType, wantName, _, indexed := parseUCISectionRef(sectionRef)
	header := "config " + wantType
	if !indexed && wantName != "" && wantName != wantType {
		header += " " + uciQuote(wantName)
	}
	header += "\n"
	body := ""
	if value != "" {
		body = "\toption " + option + " " + uciQuote(value) + "\n"
	}
	// Ensure separation from any prior content.
	if len(lines) > 0 && !strings.HasSuffix(lines[len(lines)-1], "\n") {
		lines[len(lines)-1] += "\n"
	}
	if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
		lines = append(lines, "\n")
	}
	lines = append(lines, header)
	if body != "" {
		lines = append(lines, body)
	}
	return lines
}

// uciQuote single-quotes a value, escaping embedded single quotes the way the
// shell-style UCI parser expects (close-quote, escaped-quote, reopen-quote).
// Empty strings serialize to ” so the option line stays valid.
func uciQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// looksLikePOSIXTZ heuristically detects whether a UCI timezone value is
// already a POSIX TZ string (e.g. "EST5EDT,M3.2.0,M11.1.0", "UTC0") rather
// than an IANA name (e.g. "America/New_York"). POSIX TZ strings never contain
// a slash or a space; IANA names always contain a slash unless they are one
// of the legacy aliases ("UTC", "GMT") which we treat as POSIX-safe too.
func looksLikePOSIXTZ(value string) bool {
	if strings.ContainsAny(value, "/ ") {
		return false
	}
	return true
}

// readTrailingTZ extracts the POSIX TZ string appended to a tzdata binary
// file by the IANA Time Zone Database. RFC 8536 §3.2 mandates that v2+
// tzfiles end with `\n<POSIX-TZ>\n`, so reading the file's last line is
// the canonical way to recover the POSIX form when only the IANA name is
// known. Falls back to (false) on parse error so the caller can use the
// raw IANA value.
func readTrailingTZ(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 2 {
		return "", false
	}
	// Strip a trailing newline, then take everything after the prior newline.
	if data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	nl := strings.LastIndexByte(string(data), '\n')
	if nl < 0 {
		return "", false
	}
	tz := strings.TrimSpace(string(data[nl+1:]))
	if tz == "" {
		return "", false
	}
	return tz, true
}

func (b *OpenWrtBackend) setUCIOptionViaUbus(ctx context.Context, config, section, option, value string, commit bool) error {
	if b.ubusClient == nil {
		return errors.New("ubus client unavailable")
	}
	ref := b.resolveUCISectionRef(config, section)
	if ref == "" {
		return errors.New("uci section unresolved")
	}
	if err := b.ubusClient.UCISet(ctx, config, ref, map[string]any{option: value}, b.ubusTimeout); err != nil {
		return err
	}
	if !commit {
		return nil
	}
	return b.commitUCIViaUbus(ctx, config)
}

func (b *OpenWrtBackend) deleteUCIOptionViaUbus(ctx context.Context, config, section, option string, commit bool) error {
	if b.ubusClient == nil {
		return errors.New("ubus client unavailable")
	}
	ref := b.resolveUCISectionRef(config, section)
	if ref == "" {
		return errors.New("uci section unresolved")
	}
	if err := b.ubusClient.UCIDelete(ctx, config, ref, option, b.ubusTimeout); err != nil {
		return err
	}
	if !commit {
		return nil
	}
	return b.commitUCIViaUbus(ctx, config)
}

func (b *OpenWrtBackend) commitUCIViaUbus(ctx context.Context, config string) error {
	if err := b.ubusClient.UCICommit(ctx, config, b.ubusTimeout); err != nil {
		return err
	}
	if err := b.ubusClient.UCIApply(ctx, false, b.ubusTimeout); err == nil {
		return nil
	}
	return b.ubusClient.UCIReloadConfig(ctx, b.ubusTimeout)
}

func (b *OpenWrtBackend) reloadScript(ctx context.Context, script string) error {
	if script == "" {
		return nil
	}

	// "wifi" is a standalone command (not an init script) — run without args.
	// Init scripts like /etc/init.d/network take "reload" as an argument.
	if script == "wifi" {
		_, err := b.commandRunner(ctx, "wifi")
		return err
	}

	if _, err := os.Stat(script); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	_, err := b.commandRunner(ctx, script, "reload")
	return err
}

func (b *OpenWrtBackend) updateState(update func(*openWrtState)) error {
	state, _ := b.readState()
	update(&state)
	return b.writeState(state)
}

func (b *OpenWrtBackend) readState() (openWrtState, error) {
	var state openWrtState
	data, err := os.ReadFile(b.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return state, err
	}
	if len(data) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return openWrtState{}, err
	}
	return state, nil
}

func (b *OpenWrtBackend) writeState(state openWrtState) error {
	if err := ensureStateParentDir(b.statePath); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tempPath := b.statePath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tempPath, b.statePath)
}

func (b *OpenWrtBackend) readBoardInfo() (openWrtBoardInfo, error) {
	var info openWrtBoardInfo
	data, err := b.ubusCaller("system", "board", b.ubusTimeout)
	if err != nil {
		return info, err
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return openWrtBoardInfo{}, err
	}
	return info, nil
}

func (b *OpenWrtBackend) readSystemInfo() (openWrtSystemInfo, error) {
	var info openWrtSystemInfo
	data, err := b.ubusCaller("system", "info", b.ubusTimeout)
	if err != nil {
		return info, err
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return openWrtSystemInfo{}, err
	}
	return info, nil
}

func (b *OpenWrtBackend) readNetworkInterfaceDump() (openWrtInterfaceDump, error) {
	var dump openWrtInterfaceDump
	data, err := b.ubusCaller("network.interface", "dump", b.ubusTimeout)
	if err != nil {
		return dump, err
	}
	if err := json.Unmarshal(data, &dump); err != nil {
		return openWrtInterfaceDump{}, err
	}
	return dump, nil
}

func (b *OpenWrtBackend) readWirelessRadioStatus() map[string]openWrtWirelessRadioStatus {
	data, err := b.ubusCaller("network.wireless", "status", b.ubusTimeout)
	if err != nil {
		return nil
	}

	var radios map[string]openWrtWirelessRadioStatus
	if err := json.Unmarshal(data, &radios); err != nil {
		return nil
	}
	return radios
}

func (b *OpenWrtBackend) readWiFiStationCounts() map[string]int {
	data, err := b.ubusCaller("device", "getStaList", b.ubusTimeout)
	if err != nil {
		return map[string]int{}
	}

	var payload struct {
		Station []openWrtWiFiStation `json:"station"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return map[string]int{}
	}

	counts := make(map[string]int)
	for _, station := range payload.Station {
		iface := strings.TrimSpace(station.Iface)
		if iface == "" {
			continue
		}
		counts[iface]++
	}
	return counts
}

func (b *OpenWrtBackend) readWirelessRadioStatusFromUCI() map[string]openWrtWirelessRadioStatus {
	parsed, err := b.readUCIConfig("wireless")
	if err != nil {
		return nil
	}

	radios := make(map[string]openWrtWirelessRadioStatus)
	deviceIndex := 0
	for _, section := range parsed.Sections {
		if section.Type != "wifi-device" {
			continue
		}
		name := section.Name
		if name == "" {
			name = fmt.Sprintf("radio%d", deviceIndex)
		}
		deviceIndex++

		config := make(map[string]any, len(section.Options))
		for key, value := range section.Options {
			config[key] = value
		}
		radios[name] = openWrtWirelessRadioStatus{
			Disabled: parseOpenWrtBool(section.Options["disabled"], false),
			Config:   config,
		}
	}

	ifaceIndex := 0
	for _, section := range parsed.Sections {
		if section.Type != "wifi-iface" {
			continue
		}
		device := strings.TrimSpace(section.Options["device"])
		if device == "" {
			continue
		}
		radio := radios[device]
		if radio.Config == nil {
			radio.Config = map[string]any{}
		}

		config := make(map[string]any, len(section.Options))
		for key, value := range section.Options {
			config[key] = value
		}
		iface := openWrtWirelessIfaceStatus{
			Section: section.Name,
			IfName:  firstNonEmpty(section.Options["ifname"], section.Name, fmt.Sprintf("wlan%d", ifaceIndex)),
			Up:      !parseOpenWrtBool(section.Options["disabled"], false),
			Config:  config,
		}
		if iface.Section == "" {
			iface.Section = fmt.Sprintf("wifi-iface-%d", ifaceIndex)
		}
		ifaceIndex++
		radio.Interfaces = append(radio.Interfaces, iface)
		radios[device] = radio
	}

	return radios
}

func (b *OpenWrtBackend) readReleaseInfo() map[string]string {
	for _, path := range []string{b.openWrtReleasePath, b.osReleasePath} {
		if values, err := parseAssignmentFile(path); err == nil && len(values) > 0 {
			return values
		}
	}
	return map[string]string{}
}

func (b *OpenWrtBackend) readHostname() string {
	return strings.TrimSpace(b.readTextFile(b.hostnamePath))
}

func (b *OpenWrtBackend) readUptimeSeconds() int64 {
	raw := strings.TrimSpace(b.readTextFile(b.uptimePath))
	if raw == "" {
		return 0
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return 0
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	if seconds < 0 {
		return 0
	}
	return int64(seconds)
}

func (b *OpenWrtBackend) readMemInfo() (uint64, uint64) {
	data := b.readTextFile(b.memInfoPath)
	if data == "" {
		return 0, 0
	}
	var total, free uint64
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = value
		case "MemAvailable:":
			free = value
		case "MemFree:":
			if free == 0 {
				free = value
			}
		}
	}
	return total, free
}

func (b *OpenWrtBackend) readIPv6Enabled() bool {
	raw := strings.TrimSpace(b.readTextFile(b.ipv6DisablePath))
	return raw != "1"
}

func (b *OpenWrtBackend) readTimeSettings(ctx context.Context) (bool, int, int) {
	ntpEnabled := parseOpenWrtBool(b.readUCIValue(ctx, "system", "timeserver", "enabled"), true)
	ntpServerEnabled := parseOpenWrtBool(b.readUCIValue(ctx, "system", "timeserver", "enable_server"), false)
	servers := b.readUCIList("system", "timeserver", "server")
	clientCount := len(servers)
	serverCount := 0
	if ntpServerEnabled {
		serverCount = 1
	}
	return ntpEnabled || ntpServerEnabled, clientCount, serverCount
}

func (b *OpenWrtBackend) readFirewallEnabled(ctx context.Context) bool {
	switch strings.TrimSpace(b.readUCIValue(ctx, "firewall", "defaults", "disabled")) {
	case "1", "true", "yes", "on":
		return false
	default:
		return true
	}
}

// appendFirewallFields walks /etc/config/firewall and projects every section
// into the TR-181 Device.Firewall.Chain.1.Rule.{i}.* table. We deliberately
// keep ONE chain (named "openwrt") because OpenWrt's UCI firewall doesn't
// expose internal iptables/nftables chains as a first-class concept — zones,
// forwardings, rules and redirects all live in the same flat config and feed
// the kernel chains the firewall script materialises at apply time.
//
// Mapping (UCI section → TR-181 Rule):
//
//	config defaults    → Device.Firewall.Config (global policy hint)
//	config zone        → Rule with Description="zone:<name>", target=input policy
//	config forwarding  → Rule with Description="fwd:<src>->dest", target=Accept
//	config rule        → Rule with full criteria (proto/src_ip/dest_port/...)
//	config redirect    → Rule with Description="redirect:<name>", target=TargetChain
//	config include     → skipped (script include, not a rule)
//
// The schema fields (`Target` enum, `Protocol` int, `IPVersion` int, port
// ranges, etc.) follow BBF TR-181 §Device.Firewall.Chain.{i}.Rule.{i}. exactly,
// so any TR-369 / USP controller that already understands TR-181 can read
// these without an OpenWrt-specific extension.
//
// Errors from the parser are non-fatal — a missing/unreadable file just
// produces no Rule rows so the existing Enable/Type fields stay coherent.
func (b *OpenWrtBackend) appendFirewallFields(msg *wusp.Message) {
	parsed, err := b.readUCIConfig("firewall")
	if err != nil {
		return
	}

	const chainPrefix = "Device.Firewall.Chain.1."
	defaultPolicy := ""
	rules := make([]openWrtFirewallRule, 0, len(parsed.Sections))

	for _, section := range parsed.Sections {
		switch section.Type {
		case "defaults":
			defaultPolicy = strings.ToUpper(strings.TrimSpace(section.Options["input"]))
		case "zone":
			name := firstNonEmpty(section.Options["name"], section.Name)
			rules = append(rules, openWrtFirewallRule{
				Description: "zone:" + name,
				Target:      mapFirewallTarget(section.Options["input"]),
				Enabled:     parseOpenWrtBool(section.Options["enabled"], true),
			})
		case "forwarding":
			src := strings.TrimSpace(section.Options["src"])
			dest := strings.TrimSpace(section.Options["dest"])
			rules = append(rules, openWrtFirewallRule{
				Description: "fwd:" + src + "->" + dest,
				Target:      "Accept",
				Enabled:     parseOpenWrtBool(section.Options["enabled"], true),
			})
		case "rule":
			rules = append(rules, openWrtRuleFromUCISection(section))
		case "redirect":
			name := firstNonEmpty(section.Options["name"], section.Name, "redirect")
			rules = append(rules, openWrtFirewallRule{
				Description: "redirect:" + name,
				Target:      "TargetChain", // NAT rather than a filter verdict
				Enabled:     parseOpenWrtBool(section.Options["enabled"], true),
				Protocol:    mapFirewallProtocol(section.Options["proto"]),
				DestPort:    parseFirewallPortLow(section.Options["src_dport"]),
				DestPortMax: parseFirewallPortHigh(section.Options["src_dport"]),
				IPVersion:   mapFirewallFamily(section.Options["family"]),
			})
		}
	}

	// Global firewall fields.
	if defaultPolicy != "" {
		appendField(msg, "Device.Firewall.Config", wusp.String(mapFirewallConfigLevel(defaultPolicy)))
	}
	appendField(msg, "Device.Firewall.ChainNumberOfEntries", wusp.Uint(1))

	// Single chain header.
	appendField(msg, chainPrefix+"Enable", wusp.Bool(true))
	appendField(msg, chainPrefix+"Name", wusp.String("openwrt"))
	appendField(msg, chainPrefix+"Creator", wusp.String("Defaults"))
	appendField(msg, chainPrefix+"RuleNumberOfEntries", wusp.Uint(uint64(len(rules))))

	for i, r := range rules {
		base := fmt.Sprintf("%sRule.%d.", chainPrefix, i+1)
		appendField(msg, base+"Enable", wusp.Bool(r.Enabled))
		status := "Enabled"
		if !r.Enabled {
			status = "Disabled"
		}
		appendField(msg, base+"Status", wusp.String(status))
		appendField(msg, base+"Order", wusp.String(strconv.Itoa(i+1)))
		if r.Description != "" {
			appendField(msg, base+"Description", wusp.String(r.Description))
		}
		if r.Target != "" {
			appendField(msg, base+"Target", wusp.String(r.Target))
		}
		appendField(msg, base+"Protocol", wusp.Int(int64(r.Protocol)))
		appendField(msg, base+"IPVersion", wusp.Int(int64(r.IPVersion)))
		if r.SourceIP != "" {
			appendField(msg, base+"SourceIP", wusp.String(r.SourceIP))
		}
		if r.SourceMask != "" {
			appendField(msg, base+"SourceMask", wusp.String(r.SourceMask))
		}
		if r.DestIP != "" {
			appendField(msg, base+"DestIP", wusp.String(r.DestIP))
		}
		if r.DestMask != "" {
			appendField(msg, base+"DestMask", wusp.String(r.DestMask))
		}
		if r.SourceMAC != "" {
			appendField(msg, base+"SourceMAC", wusp.String(r.SourceMAC))
		}
		appendField(msg, base+"SourcePort", wusp.Int(int64(r.SourcePort)))
		appendField(msg, base+"SourcePortRangeMax", wusp.Int(int64(r.SourcePortMax)))
		appendField(msg, base+"DestPort", wusp.Int(int64(r.DestPort)))
		appendField(msg, base+"DestPortRangeMax", wusp.Int(int64(r.DestPortMax)))
		appendField(msg, base+"Log", wusp.Bool(r.Log))
	}
}

// openWrtFirewallRule is the intermediate per-rule struct fed to TR-181
// emission. Defaults below match TR-181's "criterion not used" convention:
// -1 for numeric matchers, empty string for textual ones.
type openWrtFirewallRule struct {
	Description   string
	Target        string // TR-181 enum: Accept | Drop | Reject | Return | TargetChain
	Enabled       bool
	Protocol      int    // IANA protocol number, -1 = any
	IPVersion     int    // 4 | 6 | -1 = any
	SourceIP      string // bare address (no /mask)
	SourceMask    string // CIDR bits or dotted netmask
	DestIP        string
	DestMask      string
	SourceMAC     string
	SourcePort    int // -1 = any
	SourcePortMax int // -1 = single port
	DestPort      int
	DestPortMax   int
	Log           bool
}

func openWrtRuleFromUCISection(section openWrtUCISection) openWrtFirewallRule {
	srcIP, srcMask := splitFirewallCIDR(section.Options["src_ip"])
	dstIP, dstMask := splitFirewallCIDR(section.Options["dest_ip"])
	return openWrtFirewallRule{
		Description:   firstNonEmpty(section.Options["name"], section.Name),
		Target:        mapFirewallTarget(section.Options["target"]),
		Enabled:       parseOpenWrtBool(section.Options["enabled"], true),
		Protocol:      mapFirewallProtocol(section.Options["proto"]),
		IPVersion:     mapFirewallFamily(section.Options["family"]),
		SourceIP:      srcIP,
		SourceMask:    srcMask,
		DestIP:        dstIP,
		DestMask:      dstMask,
		SourceMAC:     strings.TrimSpace(section.Options["src_mac"]),
		SourcePort:    parseFirewallPortLow(section.Options["src_port"]),
		SourcePortMax: parseFirewallPortHigh(section.Options["src_port"]),
		DestPort:      parseFirewallPortLow(section.Options["dest_port"]),
		DestPortMax:   parseFirewallPortHigh(section.Options["dest_port"]),
		Log:           parseOpenWrtBool(section.Options["log"], false),
	}
}

// mapFirewallTarget canonicalises UCI's case-insensitive target strings to the
// TR-181 enum values listed in §Device.Firewall.Chain.{i}.Rule.{i}.Target.
func mapFirewallTarget(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "ACCEPT":
		return "Accept"
	case "DROP":
		return "Drop"
	case "REJECT":
		return "Reject"
	case "RETURN":
		return "Return"
	case "":
		return ""
	default:
		// User-defined chain name → TR-181 represents this with Target=TargetChain
		// and TargetChain set to the path. We don't have a path so leave Target
		// as TargetChain so the dashboard sees a non-empty value.
		return "TargetChain"
	}
}

// mapFirewallProtocol returns the IANA protocol number for a UCI `option proto`
// value. UCI accepts both names ("tcp", "udp", "icmp", ...) and numbers; we
// preserve numbers when given and fall back to -1 (= "any") for "all"/empty/
// unknown so the TR-181 ProtocolExclude convention (-1 = unused) holds.
//
// IANA Protocol Numbers Registry: https://www.iana.org/assignments/protocol-numbers/
func mapFirewallProtocol(raw string) int {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "", "all", "any":
		return -1
	case "icmp":
		return 1
	case "igmp":
		return 2
	case "tcp":
		return 6
	case "udp":
		return 17
	case "gre":
		return 47
	case "esp":
		return 50
	case "ah":
		return 51
	case "icmpv6", "ipv6-icmp":
		return 58
	case "ospf":
		return 89
	case "sctp":
		return 132
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 255 {
		return n
	}
	return -1
}

// mapFirewallFamily returns 4/6/-1 for UCI's `option family` field.
// TR-181 §IPVersion uses -1 to mean "any", matching the Min/Max bounds in the
// schema (Min=-1, Max=-1 in the gen file we saw — appears to be a TR-181
// quirk; we still use -1 to mean "any" for consistency with Protocol).
func mapFirewallFamily(raw string) int {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ipv4", "4":
		return 4
	case "ipv6", "6":
		return 6
	default:
		return -1
	}
}

// mapFirewallConfigLevel projects OpenWrt's defaults `input` policy to the
// TR-181 Device.Firewall.Config enum:
//
//	REJECT/DROP input → "High-Security" (default-deny)
//	ACCEPT input      → "Low-Security"  (default-allow)
//	disabled          → "Off"
//
// Anything else is treated as "Advanced" so the dashboard can still display
// something meaningful.
func mapFirewallConfigLevel(inputPolicy string) string {
	switch strings.ToUpper(strings.TrimSpace(inputPolicy)) {
	case "REJECT", "DROP":
		return "High-Security"
	case "ACCEPT":
		return "Low-Security"
	case "":
		return "Off"
	default:
		return "Advanced"
	}
}

// splitFirewallCIDR splits "192.168.1.0/24" into ("192.168.1.0", "24") and
// "fc00::/6" into ("fc00::", "6"). Bare addresses come back with empty mask.
func splitFirewallCIDR(raw string) (string, string) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", ""
	}
	if i := strings.Index(v, "/"); i > 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

// parseFirewallPortLow / parseFirewallPortHigh handle UCI's three port
// notations: "" → (-1, -1), "80" → (80, -1), "1000:2000" → (1000, 2000).
// Out-of-range or non-numeric values produce -1 so the TR-181 "criterion
// not used" convention holds.
func parseFirewallPortLow(raw string) int {
	v := strings.TrimSpace(raw)
	if v == "" {
		return -1
	}
	if i := strings.Index(v, ":"); i > 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return -1
	}
	return n
}

func parseFirewallPortHigh(raw string) int {
	v := strings.TrimSpace(raw)
	i := strings.Index(v, ":")
	if i < 0 {
		return -1
	}
	v = v[i+1:]
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return -1
	}
	return n
}

func (b *OpenWrtBackend) readInterfaceCount() int {
	if dump, err := b.readNetworkInterfaceDump(); err == nil {
		count := 0
		for _, iface := range dump.Interfaces {
			if strings.TrimSpace(iface.Interface) != "" {
				count++
			}
		}
		if count > 0 {
			return count
		}
	}

	entries, err := os.ReadDir(b.netClassDir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if strings.TrimSpace(entry.Name()) != "" {
			count++
		}
	}
	return count
}

func (b *OpenWrtBackend) readManufacturerOUI() string {
	entries, err := os.ReadDir(b.netClassDir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		address := strings.TrimSpace(b.readTextFile(filepath.Join(b.netClassDir, entry.Name(), "address")))
		if address == "" {
			continue
		}
		mac, err := net.ParseMAC(address)
		if err != nil || len(mac) < 3 {
			continue
		}
		if isZeroMAC(mac) {
			continue
		}
		return strings.ToUpper(fmt.Sprintf("%02X%02X%02X", mac[0], mac[1], mac[2]))
	}
	return ""
}

func (b *OpenWrtBackend) readUCIValue(ctx context.Context, config, section, option string) string {
	if value, ok := b.readUCIValueCLI(ctx, config, section, option); ok {
		return value
	}
	parsed, err := b.readUCIConfig(config)
	if err != nil {
		return ""
	}
	current := parsed.findSection(section)
	if current == nil {
		return ""
	}
	return strings.TrimSpace(current.Options[option])
}

func (b *OpenWrtBackend) readUCIList(config, section, option string) []string {
	parsed, err := b.readUCIConfig(config)
	if err != nil {
		return nil
	}
	current := parsed.findSection(section)
	if current == nil {
		return nil
	}
	if items := current.Lists[option]; len(items) > 0 {
		return append([]string(nil), items...)
	}
	if value := strings.TrimSpace(current.Options[option]); value != "" {
		return []string{value}
	}
	return nil
}

func (b *OpenWrtBackend) readUCIValueCLI(ctx context.Context, config, section, option string) (string, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	ref := b.resolveUCISectionRef(config, section)
	if ref == "" {
		return "", false
	}
	output, err := b.commandRunner(ctx, "uci", "-q", "get", fmt.Sprintf("%s.%s.%s", config, ref, option))
	if err != nil {
		return "", false
	}
	value := strings.Trim(strings.TrimSpace(string(output)), `'"`)
	if value == "" {
		return "", false
	}
	return value, true
}

func (b *OpenWrtBackend) resolveUCISectionRef(config, section string) string {
	if parsed, err := b.readUCIConfig(config); err == nil {
		if ref := parsed.sectionRef(section); ref != "" {
			return ref
		}
	}
	return fallbackUCISectionRef(section)
}

func (b *OpenWrtBackend) readUCIConfig(config string) (openWrtUCIConfig, error) {
	path := filepath.Join(b.uciConfigDir, config)
	data, err := os.ReadFile(path)
	if err != nil {
		return openWrtUCIConfig{}, err
	}

	var parsed openWrtUCIConfig
	var current *openWrtUCISection
	flush := func() {
		if current == nil {
			return
		}
		parsed.Sections = append(parsed.Sections, *current)
		current = nil
	}

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "config ") {
			flush()
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			current = &openWrtUCISection{
				Type:    strings.Trim(fields[1], `'"`),
				Options: make(map[string]string),
				Lists:   make(map[string][]string),
			}
			if len(fields) >= 3 {
				current.Name = strings.Trim(strings.Join(fields[2:], " "), `'"`)
			}
			continue
		}
		if current == nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, "option "):
			name, value, ok := parseUCIAssignment(line, "option")
			if ok {
				current.Options[name] = value
			}
		case strings.HasPrefix(line, "list "):
			name, value, ok := parseUCIAssignment(line, "list")
			if ok {
				current.Lists[name] = append(current.Lists[name], value)
			}
		}
	}
	flush()
	return parsed, nil
}

func parseUCIAssignment(line, prefix string) (string, string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != prefix {
		return "", "", false
	}
	name := strings.TrimSpace(fields[1])
	if name == "" {
		return "", "", false
	}
	value := strings.Trim(strings.Join(fields[2:], " "), `'"`)
	return name, value, true
}

func (cfg openWrtUCIConfig) findSection(section string) *openWrtUCISection {
	section = strings.TrimSpace(section)
	if section == "" {
		return nil
	}
	for i := range cfg.Sections {
		if cfg.Sections[i].Name == section {
			return &cfg.Sections[i]
		}
	}
	for i := range cfg.Sections {
		if cfg.Sections[i].Type == section {
			return &cfg.Sections[i]
		}
	}
	return nil
}

func (cfg openWrtUCIConfig) sectionRef(section string) string {
	section = strings.TrimSpace(section)
	if section == "" {
		return ""
	}

	typeCounts := make(map[string]int)
	for _, current := range cfg.Sections {
		idx := typeCounts[current.Type]
		typeCounts[current.Type] = idx + 1
		if current.Name == section {
			return current.Name
		}
		if current.Type == section {
			if current.Name != "" {
				return current.Name
			}
			return fmt.Sprintf("@%s[%d]", current.Type, idx)
		}
	}
	return ""
}

func fallbackUCISectionRef(section string) string {
	switch strings.TrimSpace(section) {
	case "system":
		return "@system[0]"
	case "defaults":
		return "@defaults[0]"
	case "timeserver":
		return "@timeserver[0]"
	default:
		return strings.TrimSpace(section)
	}
}

func parseOpenWrtBool(value string, defaultValue bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return defaultValue
	}
}

func wifiStatusValue(enabled, up bool) string {
	switch {
	case !enabled:
		return "Down"
	case up:
		return "Up"
	default:
		return "Dormant"
	}
}

func wifiInterfaceModeIsAP(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "ap", "mesh", "wrap", "wds_ap":
		return true
	default:
		return false
	}
}

func wifiInterfaceModeIsEndpoint(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "sta", "station", "client", "wds_sta":
		return true
	default:
		return false
	}
}

func wifiBandFromConfig(config map[string]any) string {
	value := strings.ToLower(firstNonEmpty(configString(config, "band"), configString(config, "hwmode")))
	switch {
	case strings.Contains(value, "6g"), strings.Contains(value, "11be"), strings.Contains(value, "11ax6"):
		return "6GHz"
	case strings.Contains(value, "60"):
		return "60GHz"
	case strings.Contains(value, "5"), strings.Contains(value, "11a"):
		return "5GHz"
	case strings.Contains(value, "2"), strings.Contains(value, "11g"), strings.Contains(value, "11b"):
		return "2.4GHz"
	default:
		return "Unknown"
	}
}

func wifiBandwidthFromConfig(config map[string]any) string {
	value := strings.ToUpper(strings.TrimSpace(configString(config, "htmode")))
	switch {
	case value == "":
		return "Unknown"
	case strings.Contains(value, "320"):
		return "320MHz"
	case strings.Contains(value, "160"):
		return "160MHz"
	case strings.Contains(value, "80"):
		return "80MHz"
	case strings.Contains(value, "40"):
		return "40MHz"
	case strings.Contains(value, "20"), strings.Contains(value, "NOHT"):
		return "20MHz"
	case strings.Contains(value, "AUTO"):
		return "Auto"
	default:
		return "Unknown"
	}
}

// ── WiFi capability discovery via sysfs ─────────────────────────────────────
//
// Reads hardware capabilities directly from the kernel's sysfs virtual
// filesystem — no external commands needed. Works on Linux 4.x+ with
// cfg80211/mac80211 drivers (including ath10k, ath11k, mt76, …).
//
// Key paths:
//   /sys/class/net/<ifname>/cfg80211_htcaps   → HT (802.11n) capability tags
//   /sys/class/net/<ifname>/cfg80211_vhtcaps  → VHT (802.11ac) capability tags
//   /sys/class/net/<ifname>/phy80211/name     → phy name (e.g. "phy0")
//   /sys/class/net/<ifname>/operstate         → "up" / "down"

// radioToIfname finds the first network interface belonging to a UCI radio section.
func (b *OpenWrtBackend) radioToIfname(section string) string {
	if data, err := b.ubusCaller("network.wireless", "status", b.ubusTimeout); err == nil {
		var radios map[string]openWrtWirelessRadioStatus
		if json.Unmarshal(data, &radios) == nil {
			if radio, ok := radios[section]; ok && len(radio.Interfaces) > 0 {
				return radio.Interfaces[0].IfName
			}
		}
	}
	// Fallback: scan sysfs for matching phy
	targetPhy := strings.Replace(section, "radio", "phy", 1)
	entries, _ := os.ReadDir(b.netClassDir)
	for _, entry := range entries {
		if data, err := os.ReadFile(b.netClassDir + "/" + entry.Name() + "/phy80211/name"); err == nil {
			if strings.TrimSpace(string(data)) == targetPhy {
				return entry.Name()
			}
		}
	}
	return ""
}

var netCtl = netctl.New()

// bandwidthToHTMode converts a TR-181 OperatingChannelBandwidth value to a UCI
// htmode by querying hardware capabilities via netctl and selecting the best match.
func bandwidthToHTMode(bw, section string, b *OpenWrtBackend, ctx context.Context) string {
	bw = strings.TrimSpace(bw)

	// Pass through raw htmode values
	upper := strings.ToUpper(bw)
	if strings.HasPrefix(upper, "HT") || strings.HasPrefix(upper, "VHT") ||
		strings.HasPrefix(upper, "HE") || strings.HasPrefix(upper, "EHT") {
		return upper
	}

	// Get supported modes via netctl (reads sysfs or nl80211)
	ifname := b.radioToIfname(section)
	var supported []string
	if ifname != "" {
		if caps, err := netCtl.WiFiGetCapabilities(ifname); err == nil {
			supported = caps.SupportedHTModes
		}
	}

	// Normalize: "Auto", "20MHz", "80MHz" → width string
	width := strings.ToLower(strings.TrimSuffix(bw, "MHz"))

	if width == "auto" {
		return pickBestAutoMode(supported)
	}
	return pickModeForWidth(supported, width)
}

// pickBestAutoMode selects the widest supported mode, preferring the newest
// generation (EHT > HE > VHT > HT). Caps at 80 MHz to avoid DFS issues.
func pickBestAutoMode(supported []string) string {
	type ranked struct {
		mode  string
		gen   int // 0=HT, 1=VHT, 2=HE, 3=EHT
		width int
	}

	var best ranked
	for _, mode := range supported {
		r := ranked{mode: mode}
		for _, p := range []struct {
			prefix string
			gen    int
		}{{"EHT", 3}, {"HE", 2}, {"VHT", 1}, {"HT", 0}} {
			if strings.HasPrefix(mode, p.prefix) {
				r.gen = p.gen
				r.width, _ = strconv.Atoi(strings.TrimPrefix(mode, p.prefix))
				break
			}
		}
		// Cap at 80 for auto to avoid DFS/compatibility issues
		ew := r.width
		if ew > 80 {
			ew = 80
		}
		bew := best.width
		if bew > 80 {
			bew = 80
		}
		if r.gen > best.gen || (r.gen == best.gen && ew > bew) {
			best = r
		}
	}

	if best.mode != "" {
		prefix := [4]string{"HT", "VHT", "HE", "EHT"}[best.gen]
		w := best.width
		if w > 80 {
			w = 80
		}
		return fmt.Sprintf("%s%d", prefix, w)
	}
	return "HT20"
}

// pickModeForWidth finds the best supported mode for a specific bandwidth width.
// Prefers newest generation (EHT > HE > VHT > HT).
func pickModeForWidth(supported []string, width string) string {
	for _, prefix := range []string{"EHT", "HE", "VHT", "HT"} {
		candidate := prefix + width
		for _, mode := range supported {
			if strings.EqualFold(mode, candidate) {
				return mode
			}
		}
	}
	if len(supported) == 0 {
		return "HT" + width
	}
	return supported[len(supported)-1] // widest/newest from the sorted list
}

func configString(config map[string]any, keys ...string) string {
	for _, key := range keys {
		raw, ok := config[key]
		if !ok || raw == nil {
			continue
		}
		switch value := raw.(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		case json.Number:
			return value.String()
		case float64:
			return strconv.FormatInt(int64(value), 10)
		case int:
			return strconv.Itoa(value)
		case bool:
			if value {
				return "1"
			}
			return "0"
		}
	}
	return ""
}

func configInt(config map[string]any, keys ...string) int {
	for _, key := range keys {
		raw, ok := config[key]
		if !ok || raw == nil {
			continue
		}
		switch value := raw.(type) {
		case float64:
			return int(value)
		case int:
			return value
		case json.Number:
			if parsed, err := strconv.Atoi(value.String()); err == nil {
				return parsed
			}
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func (b *OpenWrtBackend) readFileModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

func (b *OpenWrtBackend) readTextFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func guessOpenWrtManufacturer(board openWrtBoardInfo, release map[string]string, modelName string) string {
	if modelName != "" {
		if manufacturer := strings.Fields(modelName); len(manufacturer) > 0 {
			return manufacturer[0]
		}
	}
	return firstNonEmpty(release["DISTRIB_ID"], board.Release.Distribution, "OpenWrt")
}

func stringifyPrefixValue(value wusp.Value) (string, error) {
	switch value.Tag {
	case wusp.TagIP6Pfx:
		raw := value.AsBytes()
		if len(raw) != 17 {
			return "", &wusp.ValidationError{Reason: "invalid IPv6 prefix blob"}
		}
		mask := net.CIDRMask(int(raw[16]), 128)
		return (&net.IPNet{
			IP:   net.IP(append([]byte(nil), raw[:16]...)),
			Mask: mask,
		}).String(), nil
	case wusp.TagString:
		return value.AsString(), nil
	default:
		return "", &wusp.ValidationError{Reason: "unsupported prefix value type"}
	}
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func defaultOpenWrtCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}
