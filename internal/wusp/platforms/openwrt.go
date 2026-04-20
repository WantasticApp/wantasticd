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
	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/platforms/ubus"
)

type OpenWrtBackendOptions struct {
	UCIConfigDir          string
	StatePath             string
	HostnamePath          string
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
		statePath:             coalesceString(opts.StatePath, "/etc/wantastic/usp-openwrt.json"),
		hostnamePath:          coalesceString(opts.HostnamePath, "/proc/sys/kernel/hostname"),
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
	b.appendWiFiFields(msg)

	// Network interface details via getifaddrs (pure Go)
	collectNetworkInterfacesStatic(msg)
	collectCPUInfoStatic(ctx, b.commandRunner, msg)

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

func (b *OpenWrtBackend) setHostname(ctx context.Context, hostname string) error {
	if err := b.setUCIOption(ctx, "system", "@system[0]", "hostname", hostname, true, systemReloadScript); err != nil {
		return err
	}
	if _, err := b.commandRunner(ctx, "hostname", hostname); err != nil {
		return err
	}
	return nil
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
//   Device.WiFi.Radio.1.Enable        → wireless.radio0.disabled
//   Device.WiFi.Radio.1.Channel       → wireless.radio0.channel
//   Device.WiFi.SSID.1.SSID           → wireless.@wifi-iface[0].ssid
//   Device.WiFi.SSID.1.Enable         → wireless.@wifi-iface[0].disabled
//   Device.WiFi.AccessPoint.1.Enable  → wireless.@wifi-iface[0].disabled
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
			if value.AsBool() { disabled = "0" }
			return b.setUCIOption(ctx, "wireless", section, "disabled", disabled, true, wirelessReloadScript)
		case "Channel":
			return b.setUCIOption(ctx, "wireless", section, "channel", wusp.ValueToString(value), true, wirelessReloadScript)
		case "OperatingChannelBandwidth":
			return b.setUCIOption(ctx, "wireless", section, "htmode", wusp.ValueToString(value), true, wirelessReloadScript)
		}
	case "ssid", "ap":
		section := fmt.Sprintf("@wifi-iface[%d]", idx-1) // SSID.1 → @wifi-iface[0]
		switch param {
		case "SSID":
			return b.setUCIOption(ctx, "wireless", section, "ssid", value.AsString(), true, wirelessReloadScript)
		case "Enable":
			disabled := "1"
			if value.AsBool() { disabled = "0" }
			return b.setUCIOption(ctx, "wireless", section, "disabled", disabled, true, wirelessReloadScript)
		}
	}
	return wusp.ErrUSPPathUnsupported
}

func (b *OpenWrtBackend) setUCIOption(ctx context.Context, config, section, option, value string, commit bool, reloadScript string) error {
	if err := b.setUCIOptionViaUbus(ctx, config, section, option, value, commit); err == nil {
		return nil
	}

	key := fmt.Sprintf("%s.%s.%s=%s", config, section, option, value)
	if _, err := b.commandRunner(ctx, "uci", "set", key); err != nil {
		return err
	}
	if commit {
		if _, err := b.commandRunner(ctx, "uci", "commit", config); err != nil {
			return err
		}
	}
	return b.reloadScript(ctx, reloadScript)
}

func (b *OpenWrtBackend) deleteUCIOption(ctx context.Context, config, section, option string, commit bool, reloadScript string) error {
	if err := b.deleteUCIOptionViaUbus(ctx, config, section, option, commit); err == nil {
		return nil
	}

	key := fmt.Sprintf("%s.%s.%s", config, section, option)
	if _, err := b.commandRunner(ctx, "uci", "-q", "delete", key); err != nil {
		return err
	}
	if commit {
		if _, err := b.commandRunner(ctx, "uci", "commit", config); err != nil {
			return err
		}
	}
	return b.reloadScript(ctx, reloadScript)
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
	if err := os.MkdirAll(filepath.Dir(b.statePath), 0o755); err != nil {
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
