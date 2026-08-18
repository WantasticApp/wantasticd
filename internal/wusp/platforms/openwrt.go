package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/linkdiscovery"
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
	DHCPLeasesPath        string
	ARPPath               string
	UbusURL               string
	UbusSessionID         string
	UbusTimeout           time.Duration
	UbusCaller            func(string, string, time.Duration) ([]byte, error)
	UbusClient            *ubus.Client
	CommandRunner         func(context.Context, string, ...string) ([]byte, error)
	WiFiAssocList         func(string) ([]iwinfo.AssocEntry, error)
	WiFiInfo              func(string) (*iwinfo.InterfaceInfo, error)
	WiFiHWModeList        func(string) (*iwinfo.HWModes, error)
	WiFiHTModeList        func(string) ([]string, error)
	WiFiTxPowerLevels     func(context.Context, string) []int
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
	dhcpLeasesPath        string
	arpPath               string
	ubusClient            *ubus.Client
	ubusTimeout           time.Duration
	ubusCaller            func(string, string, time.Duration) ([]byte, error)
	ubusCallerInjected    bool
	commandRunner         func(context.Context, string, ...string) ([]byte, error)
	wifiAssocList         func(string) ([]iwinfo.AssocEntry, error)
	wifiInfo              func(string) (*iwinfo.InterfaceInfo, error)
	wifiHWModeList        func(string) (*iwinfo.HWModes, error)
	wifiHTModeList        func(string) ([]string, error)
	wifiTxPowerLevels     func(context.Context, string) []int
	cellular              *cellularMonitor
	now                   func() time.Time
}

func (b *OpenWrtBackend) Warmup(ctx context.Context) error {
	linkdiscovery.StartDefault()
	if b == nil || b.cellular == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		b.cellular.refresh()
		b.cellular.start()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (b *OpenWrtBackend) callUbus(ctx context.Context, object, method string, params map[string]any) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("nil OpenWrt backend")
	}
	if b.ubusCaller != nil && (len(params) == 0 || b.ubusCallerInjected) {
		return b.ubusCaller(object, method, b.ubusTimeout)
	}
	if b.ubusClient == nil {
		return nil, fmt.Errorf("ubus unavailable")
	}
	return b.ubusClient.Call(ctx, object, method, params, b.ubusTimeout)
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
	MAC           string  `json:"mac"`
	RSSI          *int    `json:"rssi"`
	Noise         *int    `json:"noise"`
	Iface         string  `json:"iface"`
	Inactive      *uint32 `json:"inactive"`
	ConnectedTime *uint32 `json:"connected_time"`
	RxPackets     *uint32 `json:"rx_packets"`
	TxPackets     *uint32 `json:"tx_packets"`
	RxBytes       *uint64 `json:"rx_bytes"`
	TxBytes       *uint64 `json:"tx_bytes"`
	TxRetries     *uint32 `json:"tx_retries"`
	TxFailed      *uint32 `json:"tx_failed"`
	RxRate        *uint32 `json:"rx_rate"`
	TxRate        *uint32 `json:"tx_rate"`
}

type openWrtIWInfoCapabilities struct {
	HWModes []string `json:"hwmodes"`
	HTModes []string `json:"htmodes"`
}

// openWrtHostapdClients is the stock OpenWrt hostapd.<ifname>.get_clients
// response. Unlike the vendor-specific device.getStaList call, this object is
// supplied by wpad/hostapd on normal OpenWrt access points.
type openWrtHostapdClients struct {
	Frequency int `json:"freq"`
	Clients   map[string]struct {
		Auth       *bool `json:"auth"`
		Assoc      *bool `json:"assoc"`
		Authorized *bool `json:"authorized"`
		HT         bool  `json:"ht"`
		VHT        bool  `json:"vht"`
		HE         bool  `json:"he"`
		EHT        bool  `json:"eht"`
		Signal     *int  `json:"signal"`
		Bytes      struct {
			RX *uint64 `json:"rx"`
			TX *uint64 `json:"tx"`
		} `json:"bytes"`
		Packets struct {
			RX *uint32 `json:"rx"`
			TX *uint32 `json:"tx"`
		} `json:"packets"`
		Rate struct {
			RX *uint32 `json:"rx"`
			TX *uint32 `json:"tx"`
		} `json:"rate"`
	} `json:"clients"`
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
		dhcpLeasesPath:        coalesceString(opts.DHCPLeasesPath, "/tmp/dhcp.leases"),
		arpPath:               coalesceString(opts.ARPPath, "/proc/net/arp"),
		ubusClient:            opts.UbusClient,
		ubusTimeout:           opts.UbusTimeout,
		ubusCaller:            opts.UbusCaller,
		ubusCallerInjected:    opts.UbusCaller != nil,
		commandRunner:         opts.CommandRunner,
		wifiAssocList:         opts.WiFiAssocList,
		wifiInfo:              opts.WiFiInfo,
		wifiHWModeList:        opts.WiFiHWModeList,
		wifiHTModeList:        opts.WiFiHTModeList,
		wifiTxPowerLevels:     opts.WiFiTxPowerLevels,
		cellular:              newCellularMonitor(),
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
	if backend.wifiAssocList == nil {
		backend.wifiAssocList = iwinfo.GetAssocList
	}
	if backend.wifiInfo == nil {
		backend.wifiInfo = iwinfo.GetInfo
	}
	if backend.wifiHWModeList == nil {
		backend.wifiHWModeList = iwinfo.GetHWModeList
	}
	if backend.wifiHTModeList == nil {
		backend.wifiHTModeList = iwinfo.GetHTModeList
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
		if err := b.setOpenWrtCellularParam(ctx, path, value); err != wusp.ErrUSPPathUnsupported {
			return err
		}
		if err := b.setOpenWrtMeshParam(ctx, path, value); err != wusp.ErrUSPPathUnsupported {
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
	linkdiscovery.StartDefault()
	var snapshot openWrtSnapshot
	_ = runCollector("openwrt.snapshot", func() error {
		snapshot = b.collectSnapshot(ctx)
		return nil
	})

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
	_ = runCollector("openwrt.firewall", func() error { b.appendFirewallFields(msg); return nil })
	_ = runCollector("openwrt.wifi", func() error { b.appendWiFiFields(ctx, msg); return nil })

	// Network interface details via getifaddrs (pure Go)
	_ = runCollector("openwrt.network.interfaces", func() error { collectNetworkInterfacesStatic(msg, b.netClassDir); return nil })
	_ = runCollector("openwrt.cpu", func() error { collectCPUInfoStatic(ctx, b.commandRunner, msg); return nil })
	_ = runCollector("openwrt.cellular.runtime", func() error {
		if b.cellular != nil {
			collectCellularSnapshot(msg, b.cellular.snapshot())
		} else {
			collectCellularStatic(msg)
		}
		return nil
	})
	_ = runCollector("openwrt.cellular.config", func() error { b.appendOpenWrtCellularConfig(msg); return nil })
	_ = runCollector("openwrt.gnss", func() error { collectGPSStatic(msg); return nil })
	_ = runCollector("openwrt.mesh.runtime", func() error { collectMeshStatic(msg); return nil })
	_ = runCollector("openwrt.mesh.topology", func() error { b.appendOpenWrtMeshTopology(ctx, msg); return nil })
	_ = runCollector("openwrt.mesh.config", func() error { b.appendOpenWrtMeshConfig(ctx, msg); return nil })
	_ = runCollector("openwrt.link.discovery", func() error {
		appendLinkDiscoveryFields(msg, linkdiscovery.DefaultSnapshot(), b.openWrtWiFiInterfaceSet())
		return nil
	})
	_ = runCollector("openwrt.wifi.scan", func() error { return appendWiFiScanFields(msg) })

	return msg, nil
}

func appendField(msg *wusp.Message, path string, value wusp.Value) {
	if path = strings.TrimSpace(path); path == "" {
		return
	}
	msg.Set(path, value)
}

func (b *OpenWrtBackend) collectSnapshot(ctx context.Context) openWrtSnapshot {
	state, stateErr := b.readState()
	logCollectorError("openwrt.state", stateErr)
	board, boardErr := b.readBoardInfo()
	logCollectorError("openwrt.board", boardErr)
	release := b.readReleaseInfo()
	systemInfo, systemErr := b.readSystemInfo()
	logCollectorError("openwrt.system", systemErr)

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

func (b *OpenWrtBackend) appendWiFiFields(ctx context.Context, msg *wusp.Message) {
	radios := b.openWrtWirelessRadios()

	radioKeys := make([]string, 0, len(radios))
	for key := range radios {
		if strings.TrimSpace(key) != "" {
			radioKeys = append(radioKeys, key)
		}
	}
	sort.Strings(radioKeys)

	ubusStations, ubusStationsErr := b.readWiFiStations()
	defer iwinfo.Close()

	ssidCount := 0
	apCount := 0
	endPointCount := 0
	radioIndexByName := make(map[string]int, len(radioKeys))
	wifiHosts := make(map[string]string)

	for i, key := range radioKeys {
		radio := radios[key]
		radioIndex := i + 1
		radioIndexByName[key] = radioIndex
		radioEnabled := !radio.Disabled && !parseOpenWrtBool(configString(radio.Config, "disabled"), false)

		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.Enable", radioIndex), wusp.Bool(radioEnabled))
		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.Status", radioIndex), wusp.String(wifiStatusValue(radioEnabled, radio.Up)))
		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.Name", radioIndex), wusp.String(key))
		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.OperatingFrequencyBand", radioIndex), wusp.String(wifiBandFromConfig(radio.Config)))
		channelValue := strings.TrimSpace(configString(radio.Config, "channel"))
		if channel := configInt(radio.Config, "channel"); channel > 0 {
			appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.Channel", radioIndex), wusp.Uint(uint64(channel)))
		}
		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.AutoChannelSupported", radioIndex), wusp.Bool(true))
		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.AutoChannelEnable", radioIndex), wusp.Bool(strings.EqualFold(channelValue, "auto")))
		bandwidth := wifiBandwidthFromConfig(radio.Config)
		appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.OperatingChannelBandwidth", radioIndex), wusp.String(bandwidth))
		if bandwidth != "Unknown" && bandwidth != "Auto" {
			appendField(msg, fmt.Sprintf("Device.WiFi.Radio.%d.CurrentOperatingChannelBandwidth", radioIndex), wusp.String(bandwidth))
		}
		radioIfName := ""
		for _, iface := range radio.Interfaces {
			if radioIfName = strings.TrimSpace(iface.IfName); radioIfName != "" {
				break
			}
		}
		b.appendWiFiRadioCapabilities(ctx, msg, key, radioIfName, radioIndex, radio.Config)

		interfaces := append([]openWrtWirelessIfaceStatus(nil), radio.Interfaces...)
		sort.SliceStable(interfaces, func(i, j int) bool {
			left := firstNonEmpty(interfaces[i].Section, interfaces[i].IfName)
			right := firstNonEmpty(interfaces[j].Section, interfaces[j].IfName)
			return left < right
		})

		for _, iface := range interfaces {
			ssidCount++
			ssidPath := fmt.Sprintf("Device.WiFi.SSID.%d.", ssidCount)

			ifName := firstNonEmpty(iface.IfName, b.existingWiFiIfName(configString(iface.Config, "ifname")))
			mode := strings.ToLower(firstNonEmpty(configString(iface.Config, "mode"), "ap"))
			ssidEnabled := !parseOpenWrtBool(configString(iface.Config, "disabled"), false)
			ssidValue := configString(iface.Config, "ssid")
			bssidValue := ""

			if ifName != "" && b.wifiInfo != nil {
				if info, err := b.wifiInfo(ifName); err == nil {
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
			appendField(msg, ssidPath+"LowerLayers", wusp.List(wusp.String(fmt.Sprintf("Device.WiFi.Radio.%d.", radioIndex))))
			if mac, err := net.ParseMAC(bssidValue); err == nil && len(mac) == 6 {
				appendField(msg, ssidPath+"BSSID", wusp.MAC(mac))
			}

			if wifiInterfaceModeIsAP(mode) {
				apCount++
				apPath := fmt.Sprintf("Device.WiFi.AccessPoint.%d.", apCount)
				appendField(msg, apPath+"Enable", wusp.Bool(ssidEnabled))
				appendField(msg, apPath+"Status", wusp.String(wifiAccessPointStatusValue(ssidEnabled, iface.Up)))
				appendField(msg, apPath+"SSIDReference", wusp.String(ssidPath))
				// Stock OpenWrt exposes clients through hostapd.<ifname>.get_clients.
				// Merge it with the optional vendor call and the direct nl80211/
				// libiwinfo collector so each source fills the fields it knows.
				stations := append([]iwinfo.AssocEntry(nil), ubusStations[ifName]...)
				succeeded := ubusStationsErr == nil
				errorsBySource := make([]string, 0, 4)
				if ubusStationsErr != nil {
					errorsBySource = append(errorsBySource, "device.getStaList: "+ubusStationsErr.Error())
				}
				for _, source := range []struct {
					name string
					read func(string) ([]iwinfo.AssocEntry, error)
				}{
					{name: "hostapd", read: b.readHostapdAssociations},
					{name: "iwinfo-ubus", read: b.readIWInfoUBusAssociations},
					{name: "nl80211", read: b.readIWInfoAssociations},
				} {
					observed, err := source.read(ifName)
					if err != nil {
						errorsBySource = append(errorsBySource, source.name+": "+err.Error())
						continue
					}
					succeeded = true
					stations = mergeWiFiAssociations(stations, observed)
				}
				if succeeded {
					appendField(msg, apPath+"AssociatedDeviceNumberOfEntries", wusp.Uint(uint64(len(stations))))
					for stationIndex, station := range stations {
						stationPath := fmt.Sprintf("%sAssociatedDevice.%d.", apPath, stationIndex+1)
						b.appendWiFiAssociatedDeviceFields(msg, stationPath, station)
						wifiHosts[strings.ToLower(station.MAC.String())] = stationPath
					}
				}
				log.Printf("[USP] wifi_collection_summary interface=%q sources_attempted=%q successful=%t selected_station_count=%d errors=%q",
					ifName, "device.getStaList,hostapd,iwinfo-ubus,nl80211", succeeded, len(stations), strings.Join(errorsBySource, "; "))
			} else if wifiInterfaceModeIsEndpoint(mode) {
				endPointCount++
			}
		}
	}

	appendField(msg, "Device.WiFi.RadioNumberOfEntries", wusp.Uint(uint64(len(radioKeys))))
	appendField(msg, "Device.WiFi.SSIDNumberOfEntries", wusp.Uint(uint64(ssidCount)))
	appendField(msg, "Device.WiFi.AccessPointNumberOfEntries", wusp.Uint(uint64(apCount)))
	appendField(msg, "Device.WiFi.EndPointNumberOfEntries", wusp.Uint(uint64(endPointCount)))
	b.appendHostFields(msg, wifiHosts)
}

func (b *OpenWrtBackend) readIWInfoAssociations(ifName string) ([]iwinfo.AssocEntry, error) {
	if strings.TrimSpace(ifName) == "" || b.wifiAssocList == nil {
		return nil, fmt.Errorf("missing runtime interface")
	}
	associations, err := b.wifiAssocList(ifName)
	if err != nil {
		return nil, err
	}
	if len(associations) == 0 {
		return associations, nil
	}
	// nl80211 station dumps do not carry per-station noise. The in-use channel
	// survey is the correct available radio-level fallback for SNR reporting.
	noise := int8(0)
	if survey, surveyErr := iwinfo.GetSurvey(ifName); surveyErr == nil {
		for _, entry := range survey {
			if entry.InUse && entry.Noise < 0 {
				noise = entry.Noise
				break
			}
		}
		if noise == 0 {
			for _, entry := range survey {
				if entry.Noise < 0 {
					noise = entry.Noise
					break
				}
			}
		}
	}
	if noise < 0 {
		for index := range associations {
			if !associations[index].NoiseKnown && associations[index].Noise == 0 {
				associations[index].Noise = noise
				associations[index].NoiseKnown = true
			}
		}
	}
	return associations, nil
}

func (b *OpenWrtBackend) readHostapdAssociations(ifName string) ([]iwinfo.AssocEntry, error) {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" {
		return nil, fmt.Errorf("missing runtime interface")
	}
	stations, socketErr := iwinfo.GetHostapdAssocList(ifName)
	if socketErr == nil {
		return stations, nil
	}
	data, err := b.callUbus(context.Background(), "hostapd."+ifName, "get_clients", nil)
	var payload openWrtHostapdClients
	if err == nil {
		err = json.Unmarshal(data, &payload)
		if err == nil && payload.Clients != nil {
			return associationsFromHostapdPayload(payload), nil
		}
	}
	if err == nil {
		err = fmt.Errorf("hostapd returned no clients object")
	}
	return nil, fmt.Errorf("hostapd socket: %v; ubus: %w", socketErr, err)
}

func associationsFromHostapdPayload(payload openWrtHostapdClients) []iwinfo.AssocEntry {
	stations := make([]iwinfo.AssocEntry, 0, len(payload.Clients))
	for macText, client := range payload.Clients {
		// hostapd can briefly retain authenticated-but-not-associated peers.
		if client.Assoc != nil && !*client.Assoc {
			continue
		}
		mac := validClientMAC(macText)
		if mac == nil {
			continue
		}
		authenticated, authenticationKnown := true, false
		if client.Authorized != nil {
			authenticated = *client.Authorized
			authenticationKnown = true
		} else if client.Auth != nil {
			authenticated = *client.Auth
			authenticationKnown = true
		}
		entry := iwinfo.AssocEntry{
			MAC:                 mac,
			AuthenticationKnown: authenticationKnown,
			Authenticated:       authenticated,
			OperatingStandard:   hostapdOperatingStandard(client.HT, client.VHT, client.HE, client.EHT, payload.Frequency),
		}
		if client.Signal != nil {
			entry.Signal, entry.SignalKnown = boundedWiFiDBM(*client.Signal), true
		}
		if client.Packets.RX != nil {
			entry.RxPackets, entry.RxPacketsKnown = *client.Packets.RX, true
		}
		if client.Packets.TX != nil {
			entry.TxPackets, entry.TxPacketsKnown = *client.Packets.TX, true
		}
		if client.Bytes.RX != nil {
			entry.RxBytes, entry.RxBytesKnown = *client.Bytes.RX, true
		}
		if client.Bytes.TX != nil {
			entry.TxBytes, entry.TxBytesKnown = *client.Bytes.TX, true
		}
		if client.Rate.RX != nil {
			entry.RxRate, entry.RxRateKnown = *client.Rate.RX, true
		}
		if client.Rate.TX != nil {
			entry.TxRate, entry.TxRateKnown = *client.Rate.TX, true
		}
		stations = append(stations, entry)
	}
	return stations
}

// readIWInfoUBusAssociations uses rpcd-mod-iwinfo when installed. It is an
// optional enrichment source; stock wpad hostapd and direct nl80211 remain the
// dependency-free paths.
func (b *OpenWrtBackend) readIWInfoUBusAssociations(ifName string) ([]iwinfo.AssocEntry, error) {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" {
		return nil, fmt.Errorf("iwinfo ubus unavailable")
	}
	data, err := b.callUbus(context.Background(), "iwinfo", "assoclist", map[string]any{"device": ifName})
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty iwinfo ubus response")
	}
	stations, decodeErr := decodeIWInfoAssociationsKnown(data)
	return stations, decodeErr
}

func decodeIWInfoAssociations(data []byte) []iwinfo.AssocEntry {
	stations, _ := decodeIWInfoAssociationsKnown(data)
	return stations
}

func decodeIWInfoAssociationsKnown(data []byte) ([]iwinfo.AssocEntry, error) {
	var payload map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	rawResults, ok := payload["results"].([]any)
	if !ok {
		rawResults, _ = payload["assoclist"].([]any)
	}
	if rawResults == nil {
		return nil, fmt.Errorf("missing iwinfo association results")
	}
	entries := make([]iwinfo.AssocEntry, 0, len(rawResults))
	for _, raw := range rawResults {
		result, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		mac := validClientMAC(configString(result, "mac", "bssid"))
		if mac == nil {
			continue
		}
		entry := iwinfo.AssocEntry{MAC: mac}
		if value, present := configIntKnown(result, "signal"); present {
			entry.Signal, entry.SignalKnown = boundedWiFiDBM(value), true
		}
		if value, present := configIntKnown(result, "signal_avg"); present {
			entry.SignalAvg, entry.SignalAvgKnown = boundedWiFiDBM(value), true
		}
		if value, present := configIntKnown(result, "noise"); present {
			entry.Noise, entry.NoiseKnown = boundedWiFiDBM(value), true
		}
		entry.Inactive, entry.InactiveKnown = configUint32Known(result, "inactive")
		entry.ConnectedTime, entry.ConnectedTimeKnown = configUint32Known(result, "connected_time")
		entry.RxBytes, entry.RxBytesKnown = configNestedUint64Known(result, "rx", "bytes", "rx_bytes")
		entry.TxBytes, entry.TxBytesKnown = configNestedUint64Known(result, "tx", "bytes", "tx_bytes")
		entry.RxPackets, entry.RxPacketsKnown = configNestedUint32Known(result, "rx", "packets", "rx_packets")
		entry.TxPackets, entry.TxPacketsKnown = configNestedUint32Known(result, "tx", "packets", "tx_packets")
		entry.RxRate, entry.RxRateKnown = configNestedUint32Known(result, "rx", "rate", "rx_rate")
		entry.TxRate, entry.TxRateKnown = configNestedUint32Known(result, "tx", "rate", "tx_rate")
		entry.TxRetries, entry.TxRetriesKnown = configNestedUint32Known(result, "tx", "retries", "tx_retries")
		entry.TxFailed, entry.TxFailedKnown = configNestedUint32Known(result, "tx", "failed", "tx_failed")
		if value, present := result["authorized"]; present {
			entry.AuthenticationKnown = true
			entry.Authenticated = configAnyBool(value)
		} else if value, present := result["authenticated"]; present {
			entry.AuthenticationKnown = true
			entry.Authenticated = configAnyBool(value)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func configIntKnown(config map[string]any, key string) (int, bool) {
	value, ok := config[key]
	if !ok || value == nil {
		return 0, false
	}
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseInt(typed.String(), 10, 64)
		return int(parsed), err == nil
	case float64:
		return int(typed), true
	case int:
		return typed, true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func configUint64Known(config map[string]any, key string) (uint64, bool) {
	value, ok := configIntKnown(config, key)
	if !ok || value < 0 {
		return 0, false
	}
	return uint64(value), true
}

func configUint32Known(config map[string]any, key string) (uint32, bool) {
	value, ok := configUint64Known(config, key)
	if !ok {
		return 0, false
	}
	if value > uint64(^uint32(0)) {
		return ^uint32(0), true
	}
	return uint32(value), true
}

func configNestedUint64Known(config map[string]any, object, key, flat string) (uint64, bool) {
	if nested, ok := config[object].(map[string]any); ok {
		if value, present := configUint64Known(nested, key); present {
			return value, true
		}
	}
	return configUint64Known(config, flat)
}

func configNestedUint32Known(config map[string]any, object, key, flat string) (uint32, bool) {
	value, ok := configNestedUint64Known(config, object, key, flat)
	if !ok {
		return 0, false
	}
	if value > uint64(^uint32(0)) {
		return ^uint32(0), true
	}
	return uint32(value), true
}

func configAnyBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return parseOpenWrtBool(typed, false)
	case json.Number:
		return typed.String() != "0"
	case float64:
		return typed != 0
	default:
		return false
	}
}

func boundedWiFiDBM(value int) int8 {
	if value < -128 {
		return -128
	}
	if value > 0 {
		return 0
	}
	return int8(value)
}

func hostapdOperatingStandard(ht, vht, he, eht bool, frequency int) string {
	switch {
	case eht:
		return "be"
	case he:
		return "ax"
	case vht:
		return "ac"
	case ht:
		return "n"
	case frequency >= 4900:
		return "a"
	case frequency > 0:
		return "g"
	default:
		return ""
	}
}

func mergeWiFiAssociations(primary, detailed []iwinfo.AssocEntry) []iwinfo.AssocEntry {
	byMAC := make(map[string]iwinfo.AssocEntry, len(primary)+len(detailed))
	merge := func(station iwinfo.AssocEntry, prefer bool) {
		if len(station.MAC) != 6 || station.MAC[0]&1 != 0 {
			return
		}
		key := strings.ToLower(station.MAC.String())
		existing, found := byMAC[key]
		if !found {
			byMAC[key] = station
			return
		}
		if prefer {
			if station.OperatingStandard == "" {
				station.OperatingStandard = existing.OperatingStandard
			}
			if !station.AuthenticationKnown {
				station.AuthenticationKnown = existing.AuthenticationKnown
				station.Authenticated = existing.Authenticated
			}
			if !assocSignedKnown(station.SignalAvgKnown, station.SignalAvg) {
				station.SignalAvg = existing.SignalAvg
				station.SignalAvgKnown = existing.SignalAvgKnown
			}
			if !assocSignedKnown(station.SignalKnown, station.Signal) {
				station.Signal = existing.Signal
				station.SignalKnown = existing.SignalKnown
			}
			if !assocSignedKnown(station.NoiseKnown, station.Noise) {
				station.Noise = existing.Noise
				station.NoiseKnown = existing.NoiseKnown
			}
			if !assocUint32Known(station.InactiveKnown, station.Inactive) {
				station.Inactive = existing.Inactive
				station.InactiveKnown = existing.InactiveKnown
			}
			if !assocUint32Known(station.ConnectedTimeKnown, station.ConnectedTime) {
				station.ConnectedTime = existing.ConnectedTime
				station.ConnectedTimeKnown = existing.ConnectedTimeKnown
			}
			if !assocUint32Known(station.RxPacketsKnown, station.RxPackets) {
				station.RxPackets = existing.RxPackets
				station.RxPacketsKnown = existing.RxPacketsKnown
			}
			if !assocUint32Known(station.TxPacketsKnown, station.TxPackets) {
				station.TxPackets = existing.TxPackets
				station.TxPacketsKnown = existing.TxPacketsKnown
			}
			if !assocUint64Known(station.RxBytesKnown, station.RxBytes) {
				station.RxBytes = existing.RxBytes
				station.RxBytesKnown = existing.RxBytesKnown
			}
			if !assocUint64Known(station.TxBytesKnown, station.TxBytes) {
				station.TxBytes = existing.TxBytes
				station.TxBytesKnown = existing.TxBytesKnown
			}
			if !assocUint32Known(station.TxRetriesKnown, station.TxRetries) {
				station.TxRetries = existing.TxRetries
				station.TxRetriesKnown = existing.TxRetriesKnown
			}
			if !assocUint32Known(station.TxFailedKnown, station.TxFailed) {
				station.TxFailed = existing.TxFailed
				station.TxFailedKnown = existing.TxFailedKnown
			}
			if !assocUint32Known(station.RxRateKnown, station.RxRate) {
				station.RxRate = existing.RxRate
				station.RxRateKnown = existing.RxRateKnown
			}
			if !assocUint32Known(station.TxRateKnown, station.TxRate) {
				station.TxRate = existing.TxRate
				station.TxRateKnown = existing.TxRateKnown
			}
			if station.RxMCS == 0 {
				station.RxMCS = existing.RxMCS
			}
			if station.TxMCS == 0 {
				station.TxMCS = existing.TxMCS
			}
			if station.RxNSS == 0 {
				station.RxNSS = existing.RxNSS
			}
			if station.TxNSS == 0 {
				station.TxNSS = existing.TxNSS
			}
			byMAC[key] = station
		}
	}
	for _, station := range primary {
		merge(station, false)
	}
	for _, station := range detailed {
		merge(station, true)
	}
	out := make([]iwinfo.AssocEntry, 0, len(byMAC))
	for _, station := range byMAC {
		out = append(out, station)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Compare(out[i].MAC.String(), out[j].MAC.String()) < 0
	})
	return out
}

func assocSignedKnown(known bool, value int8) bool   { return known || value != 0 }
func assocUint32Known(known bool, value uint32) bool { return known || value != 0 }
func assocUint64Known(known bool, value uint64) bool { return known || value != 0 }

func (b *OpenWrtBackend) appendWiFiAssociatedDeviceFields(msg *wusp.Message, path string, station iwinfo.AssocEntry) {
	appendWiFiAssociatedDeviceFields(msg, path, station, b.now())
}

func appendWiFiAssociatedDeviceFields(msg *wusp.Message, path string, station iwinfo.AssocEntry, now time.Time) {
	appendField(msg, path+"MACAddress", wusp.MAC(station.MAC))
	if station.OperatingStandard != "" {
		appendField(msg, path+"OperatingStandard", wusp.String(station.OperatingStandard))
	}
	if station.AuthenticationKnown {
		appendField(msg, path+"AuthenticationState", wusp.Bool(station.Authenticated))
	}
	appendField(msg, path+"Active", wusp.Bool(true))
	if assocUint32Known(station.TxRateKnown, station.TxRate) {
		appendField(msg, path+"LastDataDownlinkRate", wusp.Uint(uint64(station.TxRate)))
	}
	if assocUint32Known(station.RxRateKnown, station.RxRate) {
		appendField(msg, path+"LastDataUplinkRate", wusp.Uint(uint64(station.RxRate)))
	}
	if assocUint32Known(station.ConnectedTimeKnown, station.ConnectedTime) {
		appendField(msg, path+"AssociationTime", wusp.Time(now.UTC().Add(-time.Duration(station.ConnectedTime)*time.Second)))
	}
	signal := station.SignalAvg
	signalKnown := assocSignedKnown(station.SignalAvgKnown, station.SignalAvg)
	if !signalKnown || signal >= 0 {
		signal = station.Signal
		signalKnown = assocSignedKnown(station.SignalKnown, station.Signal)
	}
	if signalKnown && signal < 0 {
		appendField(msg, path+"SignalStrength", wusp.Int(int64(signal)))
	}
	if assocSignedKnown(station.NoiseKnown, station.Noise) && station.Noise < 0 {
		appendField(msg, path+"Noise", wusp.Int(int64(station.Noise)))
		if signalKnown && signal < 0 && signal >= station.Noise {
			appendField(msg, path+"SNR", wusp.Uint(uint64(int(signal)-int(station.Noise))))
		}
	}
	if assocUint64Known(station.TxBytesKnown, station.TxBytes) {
		appendField(msg, path+"Stats.BytesSent", wusp.Uint(station.TxBytes))
	}
	if assocUint64Known(station.RxBytesKnown, station.RxBytes) {
		appendField(msg, path+"Stats.BytesReceived", wusp.Uint(station.RxBytes))
	}
	if assocUint32Known(station.TxPacketsKnown, station.TxPackets) {
		appendField(msg, path+"Stats.PacketsSent", wusp.Uint(uint64(station.TxPackets)))
	}
	if assocUint32Known(station.RxPacketsKnown, station.RxPackets) {
		appendField(msg, path+"Stats.PacketsReceived", wusp.Uint(uint64(station.RxPackets)))
	}
	if assocUint32Known(station.TxFailedKnown, station.TxFailed) {
		appendField(msg, path+"Stats.ErrorsSent", wusp.Uint(uint64(station.TxFailed)))
		appendField(msg, path+"Stats.FailedRetransCount", wusp.Uint(uint64(station.TxFailed)))
	}
	if assocUint32Known(station.TxRetriesKnown, station.TxRetries) {
		appendField(msg, path+"Stats.RetransCount", wusp.Uint(uint64(station.TxRetries)))
	}
}

type openWrtLANHost struct {
	mac                net.HardwareAddr
	hostname           string
	interfaceName      string
	interfaceType      string
	associatedDevice   string
	layer3Interface    string
	addressSource      string
	leaseTimeRemaining int64
	active             bool
	ipv4               []net.IP
	ipv6               []net.IP
}

func validClientMAC(value string) net.HardwareAddr {
	mac, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return nil
	}
	allZero, allBroadcast := true, true
	for _, octet := range mac {
		allZero = allZero && octet == 0
		allBroadcast = allBroadcast && octet == 0xff
	}
	if allZero || allBroadcast {
		return nil
	}
	return mac
}

func addHostIP(host *openWrtLANHost, value string) {
	if host == nil {
		return
	}
	ip := net.ParseIP(strings.TrimSpace(strings.Split(value, "%")[0]))
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return
	}
	target := &host.ipv6
	if ip.To4() != nil {
		ip = ip.To4()
		target = &host.ipv4
	}
	for _, existing := range *target {
		if existing.Equal(ip) {
			return
		}
	}
	*target = append(*target, ip)
}

func hostInterfaceType(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.HasPrefix(name, "wlan"), strings.HasPrefix(name, "phy"):
		return "Wi-Fi"
	case strings.HasPrefix(name, "eth"):
		return "Ethernet"
	default:
		return "Other"
	}
}

func (b *OpenWrtBackend) collectLANHosts(wifiHosts map[string]string) []*openWrtLANHost {
	hosts := make(map[string]*openWrtLANHost)
	wifiInterfaces := b.openWrtWiFiInterfaceSet()
	ensure := func(macText string) *openWrtLANHost {
		mac := validClientMAC(macText)
		if mac == nil {
			return nil
		}
		key := strings.ToLower(mac.String())
		if hosts[key] == nil {
			hosts[key] = &openWrtLANHost{mac: mac}
		}
		return hosts[key]
	}

	for mac, associatedDevice := range wifiHosts {
		host := ensure(mac)
		if host == nil {
			continue
		}
		host.associatedDevice = associatedDevice
		host.interfaceType = "Wi-Fi"
		host.active = true
	}

	interfacePaths := ipInterfacePathByName()
	if neighbors, err := readRouteNeighbors(); err == nil {
		for _, neighbor := range neighbors {
			host := ensure(neighbor.MAC.String())
			if host == nil {
				continue
			}
			addHostIP(host, neighbor.IP.String())
			host.interfaceName = neighbor.InterfaceName
			if openWrtWiFiInterfaceMatch(neighbor.InterfaceName, wifiInterfaces) {
				host.interfaceType = "Wi-Fi"
			} else if host.interfaceType == "" {
				host.interfaceType = hostInterfaceType(neighbor.InterfaceName)
			}
			host.layer3Interface = interfacePaths[neighbor.InterfaceName]
			host.active = host.active || neighbor.Active
		}
	} else {
		logCollectorError("openwrt.hosts.rtnetlink", err)
	}

	nowUnix := b.now().Unix()
	for _, line := range strings.Split(b.readTextFile(b.dhcpLeasesPath), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		host := ensure(fields[1])
		if host == nil {
			continue
		}
		addHostIP(host, fields[2])
		if fields[3] != "*" {
			host.hostname = strings.TrimSpace(fields[3])
		}
		host.addressSource = "DHCP"
		host.active = true
		expiry, err := strconv.ParseInt(fields[0], 10, 64)
		switch {
		case err != nil:
			host.leaseTimeRemaining = 0
		case expiry == 0:
			host.leaseTimeRemaining = -1
		case expiry > nowUnix:
			host.leaseTimeRemaining = expiry - nowUnix
		default:
			host.leaseTimeRemaining = 0
		}
	}

	for lineIndex, line := range strings.Split(b.readTextFile(b.arpPath), "\n") {
		if lineIndex == 0 && strings.Contains(strings.ToLower(line), "ip address") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		host := ensure(fields[3])
		if host == nil {
			continue
		}
		addHostIP(host, fields[0])
		host.interfaceName = fields[5]
		if openWrtWiFiInterfaceMatch(fields[5], wifiInterfaces) {
			host.interfaceType = "Wi-Fi"
		} else if host.interfaceType == "" {
			host.interfaceType = hostInterfaceType(fields[5])
		}
		if host.layer3Interface == "" {
			host.layer3Interface = interfacePaths[fields[5]]
		}
		flags, _ := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(fields[2]), "0x"), 16, 32)
		host.active = host.active || flags&0x2 != 0
	}

	mergeMNDPHosts(hosts, linkdiscovery.DefaultSnapshot())
	out := make([]*openWrtLANHost, 0, len(hosts))
	for _, host := range hosts {
		sort.Slice(host.ipv4, func(i, j int) bool { return bytesCompareIP(host.ipv4[i], host.ipv4[j]) < 0 })
		sort.Slice(host.ipv6, func(i, j int) bool { return bytesCompareIP(host.ipv6[i], host.ipv6[j]) < 0 })
		out = append(out, host)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Compare(out[i].mac.String(), out[j].mac.String()) < 0
	})
	return out
}

func bytesCompareIP(left, right net.IP) int {
	return strings.Compare(string([]byte(left)), string([]byte(right)))
}

func (b *OpenWrtBackend) appendHostFields(msg *wusp.Message, wifiHosts map[string]string) {
	hosts := b.collectLANHosts(wifiHosts)
	appendLANHostFields(msg, hosts)
}

func appendLANHostFields(msg *wusp.Message, hosts []*openWrtLANHost) {
	appendField(msg, "Device.Hosts.HostNumberOfEntries", wusp.Uint(uint64(len(hosts))))
	for index, host := range hosts {
		path := fmt.Sprintf("Device.Hosts.Host.%d.", index+1)
		appendField(msg, path+"PhysAddress", wusp.String(host.mac.String()))
		if len(host.ipv4) > 0 {
			appendField(msg, path+"IPAddress", wusp.String(host.ipv4[0].String()))
		} else if len(host.ipv6) > 0 {
			appendField(msg, path+"IPAddress", wusp.String(host.ipv6[0].String()))
		}
		if host.addressSource != "" {
			appendField(msg, path+"AddressSource", wusp.String(host.addressSource))
			appendField(msg, path+"LeaseTimeRemaining", wusp.Int(host.leaseTimeRemaining))
		}
		if host.associatedDevice != "" {
			appendField(msg, path+"AssociatedDevice", wusp.String(host.associatedDevice))
		}
		if host.layer3Interface != "" {
			appendField(msg, path+"Layer3Interface", wusp.String(host.layer3Interface))
		}
		if host.interfaceType != "" {
			appendField(msg, path+"InterfaceType", wusp.String(host.interfaceType))
		}
		if host.hostname != "" {
			appendField(msg, path+"HostName", wusp.String(host.hostname))
		}
		appendField(msg, path+"Active", wusp.Bool(host.active))
		appendField(msg, path+"IPv4AddressNumberOfEntries", wusp.Uint(uint64(len(host.ipv4))))
		appendField(msg, path+"IPv6AddressNumberOfEntries", wusp.Uint(uint64(len(host.ipv6))))
		for addressIndex, ip := range host.ipv4 {
			appendField(msg, fmt.Sprintf("%sIPv4Address.%d.IPAddress", path, addressIndex+1), wusp.IP4(ip))
		}
		for addressIndex, ip := range host.ipv6 {
			appendField(msg, fmt.Sprintf("%sIPv6Address.%d.IPAddress", path, addressIndex+1), wusp.IP6(ip))
		}
	}
}

func ipInterfacePathByName() map[string]string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	paths := make(map[string]string, len(ifaces))
	index := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 && !isCellularNetdev(iface.Name) {
			continue
		}
		index++
		paths[iface.Name] = fmt.Sprintf("Device.IP.Interface.%d.", index)
	}
	return paths
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
		section := b.resolveWiFiRadioSection(idx)
		if section == "" {
			return wusp.ErrUSPPathNotFound
		}
		switch param {
		case "Enable":
			disabled := "1"
			if value.AsBool() {
				disabled = "0"
			}
			return b.setUCIOption(ctx, "wireless", section, "disabled", disabled, true, wirelessReloadScript)
		case "Channel":
			return b.setUCIOption(ctx, "wireless", section, "channel", wusp.ValueToString(value), true, wirelessReloadScript)
		case "AutoChannelEnable":
			if value.AsBool() {
				return b.setUCIOption(ctx, "wireless", section, "channel", "auto", true, wirelessReloadScript)
			}
			if strings.EqualFold(b.readUCIValue(ctx, "wireless", section, "channel"), "auto") {
				return fmt.Errorf("wusp openwrt radio channel must be selected before automatic channel selection can be disabled")
			}
			return nil
		case "OperatingFrequencyBand":
			band, err := normalizeOpenWrtWiFiBand(wusp.ValueToString(value))
			if err != nil {
				return err
			}
			if err := b.setUCIOption(ctx, "wireless", section, "band", band, false, ""); err != nil {
				return err
			}
			// The previous channel might be illegal in the new band. Let OpenWrt's
			// ACS select a regulatory-valid channel on the single ensuing reload.
			return b.setUCIOption(ctx, "wireless", section, "channel", "auto", true, wirelessReloadScript)
		case "OperatingChannelBandwidth":
			requested := normalizeWiFiBandwidth(wusp.ValueToString(value))
			if requested == "" {
				return fmt.Errorf("wusp openwrt invalid WiFi channel bandwidth %q", wusp.ValueToString(value))
			}
			if err := b.validateWiFiBandwidth(ctx, section, requested); err != nil {
				return err
			}
			htmode := bandwidthToHTMode(requested, section, b, ctx)
			return b.setUCIOption(ctx, "wireless", section, "htmode", htmode, true, wirelessReloadScript)
		case "OperatingStandards":
			standards, err := parseWiFiStandardsValue(value)
			if err != nil {
				return err
			}
			return b.setWiFiOperatingStandards(ctx, section, standards)
		case "TransmitPower":
			percent, err := strconv.Atoi(strings.TrimSpace(wusp.ValueToString(value)))
			if err != nil || percent < -1 || percent > 100 {
				return fmt.Errorf("wusp openwrt transmit power must be -1 or 0..100 percent")
			}
			if percent == -1 {
				return b.deleteUCIOption(ctx, "wireless", section, "txpower", true, wirelessReloadScript)
			}
			ifName := b.radioToIfname(section)
			levels := b.readWiFiTxPowerLevels(ctx, ifName)
			dbm, ok := txPowerLevelForPercent(levels, percent)
			if !ok {
				return fmt.Errorf("wusp openwrt transmit power %d is not supported; refresh TransmitPowerSupported", percent)
			}
			return b.setUCIOption(ctx, "wireless", section, "txpower", strconv.Itoa(dbm), true, wirelessReloadScript)
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

// resolveWiFiRadioSection maps the TR-181 instance to the same sorted runtime
// radio key used by appendWiFiFields. OpenWrt derivatives commonly name their
// wifi-device sections wifi0, wifi1, qcawifi, or use a sparse radio sequence;
// assuming Radio.1 == radio0 writes a new, unused UCI section on those devices.
func (b *OpenWrtBackend) resolveWiFiRadioSection(radioIndex int) string {
	if radioIndex <= 0 {
		return ""
	}
	// A writable TR-181 Radio instance is backed only by an actual UCI
	// wifi-device section. Runtime PHY names are observation sources, not
	// persistent configuration object names.
	uciRadios := b.readWirelessRadioStatusFromUCI()
	keys := make([]string, 0, len(uciRadios))
	for key := range uciRadios {
		if key = strings.TrimSpace(key); key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if radioIndex > len(keys) {
		return ""
	}
	return keys[radioIndex-1]
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

	// Wireless reload differs between stock OpenWrt and CPE derivatives. Prefer
	// netifd's ubus method, then the modern `wifi reload`, and finally the legacy
	// no-argument form. This keeps radio writes live without vendor-only APIs.
	// Init scripts like /etc/init.d/network take "reload" as an argument.
	if script == "wifi" {
		var lastErr error
		for _, command := range []struct {
			name string
			args []string
		}{
			{name: "ubus", args: []string{"call", "network", "reload"}},
			{name: "wifi", args: []string{"reload"}},
			{name: "wifi"},
		} {
			if _, err := b.commandRunner(ctx, command.name, command.args...); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		return lastErr
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
	decode := func(data []byte) (map[string]openWrtWirelessRadioStatus, bool) {
		var radios map[string]openWrtWirelessRadioStatus
		if len(data) == 0 || json.Unmarshal(data, &radios) != nil || radios == nil {
			return nil, false
		}
		return radios, true
	}
	data, err := b.callUbus(context.Background(), "network.wireless", "status", nil)
	if err != nil {
		return nil
	}
	radios, _ := decode(data)
	return radios
}

// openWrtWirelessRadios builds the TR-181 radio inventory around persistent
// UCI wifi-device sections whenever they exist. netifd, nl80211, hostapd and
// sysfs remain the authoritative sources for live state, but a runtime phyN
// must never become the configuration identity of an OpenWrt radio.
func (b *OpenWrtBackend) openWrtWirelessRadios() map[string]openWrtWirelessRadioStatus {
	configured := b.readWirelessRadioStatusFromUCI()
	runtimeRadios := b.readWirelessRadioStatus()
	if len(configured) == 0 {
		return b.enrichWirelessRuntime(runtimeRadios)
	}

	configuredKeys := make(map[string]bool, len(configured))
	for key := range configured {
		configuredKeys[key] = true
	}
	for runtimeKey, runtimeRadio := range runtimeRadios {
		target := b.configuredRadioForRuntime(configured, runtimeKey, runtimeRadio)
		if target == "" {
			// An unowned runtime PHY is still useful to the generic Linux
			// collector, but it must not create a writable OpenWrt Radio row.
			continue
		}
		configured[target] = mergeOpenWrtRadioStatus(configured[target], runtimeRadio)
	}

	configured = b.enrichWirelessRuntime(configured)
	// enrichWirelessRuntime can discover interfaces absent from netifd. Keep
	// only the UCI-backed radio identities while retaining those interfaces on
	// the best matching configured radio.
	for key := range configured {
		if !configuredKeys[key] {
			delete(configured, key)
		}
	}
	return configured
}

func (b *OpenWrtBackend) configuredRadioForRuntime(configured map[string]openWrtWirelessRadioStatus, runtimeKey string, runtimeRadio openWrtWirelessRadioStatus) string {
	runtimeKey = strings.TrimSpace(runtimeKey)
	if _, ok := configured[runtimeKey]; ok {
		return runtimeKey
	}
	for configuredKey, configuredRadio := range configured {
		if wirelessRadiosShareInterface(configuredRadio, runtimeRadio) {
			return configuredKey
		}
	}
	for _, prefix := range []string{"phy", "radio"} {
		if strings.HasPrefix(runtimeKey, prefix) {
			if phy, err := strconv.Atoi(strings.TrimPrefix(runtimeKey, prefix)); err == nil {
				return b.runtimeRadioKey(configured, phy)
			}
		}
	}
	return ""
}

func wirelessRadiosShareInterface(left, right openWrtWirelessRadioStatus) bool {
	sections := make(map[string]bool)
	ifNames := make(map[string]bool)
	for _, iface := range left.Interfaces {
		if section := strings.TrimSpace(iface.Section); section != "" {
			sections[section] = true
		}
		if ifName := strings.TrimSpace(iface.IfName); ifName != "" {
			ifNames[ifName] = true
		}
	}
	for _, iface := range right.Interfaces {
		if sections[strings.TrimSpace(iface.Section)] || ifNames[strings.TrimSpace(iface.IfName)] {
			return true
		}
	}
	return false
}

func mergeOpenWrtRadioStatus(configured, runtimeRadio openWrtWirelessRadioStatus) openWrtWirelessRadioStatus {
	configured.Up = runtimeRadio.Up
	// UCI is the desired source for disabled/config values. Runtime values fill
	// fields that are absent from the persistent section without replacing it.
	mergedConfig := make(map[string]any, len(runtimeRadio.Config)+len(configured.Config))
	for key, value := range runtimeRadio.Config {
		mergedConfig[key] = value
	}
	for key, value := range configured.Config {
		mergedConfig[key] = value
	}
	configured.Config = mergedConfig

	for _, runtimeIface := range runtimeRadio.Interfaces {
		matched := false
		for index := range configured.Interfaces {
			configuredIface := configured.Interfaces[index]
			sectionMatches := strings.TrimSpace(runtimeIface.Section) != "" && strings.TrimSpace(runtimeIface.Section) == strings.TrimSpace(configuredIface.Section)
			ifNameMatches := strings.TrimSpace(runtimeIface.IfName) != "" && strings.TrimSpace(runtimeIface.IfName) == strings.TrimSpace(configuredIface.IfName)
			if !sectionMatches && !ifNameMatches {
				continue
			}
			mergedIfaceConfig := make(map[string]any, len(runtimeIface.Config)+len(configuredIface.Config))
			for key, value := range runtimeIface.Config {
				mergedIfaceConfig[key] = value
			}
			for key, value := range configuredIface.Config {
				mergedIfaceConfig[key] = value
			}
			if strings.TrimSpace(configuredIface.IfName) == "" {
				configuredIface.IfName = runtimeIface.IfName
			}
			configuredIface.Up = runtimeIface.Up
			configuredIface.Config = mergedIfaceConfig
			configured.Interfaces[index] = configuredIface
			matched = true
			break
		}
		if !matched {
			configured.Interfaces = append(configured.Interfaces, runtimeIface)
		}
	}
	return configured
}

func (b *OpenWrtBackend) existingWiFiIfName(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || strings.ContainsAny(candidate, " /\t\r\n") {
		return ""
	}
	if _, err := os.Stat(filepath.Join(b.netClassDir, candidate)); err == nil {
		return candidate
	}
	if iface, err := net.InterfaceByName(candidate); err == nil && iface != nil {
		return candidate
	}
	return ""
}

// enrichWirelessRuntime merges runtime-only interfaces into netifd/UCI
// configuration. UCI section labels are configuration identifiers, not Linux
// interface names; this function only admits links proven by nl80211, ubus
// object discovery, iwinfo devices, or sysfs.
func (b *OpenWrtBackend) enrichWirelessRuntime(radios map[string]openWrtWirelessRadioStatus) map[string]openWrtWirelessRadioStatus {
	if radios == nil {
		radios = make(map[string]openWrtWirelessRadioStatus)
	}
	runtimeInterfaces, runtimeErr := iwinfo.RuntimeInterfaces()
	if runtimeErr != nil {
		logCollectorError("openwrt.wifi.nl80211.interfaces", runtimeErr)
	}

	discovered := make(map[string]iwinfo.WirelessInterface, len(runtimeInterfaces))
	for _, iface := range runtimeInterfaces {
		if strings.TrimSpace(iface.Name) != "" {
			discovered[iface.Name] = iface
		}
	}
	for _, ifName := range b.discoverWiFiInterfacesFromSysfs() {
		if _, ok := discovered[ifName]; ok {
			continue
		}
		discovered[ifName] = iwinfo.WirelessInterface{
			Name:         ifName,
			PHY:          b.runtimePHYIndex(ifName),
			Mode:         b.runtimeWiFiMode(ifName),
			HardwareAddr: b.runtimeHardwareAddr(ifName),
		}
	}

	known := make(map[string]bool)
	for key, radio := range radios {
		for index := range radio.Interfaces {
			// netifd status and nl80211 entries are runtime evidence in their
			// own right. Only the UCI-only path needs existence validation.
			ifName := strings.TrimSpace(radio.Interfaces[index].IfName)
			if ifName != "" {
				known[ifName] = true
				if runtime, ok := discovered[ifName]; ok {
					radio.Interfaces[index].Up = b.runtimeInterfaceUp(ifName)
					if radio.Interfaces[index].Config == nil {
						radio.Interfaces[index].Config = map[string]any{}
					}
					if configString(radio.Interfaces[index].Config, "mode") == "" {
						radio.Interfaces[index].Config["mode"] = runtime.Mode
					}
				}
			}
		}
		radios[key] = radio
	}

	for _, iface := range discovered {
		if known[iface.Name] {
			continue
		}
		radioKey := b.runtimeRadioKey(radios, iface.PHY)
		radio := radios[radioKey]
		if radio.Config == nil {
			radio.Config = map[string]any{}
		}
		if radio.Config["band"] == nil && iface.Frequency > 0 {
			radio.Config["band"] = wifiBandFromFrequency(iface.Frequency)
		}
		radio.Up = radio.Up || b.runtimeInterfaceUp(iface.Name)
		radio.Interfaces = append(radio.Interfaces, openWrtWirelessIfaceStatus{
			Section: iface.Name,
			IfName:  iface.Name,
			Up:      b.runtimeInterfaceUp(iface.Name),
			Config: map[string]any{
				"mode":   iface.Mode,
				"ifname": iface.Name,
			},
		})
		radios[radioKey] = radio
	}
	return radios
}

func (b *OpenWrtBackend) discoverWiFiInterfacesFromSysfs() []string {
	seen := make(map[string]bool)
	add := func(value string) {
		value = strings.TrimSpace(strings.TrimPrefix(value, "hostapd."))
		if value != "" && len(value) < 16 && !strings.ContainsAny(value, " /\t\r\n") {
			seen[value] = true
		}
	}
	// sysfs remains available on minimal images with no ubus/iw/iwinfo CLI.
	if entries, err := os.ReadDir(b.netClassDir); err == nil {
		for _, entry := range entries {
			if _, err := os.Stat(filepath.Join(b.netClassDir, entry.Name(), "phy80211")); err == nil {
				add(entry.Name())
			}
		}
	}
	out := make([]string, 0, len(seen))
	for ifName := range seen {
		out = append(out, ifName)
	}
	sort.Strings(out)
	return out
}

func (b *OpenWrtBackend) runtimeRadioKey(radios map[string]openWrtWirelessRadioStatus, phy int) string {
	candidates := []string{fmt.Sprintf("radio%d", phy), fmt.Sprintf("phy%d", phy)}
	for _, candidate := range candidates {
		if _, ok := radios[candidate]; ok {
			return candidate
		}
	}
	// Vendor images frequently name UCI wifi-device sections wifi0, wifi1,
	// qcawifi0, etc. When explicit interface/section evidence is unavailable,
	// align the stable UCI section order with the kernel PHY index for runtime
	// enrichment only. Set operations still resolve directly to this UCI key.
	keys := make([]string, 0, len(radios))
	for key := range radios {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if phy >= 0 && phy < len(keys) {
		return keys[phy]
	}
	if len(radios) == 1 {
		for key := range radios {
			return key
		}
	}
	return fmt.Sprintf("phy%d", phy)
}

func (b *OpenWrtBackend) runtimePHYIndex(ifName string) int {
	value := strings.TrimSpace(b.readTextFile(filepath.Join(b.netClassDir, ifName, "phy80211", "index")))
	if phy, err := strconv.Atoi(value); err == nil {
		return phy
	}
	name := strings.TrimSpace(b.readTextFile(filepath.Join(b.netClassDir, ifName, "phy80211", "name")))
	if strings.HasPrefix(name, "phy") {
		if phy, err := strconv.Atoi(strings.TrimPrefix(name, "phy")); err == nil {
			return phy
		}
	}
	if resolved, err := filepath.EvalSymlinks(filepath.Join(b.netClassDir, ifName, "phy80211")); err == nil {
		name = filepath.Base(resolved)
		if strings.HasPrefix(name, "phy") {
			if phy, err := strconv.Atoi(strings.TrimPrefix(name, "phy")); err == nil {
				return phy
			}
		}
	}
	return 0
}

func (b *OpenWrtBackend) runtimeWiFiMode(ifName string) string {
	if info, err := b.wifiInfo(ifName); err == nil && info != nil {
		switch info.Mode {
		case 1:
			return "ap"
		case 3:
			return "station"
		}
	}
	return "ap"
}

func (b *OpenWrtBackend) runtimeHardwareAddr(ifName string) net.HardwareAddr {
	mac, _ := net.ParseMAC(strings.TrimSpace(b.readTextFile(filepath.Join(b.netClassDir, ifName, "address"))))
	return mac
}

func (b *OpenWrtBackend) runtimeInterfaceUp(ifName string) bool {
	state := strings.ToLower(strings.TrimSpace(b.readTextFile(filepath.Join(b.netClassDir, ifName, "operstate"))))
	if state != "" {
		return state != "down" && state != "notpresent" && state != "lowerlayerdown"
	}
	iface, err := net.InterfaceByName(ifName)
	return err == nil && iface.Flags&net.FlagUp != 0
}

func wifiBandFromFrequency(frequency int) string {
	switch {
	case frequency >= 5925:
		return "6g"
	case frequency >= 4900:
		return "5g"
	case frequency >= 2300:
		return "2g"
	default:
		return ""
	}
}

func (b *OpenWrtBackend) readWiFiStations() (map[string][]iwinfo.AssocEntry, error) {
	data, err := b.callUbus(context.Background(), "device", "getStaList", nil)
	var payload struct {
		Station []openWrtWiFiStation `json:"station"`
	}
	if err == nil && len(data) > 0 {
		if decodeErr := json.Unmarshal(data, &payload); decodeErr == nil && payload.Station != nil {
			return mapOpenWrtWiFiStations(payload.Station), nil
		}
	}
	if err != nil {
		return map[string][]iwinfo.AssocEntry{}, err
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return map[string][]iwinfo.AssocEntry{}, err
	}
	if payload.Station == nil {
		return map[string][]iwinfo.AssocEntry{}, fmt.Errorf("device.getStaList missing station array")
	}
	return mapOpenWrtWiFiStations(payload.Station), nil
}

func mapOpenWrtWiFiStations(observations []openWrtWiFiStation) map[string][]iwinfo.AssocEntry {
	stations := make(map[string][]iwinfo.AssocEntry)
	for _, station := range observations {
		iface := strings.TrimSpace(station.Iface)
		if iface == "" {
			continue
		}
		mac, err := net.ParseMAC(strings.TrimSpace(station.MAC))
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
			continue
		}
		entry := iwinfo.AssocEntry{MAC: mac}
		if station.RSSI != nil {
			entry.Signal, entry.SignalKnown = boundedWiFiDBM(*station.RSSI), true
		}
		if station.Noise != nil {
			entry.Noise, entry.NoiseKnown = boundedWiFiDBM(*station.Noise), true
		}
		if station.Inactive != nil {
			entry.Inactive, entry.InactiveKnown = *station.Inactive, true
		}
		if station.ConnectedTime != nil {
			entry.ConnectedTime, entry.ConnectedTimeKnown = *station.ConnectedTime, true
		}
		if station.RxPackets != nil {
			entry.RxPackets, entry.RxPacketsKnown = *station.RxPackets, true
		}
		if station.TxPackets != nil {
			entry.TxPackets, entry.TxPacketsKnown = *station.TxPackets, true
		}
		if station.RxBytes != nil {
			entry.RxBytes, entry.RxBytesKnown = *station.RxBytes, true
		}
		if station.TxBytes != nil {
			entry.TxBytes, entry.TxBytesKnown = *station.TxBytes, true
		}
		if station.TxRetries != nil {
			entry.TxRetries, entry.TxRetriesKnown = *station.TxRetries, true
		}
		if station.TxFailed != nil {
			entry.TxFailed, entry.TxFailedKnown = *station.TxFailed, true
		}
		if station.RxRate != nil {
			entry.RxRate, entry.RxRateKnown = *station.RxRate, true
		}
		if station.TxRate != nil {
			entry.TxRate, entry.TxRateKnown = *station.TxRate, true
		}
		stations[iface] = append(stations[iface], entry)
	}
	return stations
}

func (b *OpenWrtBackend) readOpenWrtWiFiCapabilities(ctx context.Context, ifName string) (*iwinfo.HWModes, []string) {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" {
		return nil, nil
	}
	hwModes := &iwinfo.HWModes{}
	var htModes []string
	if b.wifiHWModeList != nil {
		if modes, err := b.wifiHWModeList(ifName); err == nil && modes != nil {
			mergeWiFiHWModes(hwModes, modes)
		}
	}
	if b.wifiHTModeList != nil {
		if modes, err := b.wifiHTModeList(ifName); err == nil {
			htModes = mergeWiFiHTModes(htModes, modes)
		}
	}

	// rpcd-mod-iwinfo exposes both lists using the runtime netdev. Prefer the
	// local ubus socket so stock OpenWrt does not depend on anonymous HTTP ubus.
	var rpcCapabilities openWrtIWInfoCapabilities
	if data, err := b.callUbus(ctx, "iwinfo", "info", map[string]any{"device": ifName}); err == nil && json.Unmarshal(data, &rpcCapabilities) == nil {
		mergeWiFiHWModes(hwModes, parseWiFiHWModes(rpcCapabilities.HWModes))
		htModes = mergeWiFiHTModes(htModes, rpcCapabilities.HTModes)
	}
	if !hasAnyWiFiHWMode(hwModes) {
		hwModes = nil
	}
	return hwModes, htModes
}

func parseWiFiHWModes(values []string) *iwinfo.HWModes {
	modes := &iwinfo.HWModes{}
	for _, value := range values {
		for _, token := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
			return r == ',' || r == '/' || r == '|' || r == '[' || r == ']' || r == '"'
		}) {
			token = strings.TrimSpace(strings.TrimPrefix(token, "802.11"))
			switch token {
			case "a":
				modes.A = true
			case "b":
				modes.B = true
			case "g":
				modes.G = true
			case "n":
				modes.N = true
			case "ac":
				modes.AC = true
			case "ax":
				modes.AX = true
			case "be":
				modes.BE = true
			}
		}
	}
	return modes
}

func mergeWiFiHWModes(target, source *iwinfo.HWModes) {
	if target == nil || source == nil {
		return
	}
	target.A = target.A || source.A
	target.B = target.B || source.B
	target.G = target.G || source.G
	target.N = target.N || source.N
	target.AC = target.AC || source.AC
	target.AX = target.AX || source.AX
	target.BE = target.BE || source.BE
}

func hasAnyWiFiHWMode(modes *iwinfo.HWModes) bool {
	return modes != nil && (modes.A || modes.B || modes.G || modes.N || modes.AC || modes.AX || modes.BE)
}

func mergeWiFiHTModes(current, observed []string) []string {
	seen := make(map[string]bool, len(current)+len(observed))
	for _, value := range append(append([]string(nil), current...), observed...) {
		value = strings.ToUpper(strings.Trim(strings.TrimSpace(value), "[],\"'"))
		if value == "NOHT" || strings.HasPrefix(value, "HT") || strings.HasPrefix(value, "VHT") || strings.HasPrefix(value, "HE") || strings.HasPrefix(value, "EHT") {
			seen[value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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
		configuredIfName := b.existingWiFiIfName(section.Options["ifname"])
		iface := openWrtWirelessIfaceStatus{
			Section: section.Name,
			IfName:  configuredIfName,
			// UCI is desired configuration, not proof that a link exists.
			Up:     false,
			Config: config,
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

func wifiAccessPointStatusValue(enabled, up bool) string {
	switch {
	case !enabled:
		return "Disabled"
	case up:
		return "Enabled"
	default:
		return "Error"
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
		return "320MHz-1"
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

func normalizeOpenWrtWiFiBand(value string) (string, error) {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), " ", "")) {
	case "2g", "2.4g", "2.4ghz":
		return "2g", nil
	case "5g", "5ghz":
		return "5g", nil
	case "6g", "6ghz":
		return "6g", nil
	default:
		return "", fmt.Errorf("wusp openwrt WiFi band must be 2.4GHz, 5GHz, or 6GHz")
	}
}

func normalizeWiFiBandwidth(value string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), " ", ""))
	switch normalized {
	case "AUTO":
		return "Auto"
	case "20", "20MHZ":
		return "20MHz"
	case "40", "40MHZ":
		return "40MHz"
	case "80", "80MHZ":
		return "80MHz"
	case "160", "160MHZ":
		return "160MHz"
	case "80+80", "80+80MHZ":
		return "80+80MHz"
	case "320", "320MHZ", "320MHZ-1":
		return "320MHz-1"
	case "320MHZ-2":
		return "320MHz-2"
	default:
		return ""
	}
}

func parseWiFiStandardsValue(value wusp.Value) ([]string, error) {
	raw := make([]string, 0, 7)
	if value.Tag == wusp.TagList {
		for _, item := range value.AsList() {
			raw = append(raw, strings.Split(wusp.ValueToString(item), ",")...)
		}
	} else {
		raw = strings.Split(wusp.ValueToString(value), ",")
	}
	seen := map[string]bool{}
	for _, standard := range raw {
		standard = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(standard, "802.11")))
		valid := false
		for _, candidate := range wifiStandardOrder {
			if standard == candidate {
				valid = true
				break
			}
		}
		if standard != "" && !valid {
			return nil, fmt.Errorf("wusp openwrt unsupported 802.11 standard %q", standard)
		}
		if valid {
			seen[standard] = true
		}
	}
	standards := orderedWiFiStandards(seen)
	if len(standards) == 0 {
		return nil, fmt.Errorf("wusp openwrt OperatingStandards cannot be empty")
	}
	return standards, nil
}

func containsWiFiStandard(standards []string, want string) bool {
	for _, standard := range standards {
		if standard == want {
			return true
		}
	}
	return false
}

func wifiStandardModePrefix(standards []string) string {
	switch {
	case containsWiFiStandard(standards, "be"):
		return "EHT"
	case containsWiFiStandard(standards, "ax"):
		return "HE"
	case containsWiFiStandard(standards, "ac"):
		return "VHT"
	case containsWiFiStandard(standards, "n"):
		return "HT"
	default:
		return "NOHT"
	}
}

func wifiBandwidthMHz(value string) int {
	switch normalizeWiFiBandwidth(value) {
	case "20MHz":
		return 20
	case "40MHz":
		return 40
	case "80MHz", "80+80MHz":
		return 80
	case "160MHz":
		return 160
	case "320MHz-1", "320MHz-2":
		return 320
	default:
		return 20
	}
}

func wifiModeForStandards(prefix, currentBandwidth string, supported []string) (string, error) {
	if prefix == "NOHT" {
		return "NOHT", nil
	}
	wantedWidth := wifiBandwidthMHz(currentBandwidth)
	bestMode := ""
	bestWidth := -1
	for _, mode := range supported {
		upper := strings.ToUpper(strings.TrimSpace(mode))
		if !strings.HasPrefix(upper, prefix) {
			continue
		}
		width, _ := strconv.Atoi(strings.TrimPrefix(upper, prefix))
		if width == wantedWidth {
			return upper, nil
		}
		if width <= wantedWidth && width > bestWidth {
			bestMode, bestWidth = upper, width
		}
	}
	if bestMode != "" {
		return bestMode, nil
	}
	if len(supported) > 0 {
		return "", fmt.Errorf("wusp openwrt requested 802.11 generation is not supported by this radio")
	}
	if prefix == "HT" && wantedWidth > 40 {
		wantedWidth = 40
	}
	return prefix + strconv.Itoa(wantedWidth), nil
}

func (b *OpenWrtBackend) validateWiFiBandwidth(ctx context.Context, section, requested string) error {
	ifName := b.radioToIfname(section)
	if ifName == "" {
		return nil
	}
	_, modes := b.readOpenWrtWiFiCapabilities(ctx, ifName)
	if len(modes) == 0 {
		return nil
	}
	supported := wifiSupportedBandwidths(modes, "")
	for _, bandwidth := range supported {
		if bandwidth == requested {
			return nil
		}
	}
	return fmt.Errorf("wusp openwrt channel bandwidth %s is not supported; valid values are %s", requested, strings.Join(supported, ","))
}

func (b *OpenWrtBackend) setWiFiOperatingStandards(ctx context.Context, section string, standards []string) error {
	band := wifiBandFromConfig(map[string]any{
		"band":   b.readUCIValue(ctx, "wireless", section, "band"),
		"hwmode": b.readUCIValue(ctx, "wireless", section, "hwmode"),
	})
	allowed := map[string]bool{}
	switch band {
	case "2.4GHz":
		for _, standard := range []string{"b", "g", "n", "ax", "be"} {
			allowed[standard] = true
		}
	case "5GHz":
		for _, standard := range []string{"a", "n", "ac", "ax", "be"} {
			allowed[standard] = true
		}
	case "6GHz":
		allowed["ax"], allowed["be"] = true, true
	default:
		return fmt.Errorf("wusp openwrt radio band must be known before setting OperatingStandards")
	}
	for _, standard := range standards {
		if !allowed[standard] {
			return fmt.Errorf("wusp openwrt 802.11%s is not valid in %s", standard, band)
		}
	}

	ifName := b.radioToIfname(section)
	hardwareModes, supportedModes := b.readOpenWrtWiFiCapabilities(ctx, ifName)
	if hardwareModes != nil {
		supported := wifiSupportedStandards(hardwareModes, band)
		for _, standard := range standards {
			if !containsWiFiStandard(supported, standard) {
				return fmt.Errorf("wusp openwrt 802.11%s is not supported by this radio", standard)
			}
		}
	}
	currentHTMode := b.readUCIValue(ctx, "wireless", section, "htmode")
	mode, err := wifiModeForStandards(wifiStandardModePrefix(standards), wifiBandwidthFromConfig(map[string]any{"htmode": currentHTMode}), supportedModes)
	if err != nil {
		return err
	}

	requireMode := ""
	if !containsWiFiStandard(standards, "a") && !containsWiFiStandard(standards, "b") && !containsWiFiStandard(standards, "g") {
		switch {
		case containsWiFiStandard(standards, "n"):
			requireMode = "n"
		case containsWiFiStandard(standards, "ac"):
			requireMode = "ac"
		case band != "6GHz":
			return fmt.Errorf("wusp openwrt cannot enforce an ax/be-only profile on this radio; include the compatible n/ac standards")
		}
	}
	legacyRates := "0"
	if containsWiFiStandard(standards, "b") {
		legacyRates = "1"
	}
	projected := wifiOperatingStandards(map[string]any{
		"band":         band,
		"htmode":       mode,
		"legacy_rates": legacyRates,
		"require_mode": requireMode,
	})
	if !sameWiFiStandards(projected, standards) {
		return fmt.Errorf(
			"wusp openwrt cannot represent OperatingStandards %s exactly with UCI htmode/legacy_rates/require_mode; resulting set would be %s",
			strings.Join(standards, ","), strings.Join(projected, ","),
		)
	}
	if err := b.setUCIOption(ctx, "wireless", section, "htmode", mode, false, ""); err != nil {
		return err
	}
	if err := b.setUCIOption(ctx, "wireless", section, "legacy_rates", legacyRates, false, ""); err != nil {
		return err
	}
	if requireMode == "" {
		return b.deleteUCIOption(ctx, "wireless", section, "require_mode", true, wirelessReloadScript)
	}
	return b.setUCIOption(ctx, "wireless", section, "require_mode", requireMode, true, wirelessReloadScript)
}

func sameWiFiStandards(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var wifiStandardOrder = []string{"a", "b", "g", "n", "ac", "ax", "be"}

func wifiStringList(values []string) wusp.Value {
	items := make([]wusp.Value, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			items = append(items, wusp.String(value))
		}
	}
	return wusp.List(items...)
}

func orderedWiFiStandards(in map[string]bool) []string {
	out := make([]string, 0, len(in))
	for _, standard := range wifiStandardOrder {
		if in[standard] {
			out = append(out, standard)
		}
	}
	return out
}

func wifiSupportedStandards(modes *iwinfo.HWModes, band string) []string {
	standards := map[string]bool{}
	if modes != nil {
		standards["a"] = modes.A && band == "5GHz"
		standards["b"] = modes.B && band == "2.4GHz"
		standards["g"] = modes.G && band == "2.4GHz"
		standards["n"] = modes.N && band != "6GHz"
		standards["ac"] = modes.AC && band == "5GHz"
		standards["ax"] = modes.AX
		standards["be"] = modes.BE
	}
	return orderedWiFiStandards(standards)
}

func wifiOperatingStandards(config map[string]any) []string {
	band := wifiBandFromConfig(config)
	htmode := strings.ToUpper(strings.TrimSpace(configString(config, "htmode")))
	requireMode := strings.ToLower(strings.TrimSpace(configString(config, "require_mode")))
	legacyRates := parseOpenWrtBool(configString(config, "legacy_rates"), false)
	standards := map[string]bool{}

	switch band {
	case "2.4GHz":
		standards["g"] = true
		standards["b"] = legacyRates
	case "5GHz":
		standards["a"] = true
	}

	if strings.HasPrefix(htmode, "HT") || strings.HasPrefix(htmode, "VHT") ||
		strings.HasPrefix(htmode, "HE") || strings.HasPrefix(htmode, "EHT") {
		standards["n"] = band != "6GHz"
	}
	if strings.HasPrefix(htmode, "VHT") || strings.HasPrefix(htmode, "HE") || strings.HasPrefix(htmode, "EHT") {
		standards["ac"] = band == "5GHz"
	}
	if strings.HasPrefix(htmode, "HE") || strings.HasPrefix(htmode, "EHT") {
		standards["ax"] = true
	}
	if strings.HasPrefix(htmode, "EHT") {
		standards["be"] = true
	}

	// OpenWrt's require_mode removes older client generations from the
	// advertised operating profile while htmode selects the newest PHY mode.
	switch requireMode {
	case "n":
		delete(standards, "a")
		delete(standards, "b")
		delete(standards, "g")
	case "ac":
		delete(standards, "a")
		delete(standards, "b")
		delete(standards, "g")
		delete(standards, "n")
	}
	return orderedWiFiStandards(standards)
}

func wifiSupportedBandwidths(htModes []string, current string) []string {
	seen := map[string]bool{"Auto": true}
	for _, mode := range htModes {
		upper := strings.ToUpper(strings.TrimSpace(mode))
		switch {
		case strings.Contains(upper, "320"):
			seen["320MHz-1"] = true
		case strings.Contains(upper, "160"):
			seen["160MHz"] = true
		case strings.Contains(upper, "80"):
			seen["80MHz"] = true
		case strings.Contains(upper, "40"):
			seen["40MHz"] = true
		case strings.Contains(upper, "20"), upper == "NOHT":
			seen["20MHz"] = true
		}
	}
	if current != "" && current != "Unknown" {
		seen[current] = true
	}
	order := []string{"Auto", "20MHz", "40MHz", "80MHz", "160MHz", "80+80MHz", "320MHz-1", "320MHz-2"}
	out := make([]string, 0, len(seen))
	for _, value := range order {
		if seen[value] {
			out = append(out, value)
		}
	}
	return out
}

func parseIWInfoTxPowerLevels(output []byte) []int {
	seen := map[int]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "*")))
		if len(fields) < 2 || !strings.EqualFold(fields[1], "dBm") {
			continue
		}
		level, err := strconv.Atoi(fields[0])
		if err == nil && level >= 0 {
			seen[level] = true
		}
	}
	levels := make([]int, 0, len(seen))
	for level := range seen {
		levels = append(levels, level)
	}
	sort.Ints(levels)
	return levels
}

func txPowerPercentForDBM(dbm, maxDBM int) int {
	if maxDBM <= 0 {
		return 100
	}
	percent := int(math.Round(math.Pow(10, float64(dbm-maxDBM)/10) * 100))
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}

func txPowerSupportedPercentages(levels []int) []int {
	if len(levels) == 0 {
		return []int{-1}
	}
	maxDBM := levels[len(levels)-1]
	seen := map[int]bool{-1: true}
	for _, level := range levels {
		seen[txPowerPercentForDBM(level, maxDBM)] = true
	}
	percentages := make([]int, 0, len(seen))
	for percent := range seen {
		percentages = append(percentages, percent)
	}
	sort.Ints(percentages)
	return percentages
}

func txPowerLevelForPercent(levels []int, percent int) (int, bool) {
	if len(levels) == 0 {
		return 0, false
	}
	maxDBM := levels[len(levels)-1]
	match := 0
	found := false
	for _, level := range levels {
		if txPowerPercentForDBM(level, maxDBM) == percent {
			match = level
			found = true
		}
	}
	return match, found
}

func (b *OpenWrtBackend) readWiFiTxPowerLevels(ctx context.Context, ifName string) []int {
	if b.wifiTxPowerLevels != nil {
		return b.wifiTxPowerLevels(ctx, ifName)
	}
	// Neither nl80211 nor stock netifd exposes the discrete vendor calibration
	// table portably. Keep this unknown instead of invoking iwinfo or inventing
	// percentage choices.
	return nil
}

func (b *OpenWrtBackend) appendWiFiRadioCapabilities(ctx context.Context, msg *wusp.Message, section, ifName string, radioIndex int, config map[string]any) {
	if strings.TrimSpace(ifName) == "" {
		ifName = b.radioToIfname(section)
	}
	base := fmt.Sprintf("Device.WiFi.Radio.%d.", radioIndex)
	band := wifiBandFromConfig(config)
	operatingStandards := wifiOperatingStandards(config)
	supportedStandards := append([]string(nil), operatingStandards...)
	hardwareModes, htModes := b.readOpenWrtWiFiCapabilities(ctx, ifName)
	if hardwareModes != nil {
		if discovered := wifiSupportedStandards(hardwareModes, band); len(discovered) > 0 {
			supportedStandards = discovered
		}
	}
	if len(supportedStandards) > 0 {
		appendField(msg, base+"SupportedStandards", wifiStringList(supportedStandards))
	}
	if len(operatingStandards) > 0 {
		appendField(msg, base+"OperatingStandards", wifiStringList(operatingStandards))
	}

	bandwidths := wifiSupportedBandwidths(htModes, wifiBandwidthFromConfig(config))
	appendField(msg, base+"SupportedOperatingChannelBandwidths", wifiStringList(bandwidths))

	levels := b.readWiFiTxPowerLevels(ctx, ifName)
	percentages := txPowerSupportedPercentages(levels)
	powerValues := make([]wusp.Value, 0, len(percentages))
	for _, percent := range percentages {
		powerValues = append(powerValues, wusp.Int(int64(percent)))
	}
	appendField(msg, base+"TransmitPowerSupported", wusp.List(powerValues...))
	configuredPower := strings.TrimSpace(configString(config, "txpower"))
	if configuredPower == "" {
		appendField(msg, base+"TransmitPower", wusp.Int(-1))
	} else if dbm, err := strconv.Atoi(configuredPower); err == nil && len(levels) > 0 {
		appendField(msg, base+"TransmitPower", wusp.Int(int64(txPowerPercentForDBM(dbm, levels[len(levels)-1]))))
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
	// Resolve the UCI wifi-device section through the same local-ubus-first
	// inventory used by collection. A configured ifname is accepted only after
	// existingWiFiIfName proves that the runtime link exists.
	if radio, ok := b.openWrtWirelessRadios()[strings.TrimSpace(section)]; ok {
		for _, iface := range radio.Interfaces {
			if ifName := b.existingWiFiIfName(iface.IfName); ifName != "" {
				return ifName
			}
		}
	}
	// Fallback: align a conventional radioN UCI section with phyN in sysfs.
	targetPhy := strings.Replace(strings.TrimSpace(section), "radio", "phy", 1)
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

	// Get supported modes from the same UCI-radio capability path used by the
	// collector (libiwinfo, local rpcd iwinfo, CLI, then sysfs/netctl).
	ifname := b.radioToIfname(section)
	var supported []string
	if ifname != "" {
		_, supported = b.readOpenWrtWiFiCapabilities(ctx, ifname)
		if len(supported) == 0 {
			if caps, err := netCtl.WiFiGetCapabilities(ifname); err == nil {
				supported = caps.SupportedHTModes
			}
		}
	}

	// Normalize TR-181 labels into OpenWrt htmode width suffixes.
	normalized := normalizeWiFiBandwidth(bw)
	width := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(normalized), "mhz-1"), "mhz-2")
	width = strings.TrimSuffix(width, "mhz")

	if normalized == "Auto" {
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
