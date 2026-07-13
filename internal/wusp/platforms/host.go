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
	"strconv"
	"strings"
	"time"

	modemPkg "wantastic-agent/internal/modem"
	"wantastic-agent/internal/wusp"
)

type hostState struct {
	FriendlyName     string `json:"friendly_name,omitempty"`
	ProvisioningCode string `json:"provisioning_code,omitempty"`
}

type hostBackend struct {
	kind                  Kind
	statePath             string
	hostnamePath          string
	uptimePath            string
	memInfoPath           string
	ipv6DisablePath       string
	tcpImplementationPath string
	osReleasePath         string
	serialNumberPath      string
	machineIDPath         string
	deviceModelPath       string
	deviceVendorPath      string
	deviceVersionPath     string
	buildPropPath         string
	timezonePath          string
	onuReleasePath        string
	netClassDir           string
	commandRunner         CommandRunner
	now                   func() time.Time
}

type timeState struct {
	Enabled bool
	Known   bool
}

var _ wusp.DataBackend = (*hostBackend)(nil)

func NewLinuxBackend(opts Options) wusp.DataBackend   { return newHostBackend(KindLinux, opts) }
func NewMacOSBackend(opts Options) wusp.DataBackend   { return newHostBackend(KindMacOS, opts) }
func NewWindowsBackend(opts Options) wusp.DataBackend { return newHostBackend(KindWindows, opts) }
func NewAndroidBackend(opts Options) wusp.DataBackend { return newHostBackend(KindAndroid, opts) }
func NewONUBackend(opts Options) wusp.DataBackend     { return newHostBackend(KindONU, opts) }

func newHostBackend(kind Kind, opts Options) *hostBackend {
	backend := &hostBackend{
		kind:                  kind,
		statePath:             coalesceString(opts.StatePath, defaultStatePath(kind)),
		hostnamePath:          coalesceString(opts.HostnamePath, defaultHostnamePath(kind)),
		uptimePath:            coalesceString(opts.UptimePath, defaultUptimePath(kind)),
		memInfoPath:           coalesceString(opts.MemInfoPath, defaultMemInfoPath(kind)),
		ipv6DisablePath:       coalesceString(opts.IPv6DisablePath, defaultIPv6DisablePath(kind)),
		tcpImplementationPath: coalesceString(opts.TCPImplementationPath, defaultTCPImplementationPath(kind)),
		osReleasePath:         coalesceString(opts.OSReleasePath, defaultOSReleasePath(kind)),
		serialNumberPath:      coalesceString(opts.SerialNumberPath, defaultSerialNumberPath(kind)),
		machineIDPath:         coalesceString(opts.MachineIDPath, defaultMachineIDPath(kind)),
		deviceModelPath:       coalesceString(opts.DeviceModelPath, defaultDeviceModelPath(kind)),
		deviceVendorPath:      coalesceString(opts.DeviceVendorPath, defaultDeviceVendorPath(kind)),
		deviceVersionPath:     coalesceString(opts.DeviceVersionPath, defaultDeviceVersionPath(kind)),
		buildPropPath:         coalesceString(opts.BuildPropPath, defaultBuildPropPath(kind)),
		timezonePath:          coalesceString(opts.TimezonePath, defaultTimezonePath(kind)),
		onuReleasePath:        coalesceString(opts.ONUReleasePath, "/etc/onu-release"),
		netClassDir:           coalesceString(opts.NetClassDir, defaultNetClassDir(kind)),
		commandRunner:         opts.CommandRunner,
		now:                   opts.Now,
	}
	if backend.commandRunner == nil {
		backend.commandRunner = defaultCommandRunner
	}
	if backend.now == nil {
		backend.now = time.Now
	}
	return backend
}

func (b *hostBackend) Collect(ctx context.Context, paths ...string) (*wusp.Message, error) {
	msg := b.collectAll(ctx)
	if len(paths) == 0 {
		return msg, nil
	}
	return subsetPlatformMessageByPaths(msg, paths...), nil
}

func (b *hostBackend) Set(ctx context.Context, path string, value wusp.Value) error {
	switch strings.TrimSpace(path) {
	case "Device.DeviceInfo.HostName":
		return b.setHostname(ctx, value.AsString())
	case "Device.DeviceInfo.FriendlyName":
		return b.updateState(func(state *hostState) {
			state.FriendlyName = value.AsString()
		})
	case "Device.DeviceInfo.ProvisioningCode":
		return b.updateState(func(state *hostState) {
			state.ProvisioningCode = value.AsString()
		})
	case "Device.Time.Enable":
		return b.setTimeEnabled(ctx, value.AsBool())
	case "Device.Time.LocalTimeZone":
		return b.setTimeZone(ctx, value.AsString())
	default:
		return wusp.ErrUSPPathUnsupported
	}
}

func (b *hostBackend) Delete(ctx context.Context, paths ...string) error {
	for _, path := range paths {
		switch strings.TrimSpace(path) {
		case "Device.DeviceInfo.FriendlyName":
			if err := b.updateState(func(state *hostState) {
				state.FriendlyName = ""
			}); err != nil {
				return err
			}
		case "Device.DeviceInfo.ProvisioningCode":
			if err := b.updateState(func(state *hostState) {
				state.ProvisioningCode = ""
			}); err != nil {
				return err
			}
		default:
			return wusp.ErrUSPPathUnsupported
		}
	}
	return nil
}

func (b *hostBackend) collectAll(ctx context.Context) *wusp.Message {
	state, _ := b.readState()
	now := b.now()

	manufacturer := b.readManufacturer(ctx)
	modelName := b.readModelName(ctx)
	softwareVersion := b.readSoftwareVersion(ctx)
	hardwareVersion := b.readHardwareVersion(ctx)
	modelNumber := firstNonEmpty(modelName, hardwareVersion)
	productClass := b.productClass()
	serialNumber := b.readSerialNumber(ctx)
	hostname := b.readHostname(ctx)
	friendlyName := firstNonEmpty(state.FriendlyName, hostname)
	memTotal, memFree := b.readMemory(ctx)
	timeState := b.readTimeEnabled(ctx)
	localTimeZone := b.readLocalTimeZone(ctx)
	ipv6Enabled, ipv6Known := b.readIPv6Enabled(ctx)

	msg := wusp.NewMessage()
	msg.Set("Device.RootDataModelVersion", wusp.String(wusp.BroadbandRootDataModelVersion))
	if manufacturer != "" {
		msg.Set("Device.DeviceInfo.Manufacturer", wusp.String(manufacturer))
	}
	if manufacturerOUI := b.readManufacturerOUI(); len(manufacturerOUI) == 6 {
		msg.Set("Device.DeviceInfo.ManufacturerOUI", wusp.String(manufacturerOUI))
	}
	if modelName != "" {
		msg.Set("Device.DeviceInfo.ModelName", wusp.String(modelName))
	}
	if modelNumber != "" {
		msg.Set("Device.DeviceInfo.ModelNumber", wusp.String(modelNumber))
	}
	if description := strings.Join(nonEmptyStrings(productClass, softwareVersion), " / "); description != "" {
		msg.Set("Device.DeviceInfo.Description", wusp.String(description))
	}
	if productClass != "" {
		msg.Set("Device.DeviceInfo.ProductClass", wusp.String(productClass))
	}
	if serialNumber != "" {
		msg.Set("Device.DeviceInfo.SerialNumber", wusp.String(serialNumber))
	}
	if hardwareVersion != "" {
		msg.Set("Device.DeviceInfo.HardwareVersion", wusp.String(hardwareVersion))
	}
	if softwareVersion != "" {
		msg.Set("Device.DeviceInfo.SoftwareVersion", wusp.String(softwareVersion))
	}
	if state.ProvisioningCode != "" {
		msg.Set("Device.DeviceInfo.ProvisioningCode", wusp.String(state.ProvisioningCode))
	}
	if uptimeSeconds := b.readUptimeSeconds(ctx); uptimeSeconds > 0 {
		msg.Set("Device.DeviceInfo.UpTime", wusp.Uint(uint64(uptimeSeconds)))
	}
	if hostname != "" {
		msg.Set("Device.DeviceInfo.HostName", wusp.String(hostname))
	}
	if friendlyName != "" {
		msg.Set("Device.DeviceInfo.FriendlyName", wusp.String(friendlyName))
	}
	if memTotal > 0 {
		msg.Set("Device.DeviceInfo.MemoryStatus.Total", wusp.Uint(memTotal))
	}
	if memFree > 0 {
		msg.Set("Device.DeviceInfo.MemoryStatus.Free", wusp.Uint(memFree))
	}
	if tcpImplementation := b.readTCPImplementation(ctx); tcpImplementation != "" {
		msg.Set("Device.DeviceInfo.NetworkProperties.TCPImplementation", wusp.List(wusp.String(tcpImplementation)))
	}

	if timeState.Known {
		msg.Set("Device.Time.Enable", wusp.Bool(timeState.Enabled))
		if !timeState.Enabled {
			msg.Set("Device.Time.Status", wusp.String("Disabled"))
		}
	}
	msg.Set("Device.Time.CurrentLocalTime", wusp.Time(now))
	if localTimeZone != "" {
		msg.Set("Device.Time.LocalTimeZone", wusp.String(localTimeZone))
	}

	msg.Set("Device.IP.IPv4Capable", wusp.Bool(true))
	msg.Set("Device.IP.IPv4Enable", wusp.Bool(true))
	msg.Set("Device.IP.IPv4Status", wusp.String("Enabled"))
	msg.Set("Device.IP.IPv6Capable", wusp.Bool(true))
	if ipv6Known {
		msg.Set("Device.IP.IPv6Enable", wusp.Bool(ipv6Enabled))
		msg.Set("Device.IP.IPv6Status", wusp.String(boolToStatus(ipv6Enabled)))
	}
	if interfaceCount := b.readInterfaceCount(); interfaceCount > 0 {
		msg.Set("Device.IP.InterfaceNumberOfEntries", wusp.Uint(uint64(interfaceCount)))
	}

	collectNetworkInterfacesStatic(msg)
	collectCPUInfoStatic(ctx, b.commandRunner, msg)
	collectCellularStatic(msg)
	collectGPSStatic(msg)
	collectMeshStatic(msg)

	return msg
}

// collectNetworkInterfacesStatic enumerates network interfaces via net.Interfaces()
// (getifaddrs on Unix) and populates Device.IP.Interface.{n}. entries.
func collectNetworkInterfacesStatic(msg *wusp.Message) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	idx := 1
	for _, iface := range ifaces {
		// Skip loopback and interfaces with no hardware address
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}

		prefix := fmt.Sprintf("Device.IP.Interface.%d.", idx)
		msg.Set(prefix+"Name", wusp.String(iface.Name))
		msg.Set(prefix+"Enable", wusp.Bool(iface.Flags&net.FlagUp != 0))
		msg.Set(prefix+"Status", wusp.String(ifaceStatus(iface.Flags)))
		msg.Set(prefix+"Type", wusp.String(ifaceType(iface.Name)))
		msg.Set(prefix+"MaxMTUSize", wusp.Uint(uint64(iface.MTU)))
		if len(iface.HardwareAddr) == 6 {
			msg.Set(prefix+"MACAddress", wusp.MAC(iface.HardwareAddr))
		}

		addrs, err := iface.Addrs()
		if err == nil {
			v4Idx, v6Idx := 1, 1
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				if ip4 := ipNet.IP.To4(); ip4 != nil {
					ipPrefix := fmt.Sprintf("%sIPv4Address.%d.", prefix, v4Idx)
					msg.Set(ipPrefix+"IPAddress", wusp.IP4(ip4))
					msg.Set(ipPrefix+"SubnetMask", wusp.IP4(net.IP(ipNet.Mask).To4()))
					msg.Set(ipPrefix+"AddressingType", wusp.String("DHCP"))
					v4Idx++
				} else if ip6 := ipNet.IP.To16(); ip6 != nil {
					ipPrefix := fmt.Sprintf("%sIPv6Address.%d.", prefix, v6Idx)
					msg.Set(ipPrefix+"IPAddress", wusp.IP6(ip6))
					ones, _ := ipNet.Mask.Size()
					// Prefix is a PathRef in BBF TR-181, stored as a string like "fe80::/64"
					msg.Set(ipPrefix+"Prefix", wusp.String(fmt.Sprintf("%s/%d", ipNet.IP.Mask(ipNet.Mask).String(), ones)))
					v6Idx++
				}
			}
		}
		idx++
	}
}

func ifaceStatus(flags net.Flags) string {
	if flags&net.FlagUp != 0 && flags&net.FlagRunning != 0 {
		return "Up"
	}
	if flags&net.FlagUp != 0 {
		return "Dormant"
	}
	return "Down"
}

func ifaceType(name string) string {
	switch {
	case strings.HasPrefix(name, "en"):
		return "Ethernet"
	case strings.HasPrefix(name, "wl"):
		return "WiFi"
	case strings.HasPrefix(name, "awdl"), strings.HasPrefix(name, "llw"):
		return "WiFi"
	case strings.HasPrefix(name, "utun"), strings.HasPrefix(name, "tun"):
		return "Tunnel"
	case strings.HasPrefix(name, "bridge"):
		return "Bridge"
	case strings.HasPrefix(name, "lo"):
		return "Loopback"
	default:
		return "Normal"
	}
}

func collectCPUInfoStatic(ctx context.Context, runner func(context.Context, string, ...string) ([]byte, error), msg *wusp.Message) {
	if runner == nil {
		return
	}
	if out, err := runner(ctx, "uname", "-m"); err == nil {
		arch := strings.TrimSpace(string(out))
		if arch != "" {
			msg.Set("Device.DeviceInfo.ProcessorNumberOfEntries", wusp.Uint(1))
			msg.Set("Device.DeviceInfo.Processor.1.Architecture", wusp.String(arch))
		}
	}
	if out, err := runner(ctx, "nproc"); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64); err == nil && n > 0 {
			msg.Set("Device.DeviceInfo.Processor.1.MaxNumberOfEntries", wusp.Uint(n))
		}
	} else if out, err := runner(ctx, "sysctl", "-n", "hw.ncpu"); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64); err == nil && n > 0 {
			msg.Set("Device.DeviceInfo.Processor.1.MaxNumberOfEntries", wusp.Uint(n))
		}
	}
}

// collectCellularStatic discovers and queries cellular modems, populating
// Device.Cellular.Interface.{n}. TR-181 params (IMEI, signal, registration, etc.)
func collectCellularStatic(msg *wusp.Message) {
	msg.Set("Device.Cellular.InterfaceNumberOfEntries", wusp.Uint(0))
	msg.Set("Device.Cellular.AccessPointNumberOfEntries", wusp.Uint(0))
	msg.Set("Device.Cellular.RoamingEnabled", wusp.Bool(false))

	ctl := modemPkg.New()
	defer ctl.Close()

	devices, err := ctl.Discover()
	if err != nil || len(devices) == 0 {
		return
	}

	ifaceIdx := 0
	apnIdx := 0
	anyRoaming := false
	for _, dev := range devices {
		info, err := ctl.GetInfo(dev)
		if err != nil || info == nil {
			continue
		}
		ifaceIdx++
		if info.Status == modemPkg.RegRoaming {
			anyRoaming = true
		}
		prefix := fmt.Sprintf("Device.Cellular.Interface.%d.", ifaceIdx)

		msg.Set(prefix+"Enable", wusp.Bool(true))
		msg.Set(prefix+"Status", wusp.String(cellularStatus(info)))
		msg.Set(prefix+"Alias", wusp.String("cpe-cellular-"+strconv.Itoa(ifaceIdx)))
		msg.Set(prefix+"Name", wusp.String(cellularInterfaceName(info, dev, ifaceIdx)))
		msg.Set(prefix+"LastChange", wusp.Uint(0))
		msg.Set(prefix+"LowerLayers", wusp.List())
		msg.Set(prefix+"Upstream", wusp.Bool(true))

		if validDigitString(info.IMEI, 15, 15) {
			msg.Set(prefix+"IMEI", wusp.String(info.IMEI))
		}

		msg.Set(prefix+"SupportedAccessTechnologies", wusp.List(cellularTechList(info.SupportedTechnologies)...))
		msg.Set(prefix+"PreferredAccessTechnology", wusp.String(cellularAccessTechnology(info.PreferredTechnology)))
		msg.Set(prefix+"CurrentAccessTechnology", wusp.String(cellularAccessTechnology(info.Technology)))
		msg.Set(prefix+"AvailableNetworks", cellularAvailableNetworks(info))
		msg.Set(prefix+"NetworkRequested", wusp.String(""))
		if info.Operator != "" || info.OperatorMCC != "" || info.OperatorMNC != "" {
			msg.Set(prefix+"NetworkInUse", wusp.String(cellularNetworkName(info)))
		}
		msg.Set(prefix+"Mode", wusp.String(cellularNRMode(info)))
		if info.UpstreamMaxBitRate > 0 {
			msg.Set(prefix+"UpstreamMaxBitRate", wusp.Uint(info.UpstreamMaxBitRate))
		}
		if info.DownstreamMaxBitRate > 0 {
			msg.Set(prefix+"DownstreamMaxBitRate", wusp.Uint(info.DownstreamMaxBitRate))
		}
		msg.Set(prefix+"SIMReferenceList", wusp.List())
		appendCellularTelemetryFields(msg, ifaceIdx, dev, info)

		// Signal quality
		sig := info.Signal
		if sig.RSSI != 0 {
			msg.Set(prefix+"RSSI", wusp.Int(int64(sig.RSSI)))
		}
		if sig.RSRP != 0 {
			msg.Set(prefix+"RSRP", wusp.Int(int64(sig.RSRP)))
		}
		if sig.RSRQ != 0 {
			msg.Set(prefix+"RSRQ", wusp.Int(int64(sig.RSRQ)))
		}
		if sig.SINR != 0 {
			msg.Set(prefix+"SINR", wusp.Int(int64(sig.SINR)))
		}

		// SIM / USIM
		if validDigitString(info.IMSI, 14, 15) {
			msg.Set(prefix+"USIM.IMSI", wusp.String(info.IMSI))
		}
		if validDigitString(info.ICCID, 6, 20) {
			msg.Set(prefix+"USIM.ICCID", wusp.String(info.ICCID))
		}
		if validDigitString(info.MSISDN, 14, 15) {
			msg.Set(prefix+"USIM.MSISDN", wusp.String(info.MSISDN))
		}
		msg.Set(prefix+"USIM.Status", wusp.String(cellularUSIMStatus(info.SIMStatus)))
		msg.Set(prefix+"USIM.PINCheck", wusp.String("Off"))

		// Traffic stats
		setCellularStats(msg, prefix, info)

		msg.Set(prefix+"SMS.StorageNumberOfEntries", wusp.Uint(cellularSMSStorageEntries(info)))
		msg.Set(prefix+"SMS.MessageNumberOfEntries", wusp.Uint(0))
		if info.SMSStorageLocation != "" {
			storagePrefix := prefix + "SMS.Storage.1."
			msg.Set(storagePrefix+"Alias", wusp.String("cpe-sms-storage-1"))
			msg.Set(storagePrefix+"Location", wusp.String(info.SMSStorageLocation))
			msg.Set(storagePrefix+"Capacity", wusp.Uint(info.SMSStorageCapacity))
			msg.Set(storagePrefix+"StorageAvailable", wusp.Bool(info.SMSStorageCapacity == 0 || info.SMSStorageUsed < info.SMSStorageCapacity))
			available := uint64(0)
			if info.SMSStorageCapacity > info.SMSStorageUsed {
				available = info.SMSStorageCapacity - info.SMSStorageUsed
			}
			msg.Set(storagePrefix+"AvailableCapacity", wusp.Uint(available))
			msg.Set(prefix+"SMS.Incoming.StorageRef", wusp.String(storagePrefix))
			msg.Set(prefix+"SMS.Incoming.CapacityLimit", wusp.Int(-1))
			msg.Set(prefix+"SMS.Outgoing.StorageRef", wusp.String(storagePrefix))
			msg.Set(prefix+"SMS.Outgoing.CapacityLimit", wusp.Int(-1))
		}

		if info.APN != "" {
			apnIdx++
			apnPrefix := fmt.Sprintf("Device.Cellular.AccessPoint.%d.", apnIdx)
			msg.Set(apnPrefix+"Enable", wusp.Bool(true))
			msg.Set(apnPrefix+"Alias", wusp.String("cpe-cellular-apn-"+strconv.Itoa(ifaceIdx)))
			msg.Set(apnPrefix+"APN", wusp.String(info.APN))
			msg.Set(apnPrefix+"Username", wusp.String(""))
			msg.Set(apnPrefix+"Password", wusp.String(""))
			msg.Set(apnPrefix+"Proxy", wusp.String(""))
			msg.Set(apnPrefix+"ProxyPort", wusp.Uint(1))
			msg.Set(apnPrefix+"Interface", wusp.String(fmt.Sprintf("Device.Cellular.Interface.%d.", ifaceIdx)))
			msg.Set(apnPrefix+"IPVersion", wusp.Int(-1))
			msg.Set(apnPrefix+"Type", wusp.List(wusp.String("default")))
		}
	}

	if ifaceIdx > 0 {
		msg.Set("Device.Cellular.InterfaceNumberOfEntries", wusp.Uint(uint64(ifaceIdx)))
		msg.Set("Device.Cellular.AccessPointNumberOfEntries", wusp.Uint(uint64(apnIdx)))
		if anyRoaming {
			msg.Set("Device.Cellular.RoamingStatus", wusp.String("Roaming"))
		} else {
			msg.Set("Device.Cellular.RoamingStatus", wusp.String("Home"))
		}
		msg.Set("Device.Cellular.RoamingEnabled", wusp.Bool(true))
	}
}

func cellularStatus(info *modemPkg.Info) string {
	if info == nil {
		return "Unknown"
	}
	if info.Connected || info.Status == modemPkg.RegHome || info.Status == modemPkg.RegRoaming {
		return "Up"
	}
	if info.Status == modemPkg.RegSearching {
		return "Dormant"
	}
	if info.Status == modemPkg.RegDenied || info.SIMStatus == modemPkg.SIMError {
		return "Error"
	}
	if info.SIMStatus == modemPkg.SIMAbsent {
		return "NotPresent"
	}
	return "Down"
}

func cellularInterfaceName(info *modemPkg.Info, devicePath string, idx int) string {
	for _, value := range []string{info.Interface, devicePath, fmt.Sprintf("cellular%d", idx)} {
		value = strings.TrimSpace(value)
		if value != "" {
			return filepath.Base(value)
		}
	}
	return fmt.Sprintf("cellular%d", idx)
}

func cellularAccessTechnology(tech modemPkg.Technology) string {
	switch tech {
	case modemPkg.TechGPRS:
		return "GPRS"
	case modemPkg.TechEDGE:
		return "EDGE"
	case modemPkg.TechUMTS:
		return "UMTS"
	case modemPkg.TechHSPA, modemPkg.TechHSPAPlus:
		return "UMTSHSPA"
	case modemPkg.TechLTE, modemPkg.TechLTEA:
		return "LTE"
	case modemPkg.TechNR5G, modemPkg.TechNR5GNSA:
		return "NR"
	default:
		return "Unknown"
	}
}

func cellularTechList(techs []modemPkg.Technology) []wusp.Value {
	if len(techs) == 0 {
		techs = []modemPkg.Technology{modemPkg.TechGPRS, modemPkg.TechEDGE, modemPkg.TechUMTS, modemPkg.TechHSPA, modemPkg.TechLTE}
	}
	seen := make(map[string]struct{})
	values := make([]wusp.Value, 0, len(techs))
	for _, tech := range techs {
		name := cellularAccessTechnology(tech)
		if name == "Unknown" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		values = append(values, wusp.String(name))
	}
	return values
}

func cellularAvailableNetworks(info *modemPkg.Info) wusp.Value {
	if info == nil || (info.Operator == "" && info.OperatorMCC == "" && info.OperatorMNC == "") {
		return wusp.List()
	}
	return wusp.List(wusp.String(cellularNetworkName(info)))
}

func cellularNetworkName(info *modemPkg.Info) string {
	name := strings.TrimSpace(info.Operator)
	plmn := strings.TrimSpace(info.OperatorMCC + info.OperatorMNC)
	if name != "" && plmn != "" && !strings.Contains(name, plmn) {
		return name + " (" + plmn + ")"
	}
	if name != "" {
		return name
	}
	return plmn
}

func cellularNRMode(info *modemPkg.Info) string {
	switch strings.ToLower(strings.TrimSpace(info.NRMode)) {
	case "standalone", "sa":
		return "Standalone"
	case "nonstandalone", "nsa", "non-standalone":
		return "NonStandalone"
	default:
		return "Unknown"
	}
}

func validDigitString(value string, minLen, maxLen int) bool {
	value = strings.TrimSpace(value)
	if len(value) < minLen || len(value) > maxLen {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func cellularUSIMStatus(status modemPkg.SIMStatus) string {
	switch status {
	case modemPkg.SIMReady:
		return "Valid"
	case modemPkg.SIMLocked:
		return "Blocked"
	case modemPkg.SIMError:
		return "Error"
	default:
		return "None"
	}
}

func setCellularStats(msg *wusp.Message, prefix string, info *modemPkg.Info) {
	stats := map[string]uint64{
		"BytesSent":                   info.TxBytes,
		"BytesReceived":               info.RxBytes,
		"PacketsSent":                 info.TxPackets,
		"PacketsReceived":             info.RxPackets,
		"ErrorsSent":                  info.TxErrors,
		"ErrorsReceived":              info.RxErrors,
		"UnicastPacketsSent":          info.TxPackets,
		"DiscardPacketsSent":          info.TxDropped,
		"DiscardPacketsReceived":      info.RxDropped,
		"MulticastPacketsSent":        info.TxMulticastPackets,
		"UnicastPacketsReceived":      info.RxPackets,
		"MulticastPacketsReceived":    info.RxMulticastPackets,
		"BroadcastPacketsSent":        info.TxBroadcastPackets,
		"BroadcastPacketsReceived":    info.RxBroadcastPackets,
		"UnknownProtoPacketsReceived": info.RxUnknownProtoPackets,
	}
	for name, value := range stats {
		msg.Set(prefix+"Stats."+name, wusp.Uint(value))
	}
}

func appendCellularTelemetryFields(msg *wusp.Message, ifaceIdx int, modemPath string, info *modemPkg.Info) {
	if msg == nil || info == nil || ifaceIdx <= 0 {
		return
	}
	root := fmt.Sprintf("Device.WUSP_CellularTelemetry.Interface.%d.", ifaceIdx)
	msg.Set("Device.WUSP_CellularTelemetry.InterfaceNumberOfEntries", wusp.Uint(uint64(ifaceIdx)))
	msg.Set(root+"Alias", wusp.String("cpe-cellular-telemetry-"+strconv.Itoa(ifaceIdx)))
	msg.Set(root+"InterfaceReference", wusp.String(fmt.Sprintf("Device.Cellular.Interface.%d.", ifaceIdx)))
	msg.Set(root+"ModemPath", wusp.String(firstNonEmpty(modemPath, info.Interface)))
	msg.Set(root+"Protocol", wusp.String(firstNonEmpty(info.Protocol, "unknown")))
	msg.Set(root+"NRMode", wusp.String(cellularNRMode(info)))
	if info.Band != "" {
		msg.Set(root+"Band", wusp.String(info.Band))
	}
	if info.CellID > 0 {
		msg.Set(root+"CellID", wusp.Uint(uint64(info.CellID)))
	}
	if info.TAC > 0 {
		msg.Set(root+"TAC", wusp.Uint(uint64(info.TAC)))
	}
	if info.LAC > 0 {
		msg.Set(root+"LAC", wusp.Uint(uint64(info.LAC)))
	}
	if info.DNS1 != "" {
		msg.Set(root+"DNS1", wusp.String(info.DNS1))
	}
	if info.DNS2 != "" {
		msg.Set(root+"DNS2", wusp.String(info.DNS2))
	}
	if ip := net.ParseIP(info.IPAddress); ip != nil && ip.To4() != nil {
		msg.Set(root+"IPv4Address", wusp.IP4(ip))
	}
	if ip := net.ParseIP(info.IPv6Address); ip != nil && ip.To16() != nil && ip.To4() == nil {
		msg.Set(root+"IPv6Address", wusp.IP6(ip))
	}

	for i, carrier := range info.CarrierAggregation {
		prefix := fmt.Sprintf("%sCarrier.%d.", root, i+1)
		msg.Set(prefix+"Role", wusp.String(firstNonEmpty(carrier.Role, "Unknown")))
		msg.Set(prefix+"RAT", wusp.String(firstNonEmpty(carrier.RAT, "Unknown")))
		if carrier.Band != "" {
			msg.Set(prefix+"Band", wusp.String(carrier.Band))
		}
		if carrier.EARFCN > 0 {
			msg.Set(prefix+"EARFCN", wusp.Uint(carrier.EARFCN))
		}
		if carrier.PCI > 0 {
			msg.Set(prefix+"PCI", wusp.Uint(carrier.PCI))
		}
		if carrier.Bandwidth != "" {
			msg.Set(prefix+"Bandwidth", wusp.String(carrier.Bandwidth))
		}
		if carrier.RSRP != 0 {
			msg.Set(prefix+"RSRP", wusp.Int(int64(carrier.RSRP)))
		}
		if carrier.RSRQ != 0 {
			msg.Set(prefix+"RSRQ", wusp.Int(int64(carrier.RSRQ)))
		}
		if carrier.SINR != 0 {
			msg.Set(prefix+"SINR", wusp.Int(int64(carrier.SINR)))
		}
		if carrier.Raw != "" {
			msg.Set(prefix+"Raw", wusp.String(carrier.Raw))
		}
	}
	msg.Set(root+"CarrierNumberOfEntries", wusp.Uint(uint64(len(info.CarrierAggregation))))

	for i, cell := range info.NeighborCells {
		prefix := fmt.Sprintf("%sNeighborCell.%d.", root, i+1)
		msg.Set(prefix+"RAT", wusp.String(firstNonEmpty(cell.RAT, "Unknown")))
		msg.Set(prefix+"Relation", wusp.String(cell.Relation))
		if cell.Frequency > 0 {
			msg.Set(prefix+"Frequency", wusp.Uint(cell.Frequency))
		}
		if cell.PCI > 0 {
			msg.Set(prefix+"PCI", wusp.Uint(cell.PCI))
		}
		if cell.RSRP != 0 {
			msg.Set(prefix+"RSRP", wusp.Int(int64(cell.RSRP)))
		}
		if cell.RSRQ != 0 {
			msg.Set(prefix+"RSRQ", wusp.Int(int64(cell.RSRQ)))
		}
		if cell.Raw != "" {
			msg.Set(prefix+"Raw", wusp.String(cell.Raw))
		}
	}
	msg.Set(root+"NeighborCellNumberOfEntries", wusp.Uint(uint64(len(info.NeighborCells))))
}

func cellularSMSStorageEntries(info *modemPkg.Info) uint64 {
	if info != nil && info.SMSStorageLocation != "" {
		return 1
	}
	return 0
}

func (b *hostBackend) readState() (hostState, error) {
	var state hostState
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
		return hostState{}, err
	}
	return state, nil
}

func (b *hostBackend) updateState(update func(*hostState)) error {
	state, _ := b.readState()
	update(&state)
	return b.writeState(state)
}

func (b *hostBackend) writeState(state hostState) error {
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

func (b *hostBackend) readHostname(ctx context.Context) string {
	hostname := strings.TrimSpace(readTextFile(b.hostnamePath))
	if hostname != "" {
		return hostname
	}
	if output := b.commandOutput(ctx, "hostname"); output != "" {
		return output
	}
	host, _ := os.Hostname()
	return strings.TrimSpace(host)
}

func (b *hostBackend) readManufacturer(ctx context.Context) string {
	switch b.kind {
	case KindMacOS:
		return "Apple"
	case KindWindows:
		return firstNonEmpty(
			b.commandOutput(ctx, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Manufacturer"),
			"Microsoft",
		)
	case KindAndroid:
		props := b.readBuildProps()
		return firstNonEmpty(props["ro.product.manufacturer"], props["ro.product.brand"], "Android")
	case KindONU:
		return firstNonEmpty(
			strings.TrimSpace(readTextFile(b.deviceVendorPath)),
			strings.TrimSpace(readAssignmentFileValue(b.onuReleasePath, "VENDOR")),
			"ONU",
		)
	default:
		return firstNonEmpty(
			strings.TrimSpace(readTextFile(b.deviceVendorPath)),
			readAssignmentFileValue(b.osReleasePath, "NAME"),
			"Linux",
		)
	}
}

func (b *hostBackend) readModelName(ctx context.Context) string {
	switch b.kind {
	case KindMacOS:
		return firstNonEmpty(
			b.commandOutput(ctx, "sysctl", "-n", "hw.model"),
			"Mac",
		)
	case KindWindows:
		return b.commandOutput(ctx, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Model")
	case KindAndroid:
		props := b.readBuildProps()
		return firstNonEmpty(props["ro.product.model"], props["ro.product.device"], "Android")
	default:
		return firstNonEmpty(
			strings.TrimSpace(readTextFile(b.deviceModelPath)),
			readAssignmentFileValue(b.onuReleasePath, "MODEL"),
			readAssignmentFileValue(b.osReleasePath, "NAME"),
		)
	}
}

func (b *hostBackend) readHardwareVersion(ctx context.Context) string {
	switch b.kind {
	case KindMacOS:
		return b.commandOutput(ctx, "sysctl", "-n", "kern.osproductversion")
	case KindWindows:
		return b.commandOutput(ctx, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_BaseBoard).Version")
	case KindAndroid:
		props := b.readBuildProps()
		return firstNonEmpty(props["ro.build.version.incremental"], props["ro.build.id"])
	default:
		return firstNonEmpty(
			strings.TrimSpace(readTextFile(b.deviceVersionPath)),
			readAssignmentFileValue(b.onuReleasePath, "HW_VERSION"),
		)
	}
}

func (b *hostBackend) readSoftwareVersion(ctx context.Context) string {
	switch b.kind {
	case KindMacOS:
		return firstNonEmpty(
			b.commandOutput(ctx, "sw_vers", "-productVersion"),
			b.commandOutput(ctx, "uname", "-r"),
		)
	case KindWindows:
		return firstNonEmpty(
			b.commandOutput(ctx, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_OperatingSystem).Version"),
			b.commandOutput(ctx, "cmd", "/C", "ver"),
		)
	case KindAndroid:
		props := b.readBuildProps()
		return firstNonEmpty(props["ro.build.version.release"], props["ro.build.display.id"], props["ro.build.id"])
	default:
		return firstNonEmpty(
			readAssignmentFileValue(b.osReleasePath, "PRETTY_NAME"),
			readAssignmentFileValue(b.osReleasePath, "VERSION_ID"),
			readAssignmentFileValue(b.onuReleasePath, "VERSION"),
			b.commandOutput(ctx, "uname", "-r"),
		)
	}
}

func (b *hostBackend) readSerialNumber(ctx context.Context) string {
	switch b.kind {
	case KindMacOS:
		output := b.commandOutput(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		if output == "" {
			return ""
		}
		for _, line := range strings.Split(output, "\n") {
			if !strings.Contains(line, "IOPlatformSerialNumber") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			return strings.Trim(strings.TrimSpace(parts[1]), `"`)
		}
		return ""
	case KindWindows:
		return firstNonEmpty(
			b.commandOutput(ctx, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_BIOS).SerialNumber"),
			b.commandOutput(ctx, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"),
		)
	case KindAndroid:
		props := b.readBuildProps()
		return firstNonEmpty(props["ro.serialno"], props["ro.boot.serialno"], props["ro.boot.hardware.sku"])
	default:
		return firstNonEmpty(
			strings.TrimSpace(readTextFile(b.serialNumberPath)),
			strings.TrimSpace(readTextFile(b.machineIDPath)),
			readAssignmentFileValue(b.onuReleasePath, "SERIAL"),
		)
	}
}

func (b *hostBackend) readMemory(ctx context.Context) (uint64, uint64) {
	if total, free := readMemInfo(b.memInfoPath); total > 0 || free > 0 {
		return total, free
	}

	switch b.kind {
	case KindMacOS:
		totalBytes, _ := strconv.ParseUint(strings.TrimSpace(b.commandOutput(ctx, "sysctl", "-n", "hw.memsize")), 10, 64)
		pageSize, freePages := parseVMStat(b.commandOutput(ctx, "vm_stat"))
		return totalBytes / 1024, (pageSize * freePages) / 1024
	case KindWindows:
		payload := b.commandOutput(ctx, "powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress")
		total, free := parseWindowsMemoryJSON(payload)
		return total, free
	default:
		return 0, 0
	}
}

func (b *hostBackend) readUptimeSeconds(ctx context.Context) int64 {
	if seconds := readUptimeSeconds(b.uptimePath); seconds > 0 {
		return seconds
	}

	switch b.kind {
	case KindMacOS:
		return parseMacBootTime(b.commandOutput(ctx, "sysctl", "-n", "kern.boottime"), b.now())
	case KindWindows:
		out := b.commandOutput(ctx, "powershell", "-NoProfile", "-Command", "[int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds")
		value, _ := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		if value > 0 {
			return value
		}
	case KindAndroid:
		fallthrough
	default:
	}

	return 0
}

func (b *hostBackend) readTCPImplementation(ctx context.Context) string {
	if value := sanitizeTCPImplementation(readTextFile(b.tcpImplementationPath)); value != "" {
		return value
	}

	switch b.kind {
	case KindMacOS:
		return "CUBIC"
	case KindWindows, KindAndroid, KindONU:
		return "Other"
	default:
		if output := b.commandOutput(ctx, "sysctl", "-n", "net.ipv4.tcp_congestion_control"); output != "" {
			return sanitizeTCPImplementation(output)
		}
		return "Other"
	}
}

func (b *hostBackend) readLocalTimeZone(ctx context.Context) string {
	if value := strings.TrimSpace(readTextFile(b.timezonePath)); value != "" {
		return value
	}

	switch b.kind {
	case KindMacOS:
		return strings.TrimPrefix(b.commandOutput(ctx, "systemsetup", "-gettimezone"), "Time Zone: ")
	case KindWindows:
		return b.commandOutput(ctx, "tzutil", "/g")
	case KindAndroid:
		return firstNonEmpty(
			b.commandOutput(ctx, "getprop", "persist.sys.timezone"),
			b.commandOutput(ctx, "getprop", "persist.sys.timezone"),
		)
	default:
		if value := b.commandOutput(ctx, "timedatectl", "show", "-p", "Timezone", "--value"); value != "" {
			return value
		}
	}

	if _, zone := b.now().Zone(); zone != 0 {
		return b.now().Location().String()
	}
	return b.now().Location().String()
}

func (b *hostBackend) readTimeEnabled(ctx context.Context) timeState {
	switch b.kind {
	case KindMacOS:
		output := strings.ToLower(b.commandOutput(ctx, "systemsetup", "-getusingnetworktime"))
		switch {
		case strings.Contains(output, "on"):
			return timeState{Enabled: true, Known: true}
		case strings.Contains(output, "off"):
			return timeState{Enabled: false, Known: true}
		}
	case KindWindows:
		output := strings.ToLower(b.commandOutput(ctx, "powershell", "-NoProfile", "-Command", "(Get-Service w32time).Status"))
		switch {
		case strings.Contains(output, "running"):
			return timeState{Enabled: true, Known: true}
		case strings.Contains(output, "stopped"), strings.Contains(output, "disabled"):
			return timeState{Enabled: false, Known: true}
		}
	case KindAndroid:
		switch strings.TrimSpace(b.commandOutput(ctx, "settings", "get", "global", "auto_time")) {
		case "1", "true":
			return timeState{Enabled: true, Known: true}
		case "0", "false":
			return timeState{Enabled: false, Known: true}
		}
	default:
		output := strings.ToLower(b.commandOutput(ctx, "timedatectl", "show", "-p", "NTP", "--value"))
		switch output {
		case "yes", "true", "1":
			return timeState{Enabled: true, Known: true}
		case "no", "false", "0":
			return timeState{Enabled: false, Known: true}
		}
	}

	return timeState{}
}

func (b *hostBackend) readIPv6Enabled(ctx context.Context) (bool, bool) {
	switch strings.TrimSpace(readTextFile(b.ipv6DisablePath)) {
	case "0":
		return true, true
	case "1":
		return false, true
	}

	switch b.kind {
	case KindMacOS, KindWindows:
		return true, true
	case KindAndroid, KindLinux, KindONU:
		if output := strings.ToLower(b.commandOutput(ctx, "sysctl", "-n", "net.ipv6.conf.all.disable_ipv6")); output != "" {
			switch output {
			case "0":
				return true, true
			case "1":
				return false, true
			}
		}
	}

	return false, false
}

func (b *hostBackend) readInterfaceCount() int {
	if b.netClassDir != "" {
		entries, err := os.ReadDir(b.netClassDir)
		if err == nil {
			count := 0
			for _, entry := range entries {
				if strings.TrimSpace(entry.Name()) != "" {
					count++
				}
			}
			if count > 0 {
				return count
			}
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	return len(ifaces)
}

func (b *hostBackend) readManufacturerOUI() string {
	if b.netClassDir != "" {
		entries, err := os.ReadDir(b.netClassDir)
		if err == nil {
			for _, entry := range entries {
				address := strings.TrimSpace(readTextFile(filepath.Join(b.netClassDir, entry.Name(), "address")))
				if oui := formatOUI(address); oui != "" {
					return oui
				}
			}
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if oui := hardwareAddrOUI(iface.HardwareAddr); oui != "" {
			return oui
		}
	}
	return ""
}

func (b *hostBackend) setHostname(ctx context.Context, hostname string) error {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return &wusp.ValidationError{Path: "Device.DeviceInfo.HostName", Reason: "empty hostname"}
	}

	switch b.kind {
	case KindMacOS:
		for _, args := range [][]string{
			{"--set", "HostName", hostname},
			{"--set", "LocalHostName", hostname},
			{"--set", "ComputerName", hostname},
		} {
			if _, err := b.commandRunner(ctx, "scutil", args...); err != nil {
				return err
			}
		}
		return nil
	case KindWindows:
		command := fmt.Sprintf("Rename-Computer -NewName '%s' -Force", escapePowerShellLiteral(hostname))
		_, err := b.commandRunner(ctx, "powershell", "-NoProfile", "-Command", command)
		return err
	case KindAndroid:
		for _, args := range [][]string{
			{"net.hostname", hostname},
			{"persist.net.hostname", hostname},
		} {
			if _, err := b.commandRunner(ctx, "setprop", args...); err != nil {
				return err
			}
		}
		return nil
	default:
		if _, err := b.commandRunner(ctx, "hostnamectl", "set-hostname", hostname); err == nil {
			return nil
		}
		_, err := b.commandRunner(ctx, "hostname", hostname)
		return err
	}
}

func (b *hostBackend) setTimeEnabled(ctx context.Context, enabled bool) error {
	switch b.kind {
	case KindMacOS:
		value := "off"
		if enabled {
			value = "on"
		}
		_, err := b.commandRunner(ctx, "systemsetup", "-setusingnetworktime", value)
		return err
	case KindWindows:
		if enabled {
			if _, err := b.commandRunner(ctx, "powershell", "-NoProfile", "-Command", "Set-Service w32time -StartupType Automatic; Start-Service w32time"); err != nil {
				return err
			}
			return nil
		}
		_, err := b.commandRunner(ctx, "powershell", "-NoProfile", "-Command", "Stop-Service w32time -ErrorAction SilentlyContinue; Set-Service w32time -StartupType Disabled")
		return err
	case KindAndroid:
		value := "0"
		if enabled {
			value = "1"
		}
		_, err := b.commandRunner(ctx, "settings", "put", "global", "auto_time", value)
		return err
	default:
		value := "false"
		if enabled {
			value = "true"
		}
		_, err := b.commandRunner(ctx, "timedatectl", "set-ntp", value)
		return err
	}
}

func (b *hostBackend) setTimeZone(ctx context.Context, timezone string) error {
	timezone = strings.TrimSpace(timezone)
	if timezone == "" {
		return &wusp.ValidationError{Path: "Device.Time.LocalTimeZone", Reason: "empty timezone"}
	}

	switch b.kind {
	case KindMacOS:
		_, err := b.commandRunner(ctx, "systemsetup", "-settimezone", timezone)
		return err
	case KindWindows:
		_, err := b.commandRunner(ctx, "tzutil", "/s", timezone)
		return err
	case KindAndroid:
		_, err := b.commandRunner(ctx, "setprop", "persist.sys.timezone", timezone)
		return err
	default:
		_, err := b.commandRunner(ctx, "timedatectl", "set-timezone", timezone)
		return err
	}
}

func (b *hostBackend) commandOutput(ctx context.Context, name string, args ...string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	output, err := b.commandRunner(ctx, name, args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func (b *hostBackend) productClass() string {
	switch b.kind {
	case KindMacOS:
		return "Mac"
	case KindWindows:
		return "Windows"
	case KindAndroid:
		return "Android"
	case KindONU:
		return "ONU"
	default:
		return "Linux"
	}
}

func (b *hostBackend) readBuildProps() map[string]string {
	values, _ := parseAssignmentFile(b.buildPropPath)
	return values
}

func defaultStatePath(kind Kind) string {
	switch kind {
	case KindMacOS:
		return "/Library/Application Support/Wantastic/usp-macos.json"
	case KindWindows:
		return `C:\ProgramData\Wantastic\usp-windows.json`
	case KindAndroid:
		return "/data/local/tmp/wantastic-usp.json"
	case KindONU:
		return defaultWantasticStatePath("usp-onu.json")
	default:
		return defaultWantasticStatePath("usp-host.json")
	}
}

func defaultHostnamePath(kind Kind) string {
	switch kind {
	case KindLinux, KindAndroid, KindONU:
		return "/proc/sys/kernel/hostname"
	default:
		return ""
	}
}

func defaultUptimePath(kind Kind) string {
	switch kind {
	case KindLinux, KindAndroid, KindONU:
		return "/proc/uptime"
	default:
		return ""
	}
}

func defaultMemInfoPath(kind Kind) string {
	switch kind {
	case KindLinux, KindAndroid, KindONU:
		return "/proc/meminfo"
	default:
		return ""
	}
}

func defaultIPv6DisablePath(kind Kind) string {
	switch kind {
	case KindLinux, KindAndroid, KindONU:
		return "/proc/sys/net/ipv6/conf/all/disable_ipv6"
	default:
		return ""
	}
}

func defaultTCPImplementationPath(kind Kind) string {
	switch kind {
	case KindLinux, KindAndroid, KindONU:
		return "/proc/sys/net/ipv4/tcp_congestion_control"
	default:
		return ""
	}
}

func defaultOSReleasePath(kind Kind) string {
	switch kind {
	case KindLinux, KindONU:
		return "/etc/os-release"
	default:
		return ""
	}
}

func defaultSerialNumberPath(kind Kind) string {
	switch kind {
	case KindLinux:
		return "/sys/devices/virtual/dmi/id/product_serial"
	case KindONU:
		return "/proc/device-tree/serial-number"
	default:
		return ""
	}
}

func defaultMachineIDPath(kind Kind) string {
	switch kind {
	case KindLinux, KindONU:
		return "/etc/machine-id"
	default:
		return ""
	}
}

func defaultDeviceModelPath(kind Kind) string {
	switch kind {
	case KindLinux:
		return "/sys/devices/virtual/dmi/id/product_name"
	case KindAndroid, KindONU:
		return "/proc/device-tree/model"
	default:
		return ""
	}
}

func defaultDeviceVendorPath(kind Kind) string {
	switch kind {
	case KindLinux:
		return "/sys/devices/virtual/dmi/id/sys_vendor"
	case KindONU:
		return "/sys/firmware/devicetree/base/vendor"
	default:
		return ""
	}
}

func defaultDeviceVersionPath(kind Kind) string {
	switch kind {
	case KindLinux:
		return "/sys/devices/virtual/dmi/id/product_version"
	case KindONU:
		return "/sys/firmware/devicetree/base/hardware-revision"
	default:
		return ""
	}
}

func defaultBuildPropPath(kind Kind) string {
	if kind == KindAndroid {
		return "/system/build.prop"
	}
	return ""
}

func defaultTimezonePath(kind Kind) string {
	switch kind {
	case KindLinux, KindONU:
		return "/etc/timezone"
	default:
		return ""
	}
}

func defaultNetClassDir(kind Kind) string {
	switch kind {
	case KindLinux, KindAndroid, KindONU:
		return "/sys/class/net"
	default:
		return ""
	}
}

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func coalesceString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func readFileQuiet(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func readDirQuiet(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

func readTextFile(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func readMemInfo(path string) (uint64, uint64) {
	data := readTextFile(path)
	if data == "" {
		return 0, 0
	}
	var total uint64
	var free uint64
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

func readUptimeSeconds(path string) int64 {
	data := strings.TrimSpace(readTextFile(path))
	if data == "" {
		return 0
	}
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return 0
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || value < 0 {
		return 0
	}
	return int64(value)
}

func parseAssignmentFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return values, nil
}

func readAssignmentFileValue(path, key string) string {
	values, err := parseAssignmentFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(values[key])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func sanitizeTCPImplementation(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "CUBIC":
		return "CUBIC"
	case "RENO":
		return "Reno"
	case "BIC":
		return "BIC"
	case "HYBLA":
		return "Hybla"
	case "WESTWOOD":
		return "Westwood"
	case "VEGAS":
		return "Vegas"
	case "SCALABLE":
		return "Scalable"
	case "LP":
		return "LP"
	case "VENO":
		return "Veno"
	case "BBR":
		return "BBR"
	default:
		return "Other"
	}
}

func boolToStatus(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}

func parseVMStat(output string) (uint64, uint64) {
	var pageSize uint64 = 4096
	var freePages uint64
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "page size of") {
			fields := strings.Fields(line)
			for i := range fields {
				if fields[i] == "of" && i+1 < len(fields) {
					if value, err := strconv.ParseUint(fields[i+1], 10, 64); err == nil {
						pageSize = value
					}
				}
			}
		}
		if strings.HasPrefix(line, "Pages free:") {
			value := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "Pages free:")), ".")
			freePages, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	return pageSize, freePages
}

func parseWindowsMemoryJSON(output string) (uint64, uint64) {
	var payload struct {
		TotalVisibleMemorySize uint64 `json:"TotalVisibleMemorySize"`
		FreePhysicalMemory     uint64 `json:"FreePhysicalMemory"`
	}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		return 0, 0
	}
	return payload.TotalVisibleMemorySize, payload.FreePhysicalMemory
}

func parseMacBootTime(output string, now time.Time) int64 {
	if output == "" {
		return 0
	}
	idx := strings.Index(output, "sec =")
	if idx == -1 {
		return 0
	}
	rest := strings.TrimSpace(output[idx+len("sec ="):])
	end := strings.IndexByte(rest, ',')
	if end == -1 {
		return 0
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(rest[:end]), 10, 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	uptime := now.Unix() - seconds
	if uptime < 0 {
		return 0
	}
	return uptime
}

func formatOUI(address string) string {
	mac, err := net.ParseMAC(strings.TrimSpace(address))
	if err != nil {
		return ""
	}
	return hardwareAddrOUI(mac)
}

func hardwareAddrOUI(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	for _, b := range mac {
		if b != 0 {
			return strings.ToUpper(fmt.Sprintf("%02X%02X%02X", mac[0], mac[1], mac[2]))
		}
	}
	return ""
}

func hasONUMarker(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(value, " onu"),
		strings.HasPrefix(value, "onu"),
		strings.Contains(value, "gpon"),
		strings.Contains(value, "xgs-pon"),
		strings.Contains(value, "xpon"),
		strings.Contains(value, "pon"),
		strings.Contains(value, "ont"):
		return true
	default:
		return false
	}
}

func escapePowerShellLiteral(value string) string {
	return strings.ReplaceAll(value, `'`, `''`)
}
