//go:build windows

package platforms

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	modKernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx   = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemFirmwareTable = modKernel32.NewProc("GetSystemFirmwareTable")
	procSetComputerNameExW     = modKernel32.NewProc("SetComputerNameExW")
	procGetTickCount64         = modKernel32.NewProc("GetTickCount64")
	modWlanapi                 = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle         = modWlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle        = modWlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces     = modWlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface     = modWlanapi.NewProc("WlanQueryInterface")
	procWlanSetInterface       = modWlanapi.NewProc("WlanSetInterface")
	procWlanFreeMemory         = modWlanapi.NewProc("WlanFreeMemory")
)

const (
	computerNamePhysicalDNSHostname = 5

	wlanOpcodeRadioState        = 4
	wlanOpcodeCurrentConnection = 7
	wlanOpcodeChannelNumber     = 8
	wlanOpcodeRSSI              = 0x10000102
	wlanStateConnected          = 1
	dot11RadioOn                = 1
	dot11RadioOff               = 2

	w32timeParams = `SYSTEM\CurrentControlSet\Services\W32Time\Parameters`
	w32timeKey    = `SYSTEM\CurrentControlSet\Services\W32Time`
	tzInfoKey     = `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`
	tzListKey     = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones`
)

type windowsProbe struct {
	run CommandRunner

	mu     sync.Mutex
	static *desktopSnapshot // identity that does not change while running
}

func newDesktopProbe(run CommandRunner) desktopProbe { return &windowsProbe{run: run} }

func regString(path, name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	value, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func regUint(path, name string) (uint64, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	value, _, err := k.GetIntegerValue(name)
	return value, err == nil
}

func notPlaceholder(values ...string) string {
	for _, v := range values {
		if !smbiosPlaceholder(v) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (p *windowsProbe) identity() *desktopSnapshot {
	if p.static != nil {
		return p.static
	}
	const bios = `HARDWARE\DESCRIPTION\System\BIOS`
	const nt = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	s := &desktopSnapshot{
		Manufacturer:   firstNonEmpty(notPlaceholder(regString(bios, "SystemManufacturer"), regString(bios, "BaseBoardManufacturer")), "Microsoft"),
		ModelName:      notPlaceholder(regString(bios, "SystemProductName"), regString(bios, "BaseBoardProduct")),
		ProcessorModel: regString(`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString"),
		Architecture:   windowsArchitecture(),
		SerialNumber:   windowsSerialNumber(),
	}
	s.ModelNumber = firstNonEmpty(notPlaceholder(regString(bios, "SystemSKU")), s.ModelName)
	s.HardwareVersion = notPlaceholder(regString(bios, "SystemVersion"), regString(bios, "BaseBoardVersion"))
	if v := notPlaceholder(regString(bios, "BIOSVersion")); s.HardwareVersion == "" && v != "" {
		s.HardwareVersion = "BIOS " + v
	}

	build, _ := strconv.Atoi(regString(nt, "CurrentBuild"))
	ubr, _ := regUint(nt, "UBR")
	major, okMajor := regUint(nt, "CurrentMajorVersionNumber")
	minor, _ := regUint(nt, "CurrentMinorVersionNumber")
	if !okMajor {
		major = 10
	}
	if build > 0 {
		s.SoftwareVersion = fmt.Sprintf("%d.%d.%d.%d", major, minor, build, ubr)
	}
	product := windowsProductName(regString(nt, "ProductName"), build)
	if display := regString(nt, "DisplayVersion"); display != "" {
		product += " " + display
	}
	if build > 0 {
		product += fmt.Sprintf(" (%d.%d)", build, ubr)
	}
	s.Description = strings.TrimSpace(product)
	if s.SerialNumber != "" && s.ModelName != "" {
		p.static = s // the firmware read worked; keep it
	}
	return s
}

func windowsArchitecture() string {
	arch := os.Getenv("PROCESSOR_ARCHITEW6432")
	if arch == "" {
		arch = os.Getenv("PROCESSOR_ARCHITECTURE")
	}
	switch strings.ToUpper(arch) {
	case "AMD64":
		return "x86_64"
	case "ARM64":
		return "arm64"
	case "X86":
		return "i686"
	}
	return strings.ToLower(arch)
}

// windowsSerialNumber reads the SMBIOS table, which needs no WMI.
func windowsSerialNumber() string {
	if procGetSystemFirmwareTable.Find() != nil {
		return ""
	}
	const rsmb = 0x52534D42 // 'RSMB'
	size, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, 0, 0)
	if size == 0 || size > 1<<20 {
		return ""
	}
	buf := make([]byte, size)
	n, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, uintptr(unsafe.Pointer(&buf[0])), size)
	if n == 0 || n > size {
		return ""
	}
	return parseSMBIOSSerial(rawSMBIOSTable(buf[:n]))
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func (p *windowsProbe) collect(ctx context.Context) *desktopSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()

	id := p.identity()
	snap := *id
	snap.Interfaces = make(map[string]desktopInterface)
	if host, err := os.Hostname(); err == nil {
		snap.Hostname = host
		snap.ComputerName = host
	}
	var mem memoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&mem))); r != 0 {
		snap.MemTotalKiB, snap.MemFreeKiB = mem.TotalPhys/1024, mem.AvailPhys/1024
	}
	if lo, hi, _ := procGetTickCount64.Call(); lo != 0 || hi != 0 {
		ms := uint64(lo)
		if unsafe.Sizeof(lo) == 4 { // 386: the result comes back in EDX:EAX
			ms |= uint64(hi) << 32
		}
		snap.UptimeSeconds = int64(ms / 1000)
	}

	zone := regString(tzInfoKey, "TimeZoneKeyName")
	snap.TimeZone = firstNonEmpty(windowsZoneToIANA[zone], zone)

	syncType := strings.ToUpper(regString(w32timeParams, "Type"))
	start, _ := regUint(w32timeKey, "Start")
	snap.Time = timeState{Known: syncType != "", Enabled: syncType != "" && syncType != "NOSYNC" && start != 4}
	snap.NTPServers = parseW32TimeServers(regString(w32timeParams, "NtpServer"))

	adapters := windowsAdapters()
	for _, a := range adapters {
		snap.Interfaces[a.name] = a.info
	}
	snap.WiFi = windowsWiFi(adapters)
	return &snap
}

type windowsAdapter struct {
	name string // FriendlyName, the net.Interfaces() name
	guid string // AdapterName, "{...}"
	mac  net.HardwareAddr
	info desktopInterface
}

func windowsAdapters() []windowsAdapter {
	size := uint32(16 << 10)
	var buf []byte
	for attempt := 0; attempt < 3; attempt++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil
		}
		buf = nil
	}
	if buf == nil {
		return nil
	}
	var out []windowsAdapter
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		ad := windowsAdapter{
			name: windows.UTF16PtrToString(a.FriendlyName),
			guid: windows.BytePtrToString(a.AdapterName),
		}
		if a.PhysicalAddressLength > 0 && a.PhysicalAddressLength <= uint32(len(a.PhysicalAddress)) {
			ad.mac = append(net.HardwareAddr(nil), a.PhysicalAddress[:a.PhysicalAddressLength]...)
		}
		ad.info.Wireless = a.IfType == windows.IF_TYPE_IEEE80211
		ad.info.Tunnel = a.IfType == windows.IF_TYPE_TUNNEL || a.IfType == 53 // IF_TYPE_PROP_VIRTUAL: Wintun
		if speed := a.TransmitLinkSpeed; speed > 0 && speed != ^uint64(0) {
			ad.info.SpeedMbps = speed / 1_000_000
		}
		row := windows.MibIfRow2{InterfaceLuid: a.Luid}
		if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row) == nil {
			ad.info.StatsKnown = true
			ad.info.Stats = desktopCounters{
				BytesReceived: row.InOctets, BytesSent: row.OutOctets,
				PacketsReceived: row.InUcastPkts + row.InNUcastPkts, PacketsSent: row.OutUcastPkts + row.OutNUcastPkts,
				ErrorsReceived: row.InErrors, ErrorsSent: row.OutErrors,
				DiscardsReceived: row.InDiscards, DiscardsSent: row.OutDiscards,
			}
		}
		out = append(out, ad)
	}
	return out
}

// WLAN API structures (wlanapi.h).
type wlanInterfaceInfo struct {
	InterfaceGUID windows.GUID
	Description   [256]uint16
	State         uint32
}

type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
	InterfaceInfo [1]wlanInterfaceInfo
}

type wlanConnectionAttributes struct {
	State          uint32
	ConnectionMode uint32
	ProfileName    [256]uint16
	SSIDLength     uint32
	SSID           [32]byte
	BSSType        uint32
	BSSID          [6]byte
	PhyType        uint32
	PhyIndex       uint32
	SignalQuality  uint32
	RxRateKbps     uint32
	TxRateKbps     uint32
	SecurityOn     int32
	OneXOn         int32
	AuthAlgorithm  uint32
	CipherAlgo     uint32
}

type wlanPhyRadioState struct {
	PhyIndex      uint32
	SoftwareState uint32
	HardwareState uint32
}

type wlanRadioState struct {
	NumberOfPhys uint32
	Phys         [64]wlanPhyRadioState
}

type wlanSession struct{ handle uintptr }

func openWlan() (*wlanSession, error) {
	if err := modWlanapi.Load(); err != nil {
		return nil, err // no WLAN service (Server Core, VMs)
	}
	var negotiated uint32
	var handle uintptr
	if r, _, _ := procWlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle))); r != 0 {
		return nil, windows.Errno(r)
	}
	return &wlanSession{handle: handle}, nil
}

func (s *wlanSession) close() { procWlanCloseHandle.Call(s.handle, 0) }

// interfaces returns the GUID and connection state of every WLAN adapter.
func (s *wlanSession) interfaces() []wlanInterfaceInfo {
	var list *wlanInterfaceInfoList
	if r, _, _ := procWlanEnumInterfaces.Call(s.handle, 0, uintptr(unsafe.Pointer(&list))); r != 0 || list == nil {
		return nil
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(list)))
	items := unsafe.Slice(&list.InterfaceInfo[0], list.NumberOfItems)
	return append([]wlanInterfaceInfo(nil), items...)
}

// query copies the opcode's data into dst and reports whether it filled it.
func (s *wlanSession) query(guid *windows.GUID, opcode uint32, dst []byte) bool {
	var size uint32
	var data *byte
	var valueType uint32
	r, _, _ := procWlanQueryInterface.Call(s.handle, uintptr(unsafe.Pointer(guid)), uintptr(opcode), 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&valueType)))
	if r != 0 || data == nil {
		return false
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(data)))
	copy(dst, unsafe.Slice(data, size))
	return int(size) >= len(dst)
}

func asBytes[T any](v *T) []byte { return unsafe.Slice((*byte)(unsafe.Pointer(v)), unsafe.Sizeof(*v)) }

func (s *wlanSession) radioOn(guid *windows.GUID) bool {
	// The reply holds only the PHYs the adapter has, so it rarely fills
	// the 64-entry struct.
	var radio wlanRadioState
	s.query(guid, wlanOpcodeRadioState, asBytes(&radio))
	n := min(int(radio.NumberOfPhys), len(radio.Phys))
	for _, phy := range radio.Phys[:n] {
		if phy.SoftwareState == dot11RadioOn && phy.HardwareState == dot11RadioOn {
			return true
		}
	}
	return n == 0
}

func windowsWiFi(adapters []windowsAdapter) []desktopWiFi {
	session, err := openWlan()
	if err != nil {
		return nil
	}
	defer session.close()
	byGUID := make(map[string]windowsAdapter, len(adapters))
	for _, a := range adapters {
		byGUID[strings.ToUpper(a.guid)] = a
	}
	var out []desktopWiFi
	for _, info := range session.interfaces() {
		guid := info.InterfaceGUID
		adapter := byGUID[strings.ToUpper(guid.String())]
		w := desktopWiFi{
			Interface: firstNonEmpty(adapter.name, windows.UTF16ToString(info.Description[:])),
			MAC:       adapter.mac,
			PowerOn:   session.radioOn(&guid),
		}
		if info.State == wlanStateConnected {
			var conn wlanConnectionAttributes
			if session.query(&guid, wlanOpcodeCurrentConnection, asBytes(&conn)) {
				w.Connected = true
				if n := min(int(conn.SSIDLength), len(conn.SSID)); n > 0 {
					w.SSID = string(conn.SSID[:n])
				}
				w.BSSID = append(net.HardwareAddr(nil), conn.BSSID[:]...)
				w.Standard = windowsWiFiStandard(conn.PhyType)
				w.RxRateKbps, w.TxRateKbps = uint64(conn.RxRateKbps), uint64(conn.TxRateKbps)
				w.Security = windowsSecurityMode(conn.AuthAlgorithm, conn.SecurityOn != 0)
				// Quality is linear from -100 dBm (0) to -50 dBm (100).
				w.RSSI, w.RSSIKnown = int(conn.SignalQuality)/2-100, true
			}
			var channel uint32
			if session.query(&guid, wlanOpcodeChannelNumber, asBytes(&channel)) && channel > 0 {
				w.Channel = int(channel)
				w.Band = windowsWiFiBand(w.Channel, 0)
			}
			var rssi int32
			if session.query(&guid, wlanOpcodeRSSI, asBytes(&rssi)) && rssi < 0 && rssi > -120 {
				w.RSSI, w.RSSIKnown = int(rssi), true
			}
		}
		out = append(out, w)
	}
	return out
}

func (p *windowsProbe) setHostname(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if err := validDesktopHostname(name); err != nil {
		return err
	}
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	// Windows applies a new computer name at the next restart.
	if r, _, callErr := procSetComputerNameExW.Call(computerNamePhysicalDNSHostname, uintptr(unsafe.Pointer(ptr))); r == 0 {
		return fmt.Errorf("set computer name: %w", callErr)
	}
	return nil
}

// setTimeZone accepts an IANA name (Europe/Paris) or a Windows one
// (Romance Standard Time).
func (p *windowsProbe) setTimeZone(ctx context.Context, zone string) error {
	zone = strings.TrimSpace(zone)
	name := zone
	if mapped, ok := ianaToWindowsZone[zone]; ok {
		name = mapped
	}
	unknown := errors.New("unknown time zone " + strconv.Quote(zone) + "; use an IANA name such as Europe/Paris")
	if name == "" || strings.ContainsAny(name, `\/"`) {
		return unknown
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tzListKey+`\`+name, registry.QUERY_VALUE)
	if err != nil {
		return unknown
	}
	k.Close()
	_, err = p.run(ctx, "tzutil", "/s", name)
	return err
}

// startW32Time makes the time service start with Windows and run now.
func startW32Time() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService("W32Time")
	if err != nil {
		return err
	}
	defer s.Close()
	if cfg, err := s.Config(); err == nil && cfg.StartType != mgr.StartAutomatic {
		cfg.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(cfg); err != nil {
			return err
		}
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return nil
}

func (p *windowsProbe) setTimeEnabled(ctx context.Context, on bool) error {
	if !on {
		_, err := p.run(ctx, "w32tm", "/config", "/syncfromflags:NO", "/update")
		return err
	}
	if err := startW32Time(); err != nil {
		return err
	}
	if _, err := p.run(ctx, "w32tm", "/config", "/syncfromflags:manual", "/update"); err != nil {
		return err
	}
	_, _ = p.run(ctx, "w32tm", "/resync", "/nowait")
	return nil
}

func (p *windowsProbe) setNTPServers(ctx context.Context, servers []string) error {
	servers, err := normalizeNTPServers(servers)
	if err != nil {
		return err
	}
	if len(servers) == 0 {
		servers = []string{"time.windows.com"}
	}
	peers := make([]string, len(servers))
	for i, server := range servers {
		peers[i] = server + ",0x9" // SpecialInterval | Client
	}
	if err := startW32Time(); err != nil {
		return err
	}
	if _, err := p.run(ctx, "w32tm", "/config", "/manualpeerlist:"+strings.Join(peers, " "), "/syncfromflags:manual", "/update"); err != nil {
		return err
	}
	_, _ = p.run(ctx, "w32tm", "/resync", "/nowait")
	return nil
}

func (p *windowsProbe) setWiFiRadio(ctx context.Context, ifname string, on bool) error {
	if !on {
		if err := ensureNotLastUplink(ifname); err != nil {
			return err
		}
	}
	session, err := openWlan()
	if err != nil {
		return err
	}
	defer session.close()
	adapters := windowsAdapters()
	for _, info := range session.interfaces() {
		guid := info.InterfaceGUID
		for _, a := range adapters {
			if !strings.EqualFold(a.guid, guid.String()) || a.name != ifname {
				continue
			}
			var radio wlanRadioState
			session.query(&guid, wlanOpcodeRadioState, asBytes(&radio))
			state := uint32(dot11RadioOff)
			if on {
				state = dot11RadioOn
			}
			n := max(1, min(int(radio.NumberOfPhys), len(radio.Phys)))
			for i := 0; i < n; i++ {
				phy := wlanPhyRadioState{PhyIndex: uint32(i), SoftwareState: state}
				if r, _, _ := procWlanSetInterface.Call(session.handle, uintptr(unsafe.Pointer(&guid)), wlanOpcodeRadioState,
					unsafe.Sizeof(phy), uintptr(unsafe.Pointer(&phy)), 0); r != 0 {
					return fmt.Errorf("set Wi-Fi radio: %w", windows.Errno(r))
				}
			}
			return nil
		}
	}
	return fmt.Errorf("%s is not a Wi-Fi adapter", ifname)
}
