//go:build linux && !qmi && !mbim

package modem

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	mm "github.com/maltegrosse/go-modemmanager"
)

type modemManagerController struct {
	at atController
}

func (c *modemManagerController) Close() error { return nil }

func (c *modemManagerController) Discover() ([]string, error) {
	modems, err := c.modemManagerModems()
	if err == nil && len(modems) > 0 {
		out := make([]string, 0, len(modems))
		for _, modem := range modems {
			out = append(out, string(modem.GetObjectPath()))
		}
		return out, nil
	}
	return c.at.Discover()
}

func (c *modemManagerController) GetInfo(devicePath string) (*Info, error) {
	if modem, ok := c.modemForPath(devicePath); ok {
		return c.infoFromModemManager(modem, devicePath), nil
	}
	return c.at.GetInfo(devicePath)
}

func (c *modemManagerController) GetSignal(devicePath string) (*SignalQuality, error) {
	info, err := c.GetInfo(devicePath)
	if err != nil {
		return nil, err
	}
	return &info.Signal, nil
}

func (c *modemManagerController) Connect(devicePath, apn string) error {
	modem, ok := c.modemForPath(devicePath)
	if !ok {
		return c.at.Connect(devicePath, apn)
	}
	simple, err := modem.GetSimpleModem()
	if err != nil {
		return err
	}
	_, err = simple.Connect(mm.SimpleProperties{
		Apn:            strings.TrimSpace(apn),
		IpType:         mm.MmBearerIpFamilyIpv4v6,
		AllowedRoaming: true,
	})
	return err
}

func (c *modemManagerController) Disconnect(devicePath string) error {
	modem, ok := c.modemForPath(devicePath)
	if !ok {
		return c.at.Disconnect(devicePath)
	}
	bearers, err := modem.GetBearers()
	if err != nil {
		return err
	}
	disconnected := false
	var lastErr error
	for _, bearer := range bearers {
		connected, err := bearer.GetConnected()
		if err != nil || !connected {
			continue
		}
		if err := bearer.Disconnect(); err != nil {
			lastErr = err
			continue
		}
		disconnected = true
	}
	if lastErr != nil && !disconnected {
		return lastErr
	}
	return nil
}

func (c *modemManagerController) modemManagerModems() ([]mm.Modem, error) {
	manager, err := mm.NewModemManager()
	if err != nil {
		return nil, err
	}
	return manager.GetModems()
}

func (c *modemManagerController) modemForPath(devicePath string) (mm.Modem, bool) {
	devicePath = strings.TrimSpace(devicePath)
	if devicePath == "" {
		return nil, false
	}
	if strings.HasPrefix(devicePath, "/org/freedesktop/ModemManager") {
		modem, err := mm.NewModem(dbus.ObjectPath(devicePath))
		return modem, err == nil
	}
	modems, err := c.modemManagerModems()
	if err != nil {
		return nil, false
	}
	for _, modem := range modems {
		if modemManagerModemMatchesPath(modem, devicePath) {
			return modem, true
		}
	}
	return nil, false
}

func modemManagerModemMatchesPath(modem mm.Modem, devicePath string) bool {
	if modem == nil {
		return false
	}
	for _, candidate := range modemManagerPathCandidates(modem) {
		if modemManagerSameDevicePath(candidate, devicePath) {
			return true
		}
	}
	return false
}

func modemManagerPathCandidates(modem mm.Modem) []string {
	var out []string
	out = append(out, string(modem.GetObjectPath()))
	if value, err := modem.GetDevice(); err == nil {
		out = append(out, value)
	}
	if value, err := modem.GetPrimaryPort(); err == nil {
		out = append(out, value, "/dev/"+filepath.Base(value))
	}
	if ports, err := modem.GetPorts(); err == nil {
		for _, port := range ports {
			out = append(out, port.PortName, "/dev/"+filepath.Base(port.PortName))
		}
	}
	if bearers, err := modem.GetBearers(); err == nil {
		for _, bearer := range bearers {
			if iface, err := bearer.GetInterface(); err == nil {
				out = append(out, iface)
			}
		}
	}
	return out
}

func modemManagerSameDevicePath(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	baseA := filepath.Base(a)
	baseB := filepath.Base(b)
	return baseA != "." && baseA == baseB
}

func (c *modemManagerController) infoFromModemManager(modem mm.Modem, requestedPath string) *Info {
	info := &Info{
		Interface:   requestedPath,
		Protocol:    "modemmanager",
		CollectedAt: time.Now(),
		NRMode:      "Unknown",
		SIMStatus:   SIMAbsent,
	}

	if value, err := modem.GetManufacturer(); err == nil {
		info.Manufacturer = strings.TrimSpace(value)
	}
	if value, err := modem.GetModel(); err == nil {
		info.Model = strings.TrimSpace(value)
	}
	if value, err := modem.GetRevision(); err == nil {
		info.Revision = strings.TrimSpace(value)
	}
	if value, err := modem.GetEquipmentIdentifier(); err == nil {
		info.IMEI = strings.TrimSpace(value)
	}
	if value, err := modem.GetOwnNumbers(); err == nil && len(value) > 0 {
		info.MSISDN = strings.TrimSpace(value[0])
	}
	if value, err := modem.GetPrimaryPort(); err == nil && info.Interface == "" {
		info.Interface = strings.TrimSpace(value)
	}

	c.applyModemManagerState(modem, info)
	c.applyModemManager3GPP(modem, info)
	c.applyModemManagerSIM(modem, info)
	c.applyModemManagerSignal(modem, info)
	c.applyModemManagerBearers(modem, info)

	if info.Interface != "" {
		c.at.enrichFromNetStats(info.Interface, info)
	}
	info.SupportedTechnologies = inferSupportedTechnologies(info)
	return info
}

func (c *modemManagerController) applyModemManagerState(modem mm.Modem, info *Info) {
	if state, err := modem.GetState(); err == nil {
		info.Connected = state == mm.MmModemStateConnected
		info.Status = modemManagerStateToRegistration(state)
	}
	if techs, err := modem.GetAccessTechnologies(); err == nil && len(techs) > 0 {
		info.SupportedTechnologies = modemManagerTechList(techs)
		info.Technology = firstKnownTech(info.Technology, modemManagerBestTech(techs))
	}
	if bands, err := modem.GetCurrentBands(); err == nil && len(bands) > 0 {
		info.Band = modemManagerBandString(bands)
	}
	if percent, _, err := modem.GetSignalQuality(); err == nil && percent > 0 {
		info.Signal.Bars = int((percent + 19) / 20)
		if info.Signal.Bars > 5 {
			info.Signal.Bars = 5
		}
		info.Signal.CSQ = int((percent * 31) / 100)
	}
}

func (c *modemManagerController) applyModemManager3GPP(modem mm.Modem, info *Info) {
	g3, err := modem.Get3gpp()
	if err != nil {
		return
	}
	if value, err := g3.GetImei(); err == nil && info.IMEI == "" {
		info.IMEI = strings.TrimSpace(value)
	}
	if value, err := g3.GetOperatorName(); err == nil {
		info.Operator = firstNonEmpty(info.Operator, strings.TrimSpace(value))
	}
	if value, err := g3.GetOperatorCode(); err == nil {
		setOperatorCode(info, value)
	}
	if state, err := g3.GetRegistrationState(); err == nil {
		info.Status = firstKnownReg(info.Status, modemManager3GPPRegistration(state))
	}
	if settings, err := g3.GetInitialEpsBearerSettings(); err == nil {
		info.APN = firstNonEmpty(info.APN, settings.APN)
		info.IPVersion = firstNonZeroInt(info.IPVersion, modemManagerIPFamily(settings.IPType))
	}
}

func (c *modemManagerController) applyModemManagerSIM(modem mm.Modem, info *Info) {
	if lock, err := modem.GetUnlockRequired(); err == nil {
		info.SIMStatus = modemManagerSIMStatus(lock)
	}
	sim, err := modem.GetSim()
	if err != nil {
		return
	}
	if info.SIMStatus == SIMAbsent {
		info.SIMStatus = SIMReady
	}
	if value, err := sim.GetImsi(); err == nil {
		info.IMSI = strings.TrimSpace(value)
	}
	if value, err := sim.GetSimIdentifier(); err == nil {
		info.ICCID = strings.TrimSpace(value)
	}
	if value, err := sim.GetOperatorIdentifier(); err == nil {
		setOperatorCode(info, value)
	}
	if value, err := sim.GetOperatorName(); err == nil {
		info.Operator = firstNonEmpty(info.Operator, strings.TrimSpace(value))
	}
}

func (c *modemManagerController) applyModemManagerSignal(modem mm.Modem, info *Info) {
	signal, err := modem.GetSignal()
	if err != nil {
		return
	}
	if lte, err := signal.GetLte(); err == nil {
		applyModemManagerSignalProperty(&info.Signal, lte)
	}
	if umts, err := signal.GetUmts(); err == nil {
		applyModemManagerSignalProperty(&info.Signal, umts)
	}
	if gsm, err := signal.GetGsm(); err == nil {
		applyModemManagerSignalProperty(&info.Signal, gsm)
	}
	if evdo, err := signal.GetEvdo(); err == nil {
		applyModemManagerSignalProperty(&info.Signal, evdo)
	}
	if cdma, err := signal.GetCdma(); err == nil {
		applyModemManagerSignalProperty(&info.Signal, cdma)
	}
}

func (c *modemManagerController) applyModemManagerBearers(modem mm.Modem, info *Info) {
	bearers, err := modem.GetBearers()
	if err != nil {
		return
	}
	for _, bearer := range bearers {
		connected, _ := bearer.GetConnected()
		if !connected && info.APN != "" && info.Interface != "" {
			continue
		}
		iface, _ := bearer.GetInterface()
		if iface != "" {
			info.Interface = strings.TrimSpace(iface)
		}
		if connected {
			info.Connected = true
		}
		if props, err := bearer.GetProperties(); err == nil {
			info.APN = firstNonEmpty(info.APN, props.APN)
			info.IPVersion = firstNonZeroInt(info.IPVersion, modemManagerIPFamily(props.IPType))
		}
		if ip4, err := bearer.GetIp4Config(); err == nil {
			applyModemManagerIPConfig(info, ip4)
		}
		if ip6, err := bearer.GetIp6Config(); err == nil {
			applyModemManagerIPConfig(info, ip6)
		}
		if stats, err := bearer.GetStats(); err == nil {
			info.TxBytes = firstNonZero(info.TxBytes, stats.TxBytes)
			info.RxBytes = firstNonZero(info.RxBytes, stats.RxBytes)
		}
		if connected {
			break
		}
	}
}

func applyModemManagerIPConfig(info *Info, config mm.BearerIpConfig) {
	switch config.IpFamily {
	case mm.MmBearerIpFamilyIpv4:
		info.IPAddress = firstNonEmpty(info.IPAddress, config.Address)
		info.IPVersion = firstNonZeroInt(info.IPVersion, 4)
	case mm.MmBearerIpFamilyIpv6:
		info.IPv6Address = firstNonEmpty(info.IPv6Address, config.Address)
		info.IPVersion = firstNonZeroInt(info.IPVersion, 6)
	case mm.MmBearerIpFamilyIpv4v6:
		info.IPVersion = firstNonZeroInt(info.IPVersion, -1)
	}
	info.DNS1 = firstNonEmpty(info.DNS1, config.Dns1)
	info.DNS2 = firstNonEmpty(info.DNS2, config.Dns2)
}

func applyModemManagerSignalProperty(signal *SignalQuality, prop mm.SignalProperty) {
	if value := roundSignal(prop.Rssi); value != 0 {
		signal.RSSI = value
	}
	if value := roundSignal(prop.Rsrp); value != 0 {
		signal.RSRP = value
	}
	if value := roundSignal(prop.Rsrq); value != 0 {
		signal.RSRQ = value
	}
	if value := roundSignal(firstNonZeroFloat(prop.Snr, prop.Sinr)); value != 0 {
		signal.SINR = value
	}
	if value := roundSignal(prop.Rscp); value != 0 {
		signal.RSCP = value
	}
	if value := roundSignal(prop.Ecio); value != 0 {
		signal.ECIO = value
	}
}

func modemManagerStateToRegistration(state mm.MMModemState) RegistrationStatus {
	switch state {
	case mm.MmModemStateSearching:
		return RegSearching
	case mm.MmModemStateFailed:
		return RegDenied
	case mm.MmModemStateRegistered, mm.MmModemStateConnecting, mm.MmModemStateConnected:
		return RegHome
	default:
		return RegNotRegistered
	}
}

func modemManager3GPPRegistration(state mm.MMModem3gppRegistrationState) RegistrationStatus {
	switch state {
	case mm.MmModem3gppRegistrationStateHome,
		mm.MmModem3gppRegistrationStateHomeSmsOnly,
		mm.MmModem3gppRegistrationStateHomeCsfbNotPreferred:
		return RegHome
	case mm.MmModem3gppRegistrationStateRoaming,
		mm.MmModem3gppRegistrationStateRoamingSmsOnly,
		mm.MmModem3gppRegistrationStateRoamingCsfbNotPreferred:
		return RegRoaming
	case mm.MmModem3gppRegistrationStateSearching:
		return RegSearching
	case mm.MmModem3gppRegistrationStateDenied,
		mm.MmModem3gppRegistrationStateEmergencyOnly:
		return RegDenied
	default:
		return RegUnknown
	}
}

func modemManagerSIMStatus(lock mm.MMModemLock) SIMStatus {
	switch lock {
	case mm.MmModemLockNone:
		return SIMReady
	case mm.MmModemLockSimPin, mm.MmModemLockSimPin2, mm.MmModemLockSimPuk, mm.MmModemLockSimPuk2:
		return SIMLocked
	case mm.MmModemLockUnknown:
		return SIMAbsent
	default:
		return SIMError
	}
}

func modemManagerTechList(techs []mm.MMModemAccessTechnology) []Technology {
	out := make([]Technology, 0, len(techs))
	seen := make(map[Technology]struct{})
	for _, tech := range techs {
		mapped := modemManagerTechnology(tech)
		if mapped == TechUnknown {
			continue
		}
		if _, ok := seen[mapped]; ok {
			continue
		}
		seen[mapped] = struct{}{}
		out = append(out, mapped)
	}
	return out
}

func modemManagerBestTech(techs []mm.MMModemAccessTechnology) Technology {
	best := TechUnknown
	bestRank := 0
	for _, tech := range techs {
		mapped := modemManagerTechnology(tech)
		if rank := technologyRank(mapped); rank > bestRank {
			best = mapped
			bestRank = rank
		}
	}
	return best
}

func modemManagerTechnology(tech mm.MMModemAccessTechnology) Technology {
	switch tech {
	case mm.MmModemAccessTechnologyGsm, mm.MmModemAccessTechnologyGsmCompact:
		return TechGSM
	case mm.MmModemAccessTechnologyGprs:
		return TechGPRS
	case mm.MmModemAccessTechnologyEdge:
		return TechEDGE
	case mm.MmModemAccessTechnologyUmts:
		return TechUMTS
	case mm.MmModemAccessTechnologyHsdpa, mm.MmModemAccessTechnologyHsupa, mm.MmModemAccessTechnologyHspa:
		return TechHSPA
	case mm.MmModemAccessTechnologyHspaPlus:
		return TechHSPAPlus
	case mm.MmModemAccessTechnologyLte:
		return TechLTE
	default:
		return TechUnknown
	}
}

func technologyRank(tech Technology) int {
	switch tech {
	case TechNR5G:
		return 90
	case TechNR5GNSA:
		return 80
	case TechLTEA:
		return 70
	case TechLTE:
		return 60
	case TechHSPAPlus:
		return 50
	case TechHSPA:
		return 40
	case TechUMTS:
		return 30
	case TechEDGE:
		return 20
	case TechGPRS:
		return 10
	case TechGSM:
		return 5
	default:
		return 0
	}
}

func modemManagerBandString(bands []mm.MMModemBand) string {
	if len(bands) == 0 {
		return ""
	}
	parts := make([]string, 0, len(bands))
	for _, band := range bands {
		value := strings.TrimSpace(fmt.Sprint(band))
		if value == "" {
			continue
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, ",")
}

func modemManagerIPFamily(family mm.MMBearerIpFamily) int {
	switch family {
	case mm.MmBearerIpFamilyIpv4:
		return 4
	case mm.MmBearerIpFamilyIpv6:
		return 6
	case mm.MmBearerIpFamilyIpv4v6:
		return -1
	default:
		return 0
	}
}

func setOperatorCode(info *Info, code string) {
	code = strings.TrimSpace(code)
	if len(code) < 5 {
		return
	}
	info.OperatorMCC = firstNonEmpty(info.OperatorMCC, code[:3])
	info.OperatorMNC = firstNonEmpty(info.OperatorMNC, code[3:])
}

func firstNonZeroInt(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func firstNonZeroFloat(values ...float64) float64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func roundSignal(value float64) int {
	if value == 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return int(math.Round(value))
}
