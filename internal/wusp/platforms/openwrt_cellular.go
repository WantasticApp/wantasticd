package platforms

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	modemPkg "wantastic-agent/internal/modem"
	"wantastic-agent/internal/wusp"
)

func (b *OpenWrtBackend) appendOpenWrtCellularConfig(msg *wusp.Message) {
	if msg == nil {
		return
	}
	parsed, err := b.readUCIConfig("network")
	if err != nil {
		return
	}

	liveIfaceCount := messageUint(msg, "Device.Cellular.InterfaceNumberOfEntries")
	ifaceIdx := liveIfaceCount
	apnIdx := messageUint(msg, "Device.Cellular.AccessPointNumberOfEntries")
	configIdx := uint64(0)
	ctl := newModemController()
	defer ctl.Close()

	for _, section := range parsed.Sections {
		if !isOpenWrtCellularSection(section) {
			continue
		}
		configIdx++
		targetIfaceIdx := configIdx
		createInterface := targetIfaceIdx > liveIfaceCount
		name := firstNonEmpty(section.Name, fmt.Sprintf("cellular%d", ifaceIdx))
		enabled := !parseOpenWrtBool(section.Options["disabled"], false)
		info, devicePath := b.collectOpenWrtCellularInfo(ctl, section)
		if info != nil && !enabled && !info.Connected {
			info.Status = modemPkg.RegNotRegistered
			info.SIMStatus = modemPkg.SIMAbsent
		}
		if createInterface {
			if info == nil || !shouldPublishCellularInfo(devicePath, info) {
				continue
			}
			ifaceIdx++
			targetIfaceIdx = ifaceIdx
		}
		ifacePath := fmt.Sprintf("Device.Cellular.Interface.%d.", targetIfaceIdx)

		msg.Set(ifacePath+"Enable", wusp.Bool(enabled))
		if createInterface {
			info.Interface = firstNonEmpty(info.Interface, name)
		}
		if info != nil {
			setCellularInterfaceFields(msg, int(targetIfaceIdx), devicePath, info)
			setCellularControlFields(msg, int(targetIfaceIdx), devicePath, info)
			msg.Set("Device.WUSP_CellularControl.InterfaceNumberOfEntries", wusp.Uint(targetIfaceIdx))
		}
		msg.Set(ifacePath+"Enable", wusp.Bool(enabled))
		if !enabled {
			msg.Set(ifacePath+"Status", wusp.String("Down"))
		}

		apn := strings.TrimSpace(section.Options["apn"])
		if apn == "" {
			continue
		}
		apnIdx++
		apnPath := fmt.Sprintf("Device.Cellular.AccessPoint.%d.", apnIdx)
		msg.Set(apnPath+"Enable", wusp.Bool(enabled))
		msg.Set(apnPath+"Alias", wusp.String("cpe-cellular-apn-"+strconv.FormatUint(apnIdx, 10)))
		msg.Set(apnPath+"APN", wusp.String(apn))
		msg.Set(apnPath+"Username", wusp.String(section.Options["username"]))
		msg.Set(apnPath+"Password", wusp.String(section.Options["password"]))
		msg.Set(apnPath+"Proxy", wusp.String(""))
		msg.Set(apnPath+"ProxyPort", wusp.Uint(1))
		msg.Set(apnPath+"Interface", wusp.String(ifacePath))
		msg.Set(apnPath+"IPVersion", wusp.Int(-1))
		msg.Set(apnPath+"Type", openWrtCellularAPNType(section))
	}

	msg.Set("Device.Cellular.InterfaceNumberOfEntries", wusp.Uint(ifaceIdx))
	msg.Set("Device.Cellular.AccessPointNumberOfEntries", wusp.Uint(apnIdx))
}

func (b *OpenWrtBackend) collectOpenWrtCellularInfo(ctl modemPkg.Controller, section openWrtUCISection) (*modemPkg.Info, string) {
	if ctl == nil {
		return nil, ""
	}
	candidates := openWrtCellularDeviceCandidates(section)
	var statsOnly *modemPkg.Info
	var statsOnlyPath string
	for _, candidate := range candidates {
		info, err := ctl.GetInfo(candidate)
		if err != nil || info == nil {
			continue
		}
		b.enrichOpenWrtCellularNetStats(info, section)
		if shouldPublishCellularInfo(candidate, info) {
			return info, candidate
		}
		if statsOnly == nil && hasCellularStats(info) {
			statsCopy := *info
			statsOnly = &statsCopy
			statsOnlyPath = candidate
		}
	}

	if devices, err := ctl.Discover(); err == nil {
		seen := make(map[string]struct{}, len(candidates))
		for _, candidate := range candidates {
			seen[candidate] = struct{}{}
		}
		for _, candidate := range devices {
			if _, ok := seen[candidate]; ok {
				continue
			}
			info, err := ctl.GetInfo(candidate)
			if err != nil || info == nil {
				continue
			}
			b.enrichOpenWrtCellularNetStats(info, section)
			if shouldPublishCellularInfo(candidate, info) {
				return info, candidate
			}
			if statsOnly == nil && hasCellularStats(info) {
				statsCopy := *info
				statsOnly = &statsCopy
				statsOnlyPath = candidate
			}
		}
	}

	info := &modemPkg.Info{
		Interface: firstOpenWrtCellularNetdev(section),
		Protocol:  strings.TrimSpace(section.Options["proto"]),
	}
	b.enrichOpenWrtCellularNetStats(info, section)
	if statsOnly != nil {
		mergeCellularStats(statsOnly, info)
		return statsOnly, statsOnlyPath
	}
	if info.Interface == "" || !hasOpenWrtCellularRuntimeData(info) {
		return nil, ""
	}
	return info, info.Interface
}

func openWrtCellularDeviceCandidates(section openWrtUCISection) []string {
	raw := []string{
		section.Options["device"],
		section.Options["ifname"],
		section.Options["interface"],
		section.Options["modem"],
		section.Options["control"],
		section.Options["at_device"],
		section.Options["atdevice"],
	}
	raw = append(raw, section.Lists["device"]...)
	raw = append(raw, section.Lists["ifname"]...)

	seen := make(map[string]struct{})
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		for part := range strings.FieldsSeq(strings.ReplaceAll(value, ",", " ")) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, ok := seen[part]; ok {
				continue
			}
			seen[part] = struct{}{}
			out = append(out, part)
		}
	}
	return out
}

func (b *OpenWrtBackend) enrichOpenWrtCellularNetStats(info *modemPkg.Info, section openWrtUCISection) {
	if info == nil {
		return
	}
	iface := firstNonEmpty(info.Interface, firstOpenWrtCellularNetdev(section))
	if strings.HasPrefix(iface, "/dev/") || strings.Contains(iface, "/") {
		iface = firstOpenWrtCellularNetdev(section)
	}
	if iface == "" {
		return
	}
	base := filepath.Join(b.netClassDir, filepath.Base(iface))
	stats := filepath.Join(base, "statistics")
	info.Interface = filepath.Base(iface)
	info.TxBytes = firstNonZeroUint(info.TxBytes, readUintTextFile(filepath.Join(stats, "tx_bytes")))
	info.RxBytes = firstNonZeroUint(info.RxBytes, readUintTextFile(filepath.Join(stats, "rx_bytes")))
	info.TxPackets = firstNonZeroUint(info.TxPackets, readUintTextFile(filepath.Join(stats, "tx_packets")))
	info.RxPackets = firstNonZeroUint(info.RxPackets, readUintTextFile(filepath.Join(stats, "rx_packets")))
	info.TxErrors = firstNonZeroUint(info.TxErrors, readUintTextFile(filepath.Join(stats, "tx_errors")))
	info.RxErrors = firstNonZeroUint(info.RxErrors, readUintTextFile(filepath.Join(stats, "rx_errors")))
	info.TxDropped = firstNonZeroUint(info.TxDropped, readUintTextFile(filepath.Join(stats, "tx_dropped")))
	info.RxDropped = firstNonZeroUint(info.RxDropped, readUintTextFile(filepath.Join(stats, "rx_dropped")))
	info.RxMulticastPackets = firstNonZeroUint(info.RxMulticastPackets, readUintTextFile(filepath.Join(stats, "multicast")))
	if speed := readUintTextFile(filepath.Join(base, "speed")); speed > 0 {
		info.UpstreamMaxBitRate = firstNonZeroUint(info.UpstreamMaxBitRate, speed*1000*1000)
		info.DownstreamMaxBitRate = firstNonZeroUint(info.DownstreamMaxBitRate, speed*1000*1000)
	}
	if state := strings.TrimSpace(b.readTextFile(filepath.Join(base, "operstate"))); state == "up" {
		info.Connected = true
	}
	if carrier := strings.TrimSpace(b.readTextFile(filepath.Join(base, "carrier"))); carrier == "1" {
		info.Connected = true
	}
}

func firstOpenWrtCellularNetdev(section openWrtUCISection) string {
	for _, candidate := range openWrtCellularDeviceCandidates(section) {
		base := filepath.Base(candidate)
		if base == "." || strings.HasPrefix(candidate, "/dev/") {
			continue
		}
		return base
	}
	return ""
}

func hasOpenWrtCellularRuntimeData(info *modemPkg.Info) bool {
	return hasCellularRuntimeData(info) ||
		info.IMEI != "" || info.IMSI != "" || info.ICCID != ""
}

func (b *OpenWrtBackend) setOpenWrtCellularParam(ctx context.Context, path string, value wusp.Value) error {
	if strings.HasPrefix(path, "Device.Cellular.Interface.") {
		return b.setOpenWrtCellularInterfaceParam(ctx, path, value)
	}
	if strings.HasPrefix(path, "Device.Cellular.AccessPoint.") {
		return b.setOpenWrtCellularAccessPointParam(ctx, path, value)
	}
	return wusp.ErrUSPPathUnsupported
}

func (b *OpenWrtBackend) setOpenWrtCellularInterfaceParam(ctx context.Context, path string, value wusp.Value) error {
	index, leaf, ok := parseIndexedPath(path, "Device.Cellular.Interface.")
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}
	section := b.openWrtCellularSection(index)
	if section == "" {
		return wusp.ErrUSPPathUnsupported
	}
	switch leaf {
	case "Enable":
		enabled, err := boolValue("Cellular.Interface.Enable", value)
		if err != nil {
			return err
		}
		disabled := "1"
		if enabled {
			disabled = "0"
		}
		return b.setUCIOption(ctx, "network", section, "disabled", disabled, true, networkReloadScript)
	default:
		return wusp.ErrUSPPathUnsupported
	}
}

func (b *OpenWrtBackend) setOpenWrtCellularAccessPointParam(ctx context.Context, path string, value wusp.Value) error {
	index, leaf, ok := parseIndexedPath(path, "Device.Cellular.AccessPoint.")
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}
	section := b.openWrtCellularAPNSection(index)
	if section == "" {
		return wusp.ErrUSPPathUnsupported
	}
	option, converted, err := openWrtCellularAPNOptionValue(leaf, value)
	if err != nil {
		return err
	}
	if option == "" {
		return nil
	}
	return b.setUCIOption(ctx, "network", section, option, converted, true, networkReloadScript)
}

func isOpenWrtCellularSection(section openWrtUCISection) bool {
	if section.Type != "interface" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(section.Options["proto"])) {
	case "3g", "qmi", "mbim", "ncm", "wwan", "modemmanager", "quectel":
		return true
	default:
		return false
	}
}

func openWrtCellularAPNOptionValue(leaf string, value wusp.Value) (string, string, error) {
	switch leaf {
	case "Enable":
		enabled, err := boolValue("Cellular.AccessPoint.Enable", value)
		if err != nil {
			return "", "", err
		}
		if enabled {
			return "disabled", "0", nil
		}
		return "disabled", "1", nil
	case "APN":
		apn, err := boundedCellularString("APN", value, 1, 100)
		return "apn", apn, err
	case "Username":
		username, err := boundedCellularString("Username", value, 0, 256)
		return "username", username, err
	case "Password":
		password, err := boundedCellularString("Password", value, 0, 256)
		return "password", password, err
	case "Proxy":
		proxy, err := boundedCellularString("Proxy", value, 0, 256)
		return "proxy", proxy, err
	case "ProxyPort":
		port, err := cellularUintString("ProxyPort", value, 1, 65535)
		return "proxyport", port, err
	case "Interface":
		ref, err := boundedCellularString("Interface", value, 0, 128)
		if err != nil {
			return "", "", err
		}
		if ref != "" && !strings.HasPrefix(ref, "Device.Cellular.Interface.") {
			return "", "", fmt.Errorf("wusp openwrt cellular Interface must reference Device.Cellular.Interface")
		}
		return "", "", nil
	case "IPVersion":
		if value.Tag != wusp.TagInt || value.AsInt() != -1 {
			return "", "", fmt.Errorf("wusp openwrt cellular IPVersion only supports -1 (IPv4v6/default)")
		}
		return "pdptype", "ipv4v6", nil
	case "Type":
		apnType, err := cellularListString("Type", value, 0, 128)
		return "type", apnType, err
	default:
		return "", "", wusp.ErrUSPPathUnsupported
	}
}

func (b *OpenWrtBackend) openWrtCellularSection(index uint64) string {
	parsed, err := b.readUCIConfig("network")
	if err != nil || index == 0 {
		return ""
	}
	count := uint64(0)
	interfaceIndex := 0
	for _, section := range parsed.Sections {
		if section.Type == "interface" {
			interfaceIndex++
		}
		if !isOpenWrtCellularSection(section) {
			continue
		}
		count++
		if count == index {
			if section.Name != "" {
				return section.Name
			}
			return fmt.Sprintf("@interface[%d]", interfaceIndex-1)
		}
	}
	return ""
}

func (b *OpenWrtBackend) openWrtCellularAPNSection(index uint64) string {
	parsed, err := b.readUCIConfig("network")
	if err != nil || index == 0 {
		return ""
	}
	count := uint64(0)
	interfaceIndex := 0
	for _, section := range parsed.Sections {
		if section.Type == "interface" {
			interfaceIndex++
		}
		if !isOpenWrtCellularSection(section) || strings.TrimSpace(section.Options["apn"]) == "" {
			continue
		}
		count++
		if count == index {
			if section.Name != "" {
				return section.Name
			}
			return fmt.Sprintf("@interface[%d]", interfaceIndex-1)
		}
	}
	return ""
}

func parseIndexedPath(path, prefix string) (uint64, string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(path), prefix)
	if !ok {
		return 0, "", false
	}
	parts := strings.SplitN(rest, ".", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	index, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || index == 0 {
		return 0, "", false
	}
	leaf := strings.TrimSpace(parts[1])
	if leaf == "" || strings.Contains(leaf, ".") {
		return 0, "", false
	}
	return index, leaf, true
}

func messageUint(msg *wusp.Message, path string) uint64 {
	if msg == nil {
		return 0
	}
	value, ok := msg.Get(path)
	if !ok || value.Tag != wusp.TagUint {
		return 0
	}
	return value.AsUint()
}

func openWrtCellularStatus(enabled bool) string {
	if !enabled {
		return "Down"
	}
	return "Dormant"
}

func openWrtCellularAPNType(section openWrtUCISection) wusp.Value {
	value := strings.TrimSpace(section.Options["type"])
	if value == "" {
		return wusp.List(wusp.String("default"))
	}
	items := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	values := make([]wusp.Value, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, wusp.String(item))
		}
	}
	if len(values) == 0 {
		return wusp.List(wusp.String("default"))
	}
	return wusp.List(values...)
}

func boundedCellularString(name string, value wusp.Value, minLen, maxLen int) (string, error) {
	if value.Tag != wusp.TagString {
		return "", fmt.Errorf("wusp openwrt cellular %s must be a string", name)
	}
	text := strings.TrimSpace(value.AsString())
	if len(text) < minLen || len(text) > maxLen {
		return "", fmt.Errorf("wusp openwrt cellular %s length must be %d..%d", name, minLen, maxLen)
	}
	return text, nil
}

func cellularUintString(name string, value wusp.Value, minValue, maxValue uint64) (string, error) {
	var n uint64
	switch value.Tag {
	case wusp.TagUint:
		n = value.AsUint()
	case wusp.TagInt:
		if value.AsInt() < 0 {
			return "", fmt.Errorf("wusp openwrt cellular %s must be %d..%d", name, minValue, maxValue)
		}
		n = uint64(value.AsInt())
	case wusp.TagString:
		parsed, err := strconv.ParseUint(strings.TrimSpace(value.AsString()), 10, 64)
		if err != nil {
			return "", fmt.Errorf("wusp openwrt cellular %s must be numeric", name)
		}
		n = parsed
	default:
		return "", fmt.Errorf("wusp openwrt cellular %s must be numeric", name)
	}
	if n < minValue || n > maxValue {
		return "", fmt.Errorf("wusp openwrt cellular %s must be %d..%d", name, minValue, maxValue)
	}
	return strconv.FormatUint(n, 10), nil
}

func cellularListString(name string, value wusp.Value, minLen, maxLen int) (string, error) {
	var text string
	switch value.Tag {
	case wusp.TagList:
		items := make([]string, 0, len(value.AsList()))
		for _, item := range value.AsList() {
			itemText := strings.TrimSpace(wusp.ValueToString(item))
			if itemText != "" {
				items = append(items, itemText)
			}
		}
		text = strings.Join(items, ",")
	case wusp.TagString:
		text = strings.TrimSpace(value.AsString())
	default:
		return "", fmt.Errorf("wusp openwrt cellular %s must be a string or list", name)
	}
	if len(text) < minLen || len(text) > maxLen {
		return "", fmt.Errorf("wusp openwrt cellular %s length must be %d..%d", name, minLen, maxLen)
	}
	return text, nil
}
