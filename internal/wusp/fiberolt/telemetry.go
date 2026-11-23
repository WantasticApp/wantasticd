package fiberolt

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// CollectOLT fills Device.WUSP_OLT.* from the vendor goform API, the FOS
// command line (cli, optional), and the platform sysinfo file. Every source
// failure degrades to the corresponding Status/StatusDetail fields; it never
// fails the whole collect. enabled mirrors the backend's persisted Enable
// flag.
func CollectOLT(ctx context.Context, api *Client, cli *CLI, enabled bool, msg *wusp.Message) {
	prefix := wusp.WUSPOLTPrefix
	msg.Set(prefix+"Installed", wusp.Bool(true))
	msg.Set(prefix+"Platform", wusp.String("olt"))
	msg.Set(prefix+"SupportedOperations", wusp.String("Reboot, FactoryRestore, ONU.Reboot, ONU.Reset, ONU.Enable, ONU.Disable"))
	msg.Set(prefix+"Enable", wusp.Bool(enabled))
	msg.Set(prefix+"AlarmNumberOfEntries", wusp.Uint(0))
	msg.Set(prefix+"PONPortNumberOfEntries", wusp.Uint(0))
	msg.Set(prefix+"ONUNumberOfEntries", wusp.Uint(0))
	if !enabled {
		msg.Set(prefix+"Status", wusp.String("disabled"))
		return
	}

	collectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := api.EnsureLogin(collectCtx); err != nil {
		msg.Set(prefix+"Status", wusp.String("login_error"))
		msg.Set(prefix+"StatusDetail", wusp.String(TruncateStatus(err.Error())))
		log.Printf("[OLT] login: %v", err)
		return
	}

	status, err := api.SysStatus(collectCtx)
	if err != nil {
		msg.Set(prefix+"Status", wusp.String("api_error"))
		msg.Set(prefix+"StatusDetail", wusp.String(TruncateStatus(err.Error())))
		log.Printf("[OLT] sysstatus: %v", err)
		return
	}
	msg.Set(prefix+"Status", wusp.String("ok"))
	msg.Set(prefix+"StatusDetail", wusp.String(""))
	msg.Set(prefix+"LastCollectTime", wusp.Uint(uint64(time.Now().Unix())))

	msg.Set(prefix+"CpuPercent", wusp.Uint(uint64(ParsePercent(status.CPUPercent))))
	msg.Set(prefix+"MemoryPercent", wusp.Uint(uint64(ParsePercent(status.MemoryPercent))))
	if temp, ok := ParseDecimal(status.Temp1Value); ok {
		msg.Set(prefix+"Temperature", wusp.Float(temp))
	}
	if temp, ok := ParseDecimal(status.Temp2Value); ok {
		msg.Set(prefix+"PonTemperature", wusp.Float(temp))
	}
	if rpm := ParseFanRPM(status.Fan1); rpm > 0 {
		msg.Set(prefix+"FanSpeed", wusp.Uint(uint64(rpm)))
	}
	if uptime, err := strconv.ParseUint(strings.TrimSpace(status.RunTime), 10, 64); err == nil {
		msg.Set(prefix+"Uptime", wusp.Uint(uptime))
	}

	// PON/uplink port table.
	ponOnline := map[string]uint64{}
	ponTotal := map[string]uint64{}
	portIndex := 1
	for _, port := range status.Ports {
		name := strings.TrimSpace(port.PortName)
		if name == "" {
			continue
		}
		row := prefix + "PONPort." + strconv.Itoa(portIndex) + "."
		msg.Set(row+"Name", wusp.String(name))
		msg.Set(row+"Type", wusp.String(PortType(name)))
		msg.Set(row+"Status", wusp.String(PortUp(port.PortStatus)))
		if speed, err := strconv.ParseUint(strings.TrimSpace(port.PortSpeed), 10, 64); err == nil {
			msg.Set(row+"Speed", wusp.Uint(speed))
		}
		if online, err := strconv.ParseUint(strings.TrimSpace(port.Online), 10, 64); err == nil {
			msg.Set(row+"OnlineONUs", wusp.Uint(online))
			ponOnline[name] = online
		}
		if offline, err := strconv.ParseUint(strings.TrimSpace(port.Offline), 10, 64); err == nil {
			ponTotal[name] = offline
			if online, ok := ponOnline[name]; ok {
				msg.Set(row+"TotalONUs", wusp.Uint(online+offline))
			} else {
				msg.Set(row+"TotalONUs", wusp.Uint(offline))
			}
		}
		portIndex++
	}
	msg.Set(prefix+"PONPortNumberOfEntries", wusp.Uint(uint64(portIndex-1)))

	// Live ONU table. The web API only lists provisioned ONUs; the CLI is
	// the source of truth for every ONU on the PON, including auto-found
	// ones that are not provisioned yet.
	ont, err := api.OntListBrife(collectCtx)
	if err != nil {
		log.Printf("[OLT] ontlist: %v", err)
		ont = &OntList{}
	}
	type onuRow struct {
		id, portName, sn, status, upTime, configState, memberState string
		voltage, rx, tx, bias, temp                                float64
		ethKnown, ethUp                                            bool
	}
	byID := map[string]*onuRow{}
	addRow := func(id, portName string) *onuRow {
		if row, ok := byID[id]; ok {
			if row.portName == "" && portName != "" {
				row.portName = portName
			}
			return row
		}
		row := &onuRow{id: id, portName: portName}
		byID[id] = row
		return row
	}
	webRows := make([]*onuRow, 0, len(ont.List))
	for _, entry := range ont.List {
		id := RowString(entry, "onuid", "id", "index")
		if id == "" {
			continue
		}
		row := addRow(id, RowString(entry, "ponPort", "portName", "pon_port"))
		if row.portName == "" {
			row.portName = ONUPortFromID(id)
		}
		row.sn = RowString(entry, "sn", "serial", "serialNumber")
		row.status = ONUStatus(RowString(entry, "status", "state", "runstate", "runState"))
		webRows = append(webRows, row)
	}
	// CLI enumeration across PON ports that report ONUs: catches
	// unprovisioned ONUs the web API does not list.
	if cli != nil {
		activePorts := map[int]bool{}
		for _, name := range []string{"pon1", "pon2", "pon3", "pon4", "pon5", "pon6", "pon7", "pon8"} {
			if n, err := strconv.Atoi(strings.TrimPrefix(name, "pon")); err == nil {
				if online, ok1 := ponOnline[name]; ok1 && online > 0 {
					activePorts[n] = true
				}
				if total, ok2 := ponTotal[name]; ok2 && total > 0 {
					activePorts[n] = true
				}
			}
		}
		for port := 1; port <= 8; port++ {
			if !activePorts[port] {
				continue
			}
			rangeIDs := fmt.Sprintf("0/%d/1-0/%d/64", port, port)
			for _, cmd := range []string{"show ont info online " + rangeIDs, "show ont info offline " + rangeIDs} {
				out, err := cli.Run(cmd)
				if err != nil {
					log.Printf("[OLT] cli %q: %v", cmd, err)
					continue
				}
				for _, info := range ParseONUInfos(out) {
					row := addRow(info.ID, ONUPortFromID(info.ID))
					if row.sn == "" {
						row.sn = info.SN
					}
					row.upTime = info.UpTime
					row.configState = info.ConfigState
					if row.memberState == "" {
						row.memberState = info.MemberState
					}
					if row.status == "" {
						row.status = "online"
					}
				}
			}
		}
	}
	// Per-ONU detail: web detail first, CLI optical readings when available.
	seenOnline := map[string]uint64{}
	detailBudget := 32
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		row := byID[id]
		if detailBudget > 0 {
			detailBudget--
			if detail, err := api.OntDetail(collectCtx, id); err == nil {
				if rx, ok := RowFloat(detail, "rxpower", "rxPower", "rxpwr", "rxPwr"); ok {
					row.rx = rx
				}
				if tx, ok := RowFloat(detail, "txpower", "txPower", "txpwr", "txPwr"); ok {
					row.tx = tx
				}
			}
			if cli != nil {
				if out, err := cli.Run("show ont optical-info " + id); err == nil {
					opt := ParseONUOptical(out)
					if opt.VoltageV != 0 {
						row.voltage = opt.VoltageV
					}
					if opt.RxPowerDBm != 0 {
						row.rx = opt.RxPowerDBm
					}
					if opt.TxPowerDBm != 0 {
						row.tx = opt.TxPowerDBm
					}
					if opt.BiasCurrent != 0 {
						row.bias = opt.BiasCurrent
					}
					if opt.TempC != 0 {
						row.temp = opt.TempC
					}
					row.ethKnown, row.ethUp = opt.EthKnown, opt.EthPortUp
				}
			}
		}
		if row.status == "online" {
			seenOnline[row.portName]++
		}
	}
	onuIndex := 1
	for _, id := range ids {
		row := byID[id]
		entry := prefix + "ONU." + strconv.Itoa(onuIndex) + "."
		msg.Set(entry+"Index", wusp.String(row.id))
		msg.Set(entry+"PONPort", wusp.String(row.portName))
		msg.Set(entry+"SerialNumber", wusp.String(row.sn))
		status := row.status
		if status == "" {
			status = "offline"
		}
		msg.Set(entry+"Status", wusp.String(status))
		msg.Set(entry+"Enable", wusp.Bool(ONUEnabled(status)))
		if secs, ok := ParseUpTime(row.upTime); ok {
			msg.Set(entry+"UpTime", wusp.Uint(secs))
		}
		if row.configState != "" {
			msg.Set(entry+"ConfigState", wusp.String(row.configState))
		}
		if row.memberState != "" {
			msg.Set(entry+"RunState", wusp.String(row.memberState))
		}
		if row.rx != 0 {
			msg.Set(entry+"RxPower", wusp.Float(row.rx))
		}
		if row.tx != 0 {
			msg.Set(entry+"TxPower", wusp.Float(row.tx))
		}
		if row.voltage != 0 {
			msg.Set(entry+"Voltage", wusp.Float(row.voltage))
		}
		if row.bias != 0 {
			msg.Set(entry+"BiasCurrent", wusp.Float(row.bias))
		}
		if row.temp != 0 {
			msg.Set(entry+"Temperature", wusp.Float(row.temp))
		}
		if row.ethKnown {
			msg.Set(entry+"EthPortUp", wusp.Bool(row.ethUp))
		}
		onuIndex++
	}
	msg.Set(prefix+"ONUNumberOfEntries", wusp.Uint(uint64(onuIndex-1)))
	msg.Set(prefix+"TotalONUs", wusp.Uint(uint64(len(byID))))

	// Online count: prefer the vendor's per-port counters, fall back to the
	// rows we classified as online.
	totalOnline := uint64(0)
	for _, online := range ponOnline {
		totalOnline += online
	}
	if totalOnline == 0 {
		for _, online := range seenOnline {
			totalOnline += online
		}
	}
	msg.Set(prefix+"OnlineONUs", wusp.Uint(totalOnline))

	// Syslog table from the device log buffer.
	if logs, err := api.SystemLog(collectCtx); err != nil {
		log.Printf("[OLT] syslog: %v", err)
	} else {
		if len(logs) > 64 {
			logs = logs[:64]
		}
		msg.Set(prefix+"SyslogNumberOfEntries", wusp.Uint(uint64(len(logs))))
		for i, entry := range logs {
			row := prefix + "Syslog." + strconv.Itoa(i+1) + "."
			msg.Set(row+"Time", wusp.String(entry.LogTime))
			msg.Set(row+"Type", wusp.String(entry.LogType))
			msg.Set(row+"Message", wusp.String(strings.TrimSpace(entry.LogTips)))
		}
	}

	// Line profiles.
	if profiles, err := api.LineProfiles(collectCtx); err != nil {
		log.Printf("[OLT] lineprofiles: %v", err)
	} else {
		msg.Set(prefix+"LineProfileNumberOfEntries", wusp.Uint(uint64(len(profiles))))
		for i, profile := range profiles {
			row := prefix + "LineProfile." + strconv.Itoa(i+1) + "."
			msg.Set(row+"ID", wusp.String(profile.ProfileID))
			msg.Set(row+"Name", wusp.String(profile.ProfileName))
			msg.Set(row+"ONTType", wusp.String(profile.ONTType))
			msg.Set(row+"MappingMode", wusp.String(profile.MappingMode))
			msg.Set(row+"TrafficMode", wusp.String(profile.TrafficMode))
		}
	}

	// Provisioned ONU authentication table.
	if provisioned, err := api.OntAuthList(collectCtx); err != nil {
		log.Printf("[OLT] provisioned onus: %v", err)
	} else {
		msg.Set(prefix+"ProvisionedONUNumberOfEntries", wusp.Uint(uint64(len(provisioned))))
		for i, p := range provisioned {
			row := prefix + "ProvisionedONU." + strconv.Itoa(i+1) + "."
			msg.Set(row+"OnuID", wusp.String(p.OnuID))
			msg.Set(row+"Mode", wusp.String(p.Mode))
			msg.Set(row+"Info", wusp.String(p.Info))
			msg.Set(row+"LineID", wusp.String(p.LineID))
			msg.Set(row+"Desc", wusp.String(p.Desc))
		}
	}

	// OLT network state: management interface, DNS, NTP, ACL, routes.
	CollectOLTNetwork(collectCtx, api, msg)

	// Temperature alarm thresholds.
	if cli != nil {
		if out, err := cli.Run("show alarm temperature"); err == nil {
			if hi, lo, ok := ParseTempAlarm(out); ok {
				msg.Set(prefix+"TemperatureAlarmHigh", wusp.Float(hi))
				msg.Set(prefix+"TemperatureAlarmLow", wusp.Float(lo))
			}
		}
	}
}

// PortType classifies a vendor port name into its family.
func PortType(name string) string {
	switch {
	case strings.HasPrefix(name, "pon"):
		return "pon"
	case strings.HasPrefix(name, "xge"):
		return "xge"
	case strings.HasPrefix(name, "ge"):
		return "ge"
	default:
		return "other"
	}
}

// PortUp normalizes the vendor port status flag.
func PortUp(status string) string {
	if strings.TrimSpace(status) == "1" {
		return "up"
	}
	return "down"
}

// ONUPortFromID maps an ONU ID like "0/1/1" to the PON port "pon1".
func ONUPortFromID(id string) string {
	parts := strings.Split(strings.TrimSpace(id), "/")
	if len(parts) < 2 {
		return ""
	}
	if n, err := strconv.Atoi(parts[1]); err == nil && n > 0 {
		return "pon" + strconv.Itoa(n)
	}
	return ""
}

// ONUStatus normalizes the many vendor spellings of the ONU state.
func ONUStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "online", "up", "working", "1", "active":
		return "online"
	case "offline", "down", "0", "inactive":
		return "offline"
	case "unconfigured", "initial":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

// ONUEnabled reports whether an ONU state means the ONU is allowed online.
func ONUEnabled(state string) bool {
	return state != "offline"
}

// TruncateStatus bounds a StatusDetail string to the schema limit.
func TruncateStatus(value string) string {
	if len(value) > 256 {
		return value[:256]
	}
	return value
}

// ParseTempAlarm parses "Temperature Alarm: 60'C(High)    -30'C(Low)".
func ParseTempAlarm(out string) (high, low float64, ok bool) {
	idx := strings.Index(out, "Temperature Alarm:")
	if idx < 0 {
		return 0, 0, false
	}
	rest := out[idx+len("Temperature Alarm:"):]
	fields := strings.Fields(rest)
	for _, f := range fields {
		f = strings.TrimSuffix(strings.TrimSuffix(f, "C"), "'")
		f = strings.Trim(f, "'")
		if strings.Contains(f, "(") {
			continue
		}
		if v, err := strconv.ParseFloat(f, 64); err == nil {
			if !ok {
				high = v
			} else {
				low = v
				break
			}
			ok = true
		}
	}
	if !ok {
		return 0, 0, false
	}
	// order: high first; if low > high they were swapped
	if low != 0 && low > high {
		high, low = low, high
	}
	return high, low, ok
}

// ParseUpTime converts vendor spellings like "0d0h40m", "1d22h48m" or plain
// seconds into a second count.
func ParseUpTime(value string) (uint64, bool) {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return 0, false
	}
	if secs, err := strconv.ParseUint(value, 10, 64); err == nil {
		return secs, true
	}
	var total uint64
	var num strings.Builder
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			num.WriteRune(r)
		case r == 'd' || r == 'h' || r == 'm' || r == 's':
			if n, err := strconv.ParseUint(num.String(), 10, 64); err == nil {
				switch r {
				case 'd':
					total += n * 86400
				case 'h':
					total += n * 3600
				case 'm':
					total += n * 60
				case 's':
					total += n
				}
			}
			num.Reset()
		default:
			num.Reset()
		}
	}
	return total, total > 0
}
