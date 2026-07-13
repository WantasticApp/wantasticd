//go:build linux

// AT command modem controller — pure Go, no CGo dependencies.
// Works with any modem exposing AT command serial ports (/dev/ttyUSB*, /dev/ttyACM*).
// Falls back to sysfs for device discovery.

package modem

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// atController communicates with modems via AT commands over serial ports.
// Falls back to sysfs/procfs for device info when AT ports aren't accessible.
type atController struct{}

func (c *atController) Close() error { return nil }

func (c *atController) Discover() ([]string, error) {
	var devices []string
	seen := make(map[string]bool)

	add := func(path string) {
		if !seen[path] {
			seen[path] = true
			devices = append(devices, path)
		}
	}

	// 1. sysfs: WWAN network interfaces (most reliable)
	if entries, err := os.ReadDir("/sys/class/net"); err == nil {
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "wwan") || strings.HasPrefix(name, "rmnet") {
				add(name)
			}
			// Check if interface is a USB modem via driver
			driverLink := "/sys/class/net/" + name + "/device/driver"
			if target, err := os.Readlink(driverLink); err == nil {
				driver := filepath.Base(target)
				if driver == "qmi_wwan" || driver == "cdc_mbim" || driver == "cdc_ether" {
					add(name)
				}
			}
		}
	}

	// 2. sysfs: USB control devices (QMI/MBIM)
	for _, cls := range []string{"/sys/class/usbmisc/cdc-wdm*", "/sys/class/wwan/wwan*"} {
		if matches, err := filepath.Glob(cls); err == nil {
			for _, m := range matches {
				add("/dev/" + filepath.Base(m))
			}
		}
	}

	// 3. /dev serial ports (AT command interfaces)
	for _, pattern := range []string{"/dev/ttyUSB*", "/dev/ttyACM*"} {
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, m := range matches {
				add(m)
			}
		}
	}

	return devices, nil
}

func (c *atController) GetInfo(devicePath string) (*Info, error) {
	// Always start with sysfs data (available without AT access)
	info := c.infoFromSysfs(devicePath)
	c.enrichFromUQMI(devicePath, info)
	c.enrichFromMMCLI(info)
	c.enrichFromNetStats(devicePath, info)

	port := c.findATPort(devicePath)
	if port == "" {
		// No AT port — return sysfs-only data if we got anything
		if info.Model != "" || info.Manufacturer != "" {
			return info, nil
		}
		return nil, fmt.Errorf("no AT port found for %s", devicePath)
	}

	f, err := os.OpenFile(port, os.O_RDWR, 0666)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", port, err)
	}
	defer f.Close()

	at := &atSession{f: f, scanner: bufio.NewScanner(f)}
	info.Interface = devicePath
	info.Protocol = "at"
	info.CollectedAt = time.Now()

	// Identity
	if lines := at.send("ATI"); len(lines) > 0 {
		info.Model = strings.Join(lines, " ")
	}
	if lines := at.send("AT+CGMI"); len(lines) > 0 {
		info.Manufacturer = lines[0]
	}
	if lines := at.send("AT+CGMM"); len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
		info.Model = strings.TrimSpace(lines[0])
	}
	if lines := at.send("AT+CGMR"); len(lines) > 0 {
		info.Revision = lines[0]
	}
	if lines := at.send("AT+GSN"); len(lines) > 0 {
		info.IMEI = strings.TrimSpace(lines[0])
	} else if lines := at.send("AT+CGSN"); len(lines) > 0 {
		info.IMEI = strings.TrimSpace(lines[0])
	}
	if lines := at.send("AT+CIMI"); len(lines) > 0 {
		info.IMSI = strings.TrimSpace(lines[0])
	}
	if lines := at.send("AT+CCID"); len(lines) > 0 {
		val := lines[0]
		if strings.HasPrefix(val, "+CCID:") {
			val = strings.TrimSpace(strings.TrimPrefix(val, "+CCID:"))
		}
		info.ICCID = val
	}
	if lines := at.send("AT+CNUM"); len(lines) > 0 {
		// +CNUM: "","+1234567890",129
		if strings.Contains(lines[0], ",") {
			parts := strings.Split(lines[0], ",")
			if len(parts) >= 2 {
				info.MSISDN = strings.Trim(parts[1], "\"")
			}
		}
	}

	// Signal
	info.Signal = c.parseSignal(at)

	// Registration + operator
	c.parseRegistration(at, info)

	// SIM status
	if lines := at.send("AT+CPIN?"); len(lines) > 0 {
		if strings.Contains(lines[0], "READY") {
			info.SIMStatus = SIMReady
		} else if strings.Contains(lines[0], "SIM PIN") {
			info.SIMStatus = SIMLocked
		} else {
			info.SIMStatus = SIMError
		}
	}

	// Data connection info
	if lines := at.send("AT+CGPADDR"); len(lines) > 0 {
		for _, line := range lines {
			if strings.HasPrefix(line, "+CGPADDR:") {
				parts := strings.Split(strings.TrimPrefix(line, "+CGPADDR:"), ",")
				if len(parts) >= 2 {
					ip := strings.Trim(strings.TrimSpace(parts[1]), "\"")
					if strings.Contains(ip, ":") {
						info.IPv6Address = ip
					} else if ip != "" {
						info.IPAddress = ip
						info.Connected = true
					}
				}
			}
		}
	}

	// APN
	if lines := at.send("AT+CGDCONT?"); len(lines) > 0 {
		for _, line := range lines {
			if strings.HasPrefix(line, "+CGDCONT:") {
				parts := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+CGDCONT:")))
				if len(parts) >= 3 {
					pdpType := strings.ToUpper(strings.TrimSpace(parts[1]))
					info.APN = strings.TrimSpace(parts[2])
					info.IPVersion = pdpTypeToIPVersion(pdpType)
					break
				}
			}
		}
	}
	if lines := at.send("AT+CGCONTRDP"); len(lines) > 0 {
		c.parseCGCONTRDP(lines, info)
	}
	if lines := at.send("AT+QMAP=\"WWAN\""); len(lines) > 0 {
		c.parseQuectelWANIP(lines, info)
	}
	if lines := at.send("AT+QNWINFO"); len(lines) > 0 {
		c.parseQuectelNetworkInfo(lines[0], info)
	}
	if lines := at.send("AT+QSPN"); len(lines) > 0 {
		c.parseQuectelOperator(lines[0], info)
	}
	if lines := at.send("AT+QENG=\"servingcell\""); len(lines) > 0 {
		c.parseQuectelServingCellInfo(lines, info)
	}
	if lines := at.send("AT+QCAINFO"); len(lines) > 0 {
		info.CarrierAggregation = parseQuectelCarrierAggregation(lines)
	}
	if lines := at.send("AT+QENG=\"neighbourcell\""); len(lines) > 0 {
		info.NeighborCells = append(info.NeighborCells, parseQuectelNeighborCells(lines)...)
	}
	if lines := at.send("AT+QNWCFG=\"nr5g_meas_info\""); len(lines) > 0 {
		info.NeighborCells = append(info.NeighborCells, parseQuectelNR5GMeasInfo(lines)...)
	}
	if isFibocom(info) {
		if lines := at.send("AT+GTPKGVER?"); len(lines) > 0 && info.Revision == "" {
			info.Revision = parseColonValue(lines[0])
		}
	}
	if lines := at.send("AT+CPMS?"); len(lines) > 0 {
		c.parseSMSStorage(lines[0], info)
	}

	info.SupportedTechnologies = inferSupportedTechnologies(info)
	if info.Technology == TechNR5GNSA {
		info.NRMode = "NonStandalone"
	} else if info.Technology == TechNR5G {
		info.NRMode = "Standalone"
	} else if info.NRMode == "" {
		info.NRMode = "Unknown"
	}
	c.enrichFromNetStats(devicePath, info)

	return info, nil
}

func (c *atController) GetSignal(devicePath string) (*SignalQuality, error) {
	port := c.findATPort(devicePath)
	if port == "" {
		return nil, fmt.Errorf("no AT port found for %s", devicePath)
	}
	f, err := os.OpenFile(port, os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	at := &atSession{f: f, scanner: bufio.NewScanner(f)}
	sig := c.parseSignal(at)
	return &sig, nil
}

func (c *atController) Connect(devicePath, apn string) error {
	apn = strings.TrimSpace(apn)
	if apn == "" {
		return fmt.Errorf("AT command connect requires APN")
	}
	at, closeFn, err := c.openATSession(devicePath)
	if err != nil {
		return err
	}
	defer closeFn()
	at.send(fmt.Sprintf("AT+CGDCONT=1,\"IPV4V6\",\"%s\"", escapeATString(apn)))
	at.send("AT+CGACT=1,1")
	return nil
}

func (c *atController) Disconnect(devicePath string) error {
	at, closeFn, err := c.openATSession(devicePath)
	if err != nil {
		return err
	}
	defer closeFn()
	at.send("AT+CGACT=0,1")
	return nil
}

func (c *atController) openATSession(devicePath string) (*atSession, func(), error) {
	port := c.findATPort(devicePath)
	if port == "" {
		return nil, func() {}, fmt.Errorf("no AT port found for %s", devicePath)
	}
	f, err := os.OpenFile(port, os.O_RDWR, 0666)
	if err != nil {
		return nil, func() {}, err
	}
	return &atSession{f: f, scanner: bufio.NewScanner(f)}, func() { _ = f.Close() }, nil
}

// ── Signal parsing ──────────────────────────────────────────────────────────

func (c *atController) parseSignal(at *atSession) SignalQuality {
	sig := SignalQuality{}

	// Basic CSQ
	if lines := at.send("AT+CSQ"); len(lines) > 0 {
		if strings.HasPrefix(lines[0], "+CSQ:") {
			parts := strings.Split(strings.TrimPrefix(lines[0], "+CSQ:"), ",")
			if len(parts) > 0 {
				if csq, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil && csq >= 0 && csq <= 31 {
					sig.CSQ = csq
					sig.RSSI = -113 + csq*2
					sig.Bars = csqToBars(csq)
				}
			}
		}
	}

	// Extended signal: AT+QCSQ (Quectel), AT+CESQ (3GPP), or AT+QENG
	// Try Quectel-specific first (most common on OpenWrt LTE dongles)
	if lines := at.send("AT+QCSQ"); len(lines) > 0 {
		c.parseQuectelSignal(lines[0], &sig)
	} else if lines := at.send("AT+XCESQ?"); len(lines) > 0 {
		c.parseFibocomXCESQ(lines[0], &sig)
	} else if lines := at.send("AT+CESQ"); len(lines) > 0 {
		c.parseCESQ(lines[0], &sig)
	}

	// Try serving cell info for band/cell details
	if lines := at.send("AT+QENG=\"servingcell\""); len(lines) > 0 {
		c.parseQuectelServingCell(lines, &sig)
	}

	return sig
}

// parseQuectelSignal parses +QCSQ: "LTE",-71,-8,157,-12
func (c *atController) parseQuectelSignal(line string, sig *SignalQuality) {
	if !strings.HasPrefix(line, "+QCSQ:") {
		return
	}
	parts := strings.Split(strings.TrimPrefix(line, "+QCSQ:"), ",")
	if len(parts) < 2 {
		return
	}
	// parts[0] = technology (quoted), parts[1+] = values
	if len(parts) >= 5 {
		// LTE: rssi, rsrp, sinr, rsrq
		sig.RSSI, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		sig.RSRP, _ = strconv.Atoi(strings.TrimSpace(parts[2]))
		sig.SINR, _ = strconv.Atoi(strings.TrimSpace(parts[3]))
		sig.RSRQ, _ = strconv.Atoi(strings.TrimSpace(parts[4]))
	}
}

// parseFibocomXCESQ parses Fibocom/Intel +XCESQ responses. Exact fields vary
// by generation; keep the standard CESQ tail mapping and accept already-dBm
// LTE metrics when present.
func (c *atController) parseFibocomXCESQ(line string, sig *SignalQuality) {
	if !strings.HasPrefix(line, "+XCESQ:") {
		return
	}
	parts := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+XCESQ:")))
	ints := make([]int, 0, len(parts))
	for _, part := range parts {
		if v, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			ints = append(ints, v)
		}
	}
	if len(ints) >= 6 {
		if v := ints[len(ints)-2]; v != 255 {
			if v <= 97 {
				sig.RSRQ = (v - 39) / 2
			} else {
				sig.RSRQ = v
			}
		}
		if v := ints[len(ints)-1]; v != 255 {
			if v <= 97 {
				sig.RSRP = v - 140
			} else {
				sig.RSRP = v
			}
		}
	}
}

// parseCESQ parses +CESQ: rxlev,ber,rscp,ecno,rsrq,rsrp
func (c *atController) parseCESQ(line string, sig *SignalQuality) {
	if !strings.HasPrefix(line, "+CESQ:") {
		return
	}
	parts := strings.Split(strings.TrimPrefix(line, "+CESQ:"), ",")
	if len(parts) >= 6 {
		if v, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil && v != 255 {
			sig.RSCP = v - 120 // 3GPP mapping
		}
		if v, err := strconv.Atoi(strings.TrimSpace(parts[3])); err == nil && v != 255 {
			sig.ECIO = (v - 24) / 2
		}
		if v, err := strconv.Atoi(strings.TrimSpace(parts[4])); err == nil && v != 255 {
			sig.RSRQ = (v - 39) / 2
		}
		if v, err := strconv.Atoi(strings.TrimSpace(parts[5])); err == nil && v != 255 {
			sig.RSRP = v - 140
		}
	}
}

func (c *atController) parseQuectelServingCell(lines []string, sig *SignalQuality) {
	// +QENG: "servingcell","NOCONN","LTE","FDD",460,01,1A2B3C4,123,100,1,5,5,1E7F,-97,-8,-68,15,42
	for _, line := range lines {
		if !strings.Contains(line, "servingcell") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 15 {
			continue
		}
		// Extract RSRP, RSRQ, SINR from the tail fields
		if v, err := strconv.Atoi(strings.TrimSpace(parts[len(parts)-4])); err == nil {
			sig.RSRP = v
		}
		if v, err := strconv.Atoi(strings.TrimSpace(parts[len(parts)-3])); err == nil {
			sig.RSRQ = v
		}
		if v, err := strconv.Atoi(strings.TrimSpace(parts[len(parts)-2])); err == nil {
			sig.SINR = v
		}
	}
}

func (c *atController) parseQuectelServingCellInfo(lines []string, info *Info) {
	for _, line := range lines {
		if !strings.HasPrefix(line, "+QENG:") {
			continue
		}
		values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QENG:")))
		if len(values) == 0 {
			continue
		}
		offset := 0
		if values[0] == "servingcell" {
			if len(values) > 1 && strings.EqualFold(values[1], "NOCONN") {
				info.Connected = false
			}
			if len(values) < 4 {
				continue
			}
			offset = 2
		}
		rat := strings.ToUpper(strings.TrimSpace(values[offset]))
		switch rat {
		case "LTE":
			info.Technology = TechLTE
			info.NRMode = "Unknown"
			if len(values) > offset+13 {
				info.OperatorMCC = values[offset+2]
				info.OperatorMNC = values[offset+3]
				info.CellID = parseHexOrDecimal32(values[offset+4])
				info.TAC = parseHexOrDecimal32(values[offset+10])
				info.Band = "B" + strings.TrimSpace(values[offset+7])
				setIntIfParsed(&info.Signal.RSRP, values[offset+11])
				setIntIfParsed(&info.Signal.RSRQ, values[offset+12])
				setIntIfParsed(&info.Signal.RSSI, values[offset+13])
				if len(values) > offset+14 {
					setIntIfParsed(&info.Signal.SINR, values[offset+14])
				}
			}
		case "NR5G-SA", "NR5G":
			info.Technology = TechNR5G
			info.NRMode = "Standalone"
		case "NR5G-NSA":
			info.Technology = TechNR5GNSA
			info.NRMode = "NonStandalone"
			if len(values) > offset+8 {
				info.OperatorMCC = values[offset+1]
				info.OperatorMNC = values[offset+2]
				info.Band = "N" + strings.TrimSpace(values[offset+8])
				setIntIfParsed(&info.Signal.RSRP, values[offset+4])
				setIntIfParsed(&info.Signal.SINR, values[offset+5])
				setIntIfParsed(&info.Signal.RSRQ, values[offset+6])
			}
		}
	}
}

func (c *atController) parseCGCONTRDP(lines []string, info *Info) {
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "+CGCONTRDP:") {
			continue
		}
		values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "+CGCONTRDP:")))
		if len(values) < 4 {
			continue
		}
		apn := strings.TrimSpace(values[2])
		if apn == "" || strings.EqualFold(apn, "ims") {
			continue
		}
		info.APN = apn
		localAddr := strings.TrimSpace(values[3])
		if localAddr != "" {
			if strings.Contains(localAddr, ":") {
				info.IPv6Address = localAddr
			} else {
				info.IPAddress = localAddr
				info.Connected = true
			}
		}
		if len(values) > 5 && strings.TrimSpace(values[5]) != "" {
			info.DNS1 = strings.TrimSpace(values[5])
		}
		if len(values) > 6 && strings.TrimSpace(values[6]) != "" {
			info.DNS2 = strings.TrimSpace(values[6])
		}
		if info.IPVersion == 0 {
			switch {
			case info.IPAddress != "" && info.IPv6Address != "":
				info.IPVersion = -1
			case info.IPv6Address != "":
				info.IPVersion = 6
			case info.IPAddress != "":
				info.IPVersion = 4
			}
		}
		return
	}
}

func (c *atController) parseQuectelWANIP(lines []string, info *Info) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+QMAP:") || !strings.Contains(line, "WWAN") {
			continue
		}
		values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QMAP:")))
		if len(values) < 5 || !strings.EqualFold(values[0], "WWAN") {
			continue
		}
		connected := strings.TrimSpace(values[1]) == "1"
		ipType := strings.ToUpper(strings.TrimSpace(values[3]))
		addr := strings.Trim(strings.TrimSpace(values[4]), `"`)
		if addr == "" || addr == "0.0.0.0" || addr == "0:0:0:0:0:0:0:0" || addr == "::" {
			continue
		}
		switch ipType {
		case "IPV4":
			info.IPAddress = addr
			if connected {
				info.Connected = true
			}
		case "IPV6":
			info.IPv6Address = addr
			if connected {
				info.Connected = true
			}
		}
		if info.IPAddress != "" && info.IPv6Address != "" {
			info.IPVersion = -1
		} else if info.IPv6Address != "" {
			info.IPVersion = 6
		} else if info.IPAddress != "" {
			info.IPVersion = 4
		}
	}
}

func (c *atController) parseQuectelNetworkInfo(line string, info *Info) {
	if !strings.HasPrefix(line, "+QNWINFO:") {
		return
	}
	values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QNWINFO:")))
	if len(values) >= 1 {
		info.Technology = ratStringToTech(values[0])
	}
	if len(values) >= 2 {
		plmn := strings.TrimSpace(values[1])
		if len(plmn) >= 5 {
			info.OperatorMCC = plmn[:3]
			info.OperatorMNC = plmn[3:]
		}
	}
	if len(values) >= 4 && strings.TrimSpace(values[3]) != "" {
		info.Band = strings.TrimSpace(values[3])
	}
}

func (c *atController) parseQuectelOperator(line string, info *Info) {
	if !strings.HasPrefix(line, "+QSPN:") {
		return
	}
	values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QSPN:")))
	if len(values) > 0 && values[0] != "" {
		info.Operator = values[0]
	}
	if len(values) > 4 {
		plmn := strings.TrimSpace(values[4])
		if len(plmn) >= 5 {
			info.OperatorMCC = plmn[:3]
			info.OperatorMNC = plmn[3:]
		}
	}
}

func (c *atController) parseSMSStorage(line string, info *Info) {
	if !strings.HasPrefix(line, "+CPMS:") {
		return
	}
	values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+CPMS:")))
	if len(values) >= 3 {
		info.SMSStorageLocation = values[0]
		info.SMSStorageUsed = parseUint(values[1])
		info.SMSStorageCapacity = parseUint(values[2])
	}
}

func parseQuectelCarrierAggregation(lines []string) []CarrierInfo {
	out := make([]CarrierInfo, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+QCAINFO:") {
			continue
		}
		values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QCAINFO:")))
		if len(values) < 2 {
			continue
		}
		carrier := CarrierInfo{
			Role: strings.TrimSpace(values[0]),
			Raw:  line,
		}
		roleUpper := strings.ToUpper(carrier.Role)
		if strings.Contains(roleUpper, "NR5G") {
			carrier.RAT = "NR"
		} else {
			carrier.RAT = "LTE"
		}
		if len(values) > 1 {
			carrier.EARFCN = parseUint(values[1])
		}

		bandIdx := -1
		for i, value := range values {
			upper := strings.ToUpper(strings.TrimSpace(value))
			switch {
			case strings.Contains(upper, "LTE BAND"):
				carrier.RAT = "LTE"
				carrier.Band = "B" + digitsOnly(upper)
				bandIdx = i
			case strings.Contains(upper, "NR5G BAND"):
				carrier.RAT = "NR"
				carrier.Band = "N" + digitsOnly(upper)
				bandIdx = i
			}
		}

		if len(values) > 2 {
			carrier.Bandwidth = quectelBandwidth(values[2], carrier.RAT)
		}
		if bandIdx > 0 && bandIdx <= 3 {
			if idx := quectelQCAIndex(len(values), "pci"); idx >= 0 && len(values) > idx {
				carrier.PCI = parseUint(values[idx])
			}
			if idx := quectelQCAIndex(len(values), "rsrp"); idx >= 0 && len(values) > idx {
				carrier.RSRP = parseOptionalInt(values[idx])
			}
			if idx := quectelQCAIndex(len(values), "rsrq"); idx >= 0 && len(values) > idx {
				carrier.RSRQ = parseOptionalInt(values[idx])
			}
			if idx := quectelQCAIndex(len(values), "sinr"); idx >= 0 && len(values) > idx {
				carrier.SINR = parseQuectelSINR(values[idx], carrier.RAT)
			}
		} else {
			if len(values) > 2 {
				carrier.PCI = parseUint(values[2])
			}
			if len(values) > 3 {
				carrier.RSRP = parseOptionalInt(values[3])
			}
			if len(values) > 4 {
				carrier.RSRQ = parseOptionalInt(values[4])
			}
			if len(values) > 5 {
				carrier.SINR = parseQuectelSINR(values[5], carrier.RAT)
			}
			if len(values) > 6 && carrier.Bandwidth == "" {
				carrier.Bandwidth = strings.TrimSpace(values[6])
			}
		}
		if carrier.Bandwidth == "" && len(values) > 0 {
			carrier.Bandwidth = strings.TrimSpace(values[len(values)-1])
		}
		out = append(out, carrier)
	}
	return out
}

func quectelQCAIndex(partsLen int, metric string) int {
	switch metric {
	case "pci":
		if partsLen == 8 {
			return 4
		}
		return 5
	case "rsrp":
		if partsLen == 8 {
			return 5
		}
		if partsLen == 12 {
			return 9
		}
		return 6
	case "rsrq":
		if partsLen == 8 {
			return 6
		}
		if partsLen == 12 {
			return 10
		}
		return 7
	case "sinr":
		switch partsLen {
		case 8:
			return 7
		case 9:
			return 8
		case 12:
			return 11
		default:
			return 9
		}
	default:
		return -1
	}
}

func quectelBandwidth(value, rat string) string {
	code := strings.TrimSpace(strings.Trim(value, "\""))
	if code == "" || code == "-" {
		return ""
	}
	if strings.EqualFold(rat, "NR") {
		switch code {
		case "0":
			return "5 MHz"
		case "1":
			return "10 MHz"
		case "2":
			return "15 MHz"
		case "3":
			return "20 MHz"
		case "4":
			return "25 MHz"
		case "5":
			return "30 MHz"
		case "6":
			return "40 MHz"
		case "7":
			return "50 MHz"
		case "8":
			return "60 MHz"
		case "9":
			return "70 MHz"
		case "10":
			return "80 MHz"
		case "11":
			return "90 MHz"
		case "12":
			return "100 MHz"
		case "13":
			return "200 MHz"
		case "14":
			return "400 MHz"
		case "15":
			return "35 MHz"
		case "16":
			return "45 MHz"
		}
	} else {
		switch code {
		case "6":
			return "1.4 MHz"
		case "15":
			return "3 MHz"
		case "25":
			return "5 MHz"
		case "50":
			return "10 MHz"
		case "75":
			return "15 MHz"
		case "100":
			return "20 MHz"
		}
	}
	return code
}

func parseQuectelSINR(value, rat string) int {
	v := parseOptionalInt(value)
	if v == -32768 {
		return 0
	}
	if strings.EqualFold(rat, "NR") && (v >= 100 || v <= -100) {
		if v >= 4000 {
			v = 4000
		} else if v < -3000 {
			return 0
		}
		if v >= 0 {
			return (v + 50) / 100
		}
		return (v - 50) / 100
	}
	return v
}

func parseQuectelNeighborCells(lines []string) []NeighborCell {
	out := make([]NeighborCell, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+QENG:") || !strings.Contains(line, "neighbourcell") {
			continue
		}
		values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QENG:")))
		if len(values) < 6 {
			continue
		}
		relation := strings.TrimSpace(values[0])
		relation = strings.TrimPrefix(relation, "neighbourcell ")
		cell := NeighborCell{
			RAT:      strings.ToUpper(strings.TrimSpace(values[1])),
			Relation: relation,
			Raw:      line,
		}
		cell.Frequency = parseUint(values[2])
		cell.PCI = parseUint(values[3])
		cell.RSRP = parseOptionalInt(values[4])
		cell.RSRQ = parseOptionalInt(values[5])
		out = append(out, cell)
	}
	return out
}

func parseQuectelNR5GMeasInfo(lines []string) []NeighborCell {
	out := make([]NeighborCell, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+QNWCFG:") || !strings.Contains(line, "nr5g_meas_info") {
			continue
		}
		values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QNWCFG:")))
		if len(values) < 6 || !strings.EqualFold(values[0], "nr5g_meas_info") {
			continue
		}
		out = append(out, NeighborCell{
			RAT:       "NR",
			Relation:  "nr5g",
			Frequency: parseUint(values[1]),
			PCI:       parseUint(values[2]),
			RSRP:      parseOptionalInt(values[4]),
			RSRQ:      parseOptionalInt(values[5]),
			Raw:       line,
		})
	}
	return out
}

// ── Registration parsing ────────────────────────────────────────────────────

func (c *atController) parseRegistration(at *atSession, info *Info) {
	// AT+COPS? — operator and technology
	if lines := at.send("AT+COPS?"); len(lines) > 0 {
		if strings.HasPrefix(lines[0], "+COPS:") {
			parts := strings.Split(lines[0], ",")
			if len(parts) >= 3 {
				info.Operator = strings.Trim(parts[2], "\"")
			}
			if len(parts) >= 4 {
				info.Technology = copsTechToTech(strings.TrimSpace(parts[3]))
			}
		}
	}

	// AT+CREG? / AT+CEREG? — registration status
	for _, cmd := range []string{"AT+C5GREG?", "AT+CEREG?", "AT+CGREG?", "AT+CREG?"} {
		if lines := at.send(cmd); len(lines) > 0 {
			line := lines[0]
			prefix := "+CEREG:"
			switch {
			case strings.HasPrefix(line, "+C5GREG:"):
				prefix = "+C5GREG:"
			case strings.HasPrefix(line, "+CGREG:"):
				prefix = "+CGREG:"
			case strings.HasPrefix(line, "+CREG:"):
				prefix = "+CREG:"
			}
			if strings.HasPrefix(line, prefix) {
				parts := splitATCSV(strings.TrimPrefix(line, prefix))
				statIdx := 1
				if len(parts) == 1 {
					statIdx = 0
				}
				if len(parts) > statIdx {
					switch strings.TrimSpace(parts[statIdx]) {
					case "1":
						info.Status = RegHome
					case "5":
						info.Status = RegRoaming
					case "2":
						info.Status = RegSearching
					case "3":
						info.Status = RegDenied
					default:
						info.Status = RegNotRegistered
					}
				}
				// Extended format: +CEREG: n,stat,tac,ci,AcT
				if len(parts) >= statIdx+3 {
					if area, err := strconv.ParseUint(strings.TrimSpace(parts[statIdx+1]), 16, 32); err == nil {
						if prefix == "+CREG:" || prefix == "+CGREG:" {
							info.LAC = uint16(area)
						} else {
							info.TAC = uint32(area)
						}
					}
					if ci, err := strconv.ParseUint(strings.TrimSpace(parts[statIdx+2]), 16, 32); err == nil {
						info.CellID = uint32(ci)
					}
				}
				if len(parts) > statIdx+3 && info.Technology == TechUnknown {
					info.Technology = copsTechToTech(strings.TrimSpace(parts[statIdx+3]))
				}
				if info.Status != RegNotRegistered {
					break // got valid registration
				}
			}
		}
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func copsTechToTech(act string) Technology {
	switch act {
	case "0":
		return TechGSM
	case "1":
		return TechGSM // GSM Compact
	case "2":
		return TechUMTS
	case "3":
		return TechEDGE
	case "4":
		return TechHSPA
	case "5":
		return TechHSPA
	case "6":
		return TechHSPA
	case "7":
		return TechLTE
	case "8":
		return TechLTEA // LTE-CA (EC-GSM-IoT)
	case "11":
		return TechNR5G
	case "12":
		return TechNR5GNSA
	case "13":
		return TechNR5G // NR-U
	default:
		return TechUnknown
	}
}

func csqToBars(csq int) int {
	switch {
	case csq >= 20:
		return 5
	case csq >= 15:
		return 4
	case csq >= 10:
		return 3
	case csq >= 5:
		return 2
	case csq >= 1:
		return 1
	default:
		return 0
	}
}

// findATPort locates the AT command port for a given modem device.
// infoFromSysfs reads modem identity from USB descriptor sysfs files.
// Available even when AT ports can't be opened (permissions, modem busy).
// Paths: /sys/class/net/<iface>/device/../{manufacturer,product,serial}
//
//	/sys/class/usbmisc/<dev>/device/../{manufacturer,product,serial}
func (c *atController) infoFromSysfs(devicePath string) *Info {
	info := &Info{
		Interface:   devicePath,
		Protocol:    "sysfs",
		CollectedAt: time.Now(),
	}

	// Resolve to USB device sysfs path
	var usbDevPath string
	for _, base := range []string{
		"/sys/class/net/" + filepath.Base(devicePath) + "/device",
		"/sys/class/usbmisc/" + filepath.Base(devicePath) + "/device",
	} {
		if real, err := filepath.EvalSymlinks(base); err == nil {
			usbDevPath = real
			break
		}
	}
	if usbDevPath == "" {
		return info
	}

	// Walk up to the USB device root (has manufacturer/product/serial files)
	for dir := usbDevPath; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "manufacturer")); err == nil {
			if data, err := os.ReadFile(filepath.Join(dir, "manufacturer")); err == nil {
				info.Manufacturer = strings.TrimSpace(string(data))
			}
			if data, err := os.ReadFile(filepath.Join(dir, "product")); err == nil {
				info.Model = strings.TrimSpace(string(data))
			}
			if data, err := os.ReadFile(filepath.Join(dir, "serial")); err == nil {
				info.IMEI = strings.TrimSpace(string(data)) // USB serial is often IMEI
			}
			break
		}
	}

	// Read operstate for connection status
	opState := "/sys/class/net/" + filepath.Base(devicePath) + "/operstate"
	if data, err := os.ReadFile(opState); err == nil {
		info.Connected = strings.TrimSpace(string(data)) == "up"
	}

	// Read carrier for link status
	carrier := "/sys/class/net/" + filepath.Base(devicePath) + "/carrier"
	if data, err := os.ReadFile(carrier); err == nil {
		info.Connected = info.Connected || strings.TrimSpace(string(data)) == "1"
	}

	return info
}

func (c *atController) enrichFromNetStats(devicePath string, info *Info) {
	if info == nil {
		return
	}
	iface := cellularNetInterface(devicePath)
	if iface == "" {
		return
	}
	if info.Interface == "" || strings.HasPrefix(info.Interface, "/dev/") {
		info.Interface = iface
	}
	base := filepath.Join("/sys/class/net", iface, "statistics")
	info.TxBytes = firstNonZero(info.TxBytes, readUintFile(filepath.Join(base, "tx_bytes")))
	info.RxBytes = firstNonZero(info.RxBytes, readUintFile(filepath.Join(base, "rx_bytes")))
	info.TxPackets = firstNonZero(info.TxPackets, readUintFile(filepath.Join(base, "tx_packets")))
	info.RxPackets = firstNonZero(info.RxPackets, readUintFile(filepath.Join(base, "rx_packets")))
	info.TxErrors = firstNonZero(info.TxErrors, readUintFile(filepath.Join(base, "tx_errors")))
	info.RxErrors = firstNonZero(info.RxErrors, readUintFile(filepath.Join(base, "rx_errors")))
	info.TxDropped = firstNonZero(info.TxDropped, readUintFile(filepath.Join(base, "tx_dropped")))
	info.RxDropped = firstNonZero(info.RxDropped, readUintFile(filepath.Join(base, "rx_dropped")))
	info.RxMulticastPackets = firstNonZero(info.RxMulticastPackets, readUintFile(filepath.Join(base, "multicast")))
	if speed := readUintFile(filepath.Join("/sys/class/net", iface, "speed")); speed > 0 {
		info.UpstreamMaxBitRate = firstNonZero(info.UpstreamMaxBitRate, speed*1000*1000)
		info.DownstreamMaxBitRate = firstNonZero(info.DownstreamMaxBitRate, speed*1000*1000)
	}
}

func (c *atController) enrichFromUQMI(devicePath string, info *Info) {
	if info == nil || exec.Command("sh", "-c", "command -v uqmi >/dev/null 2>&1").Run() != nil {
		return
	}
	control := devicePath
	if !strings.Contains(filepath.Base(control), "cdc-wdm") {
		if found := findCDCWDMForDevice(devicePath); found != "" {
			control = found
		}
	}
	if !strings.Contains(filepath.Base(control), "cdc-wdm") {
		return
	}
	if info.Protocol == "sysfs" {
		info.Protocol = "qmi"
	}
	if out, err := exec.Command("uqmi", "-d", control, "--get-imei").Output(); err == nil && info.IMEI == "" {
		info.IMEI = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("uqmi", "-d", control, "--get-imsi").Output(); err == nil && info.IMSI == "" {
		info.IMSI = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("uqmi", "-d", control, "--get-iccid").Output(); err == nil && info.ICCID == "" {
		info.ICCID = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("uqmi", "-d", control, "--get-data-status").Output(); err == nil {
		info.Connected = strings.Contains(strings.ToLower(string(out)), "connected")
	}
	if out, err := exec.Command("uqmi", "-d", control, "--get-signal-info").Output(); err == nil {
		parseJSONSignal(out, info)
	}
	if out, err := exec.Command("uqmi", "-d", control, "--get-serving-system").Output(); err == nil {
		parseJSONServingSystem(out, info)
	}
	if out, err := exec.Command("uqmi", "-d", control, "--get-current-settings").Output(); err == nil {
		parseJSONCurrentSettings(out, info)
	}
}

func (c *atController) enrichFromMMCLI(info *Info) {
	if info == nil || info.IMEI != "" || exec.Command("sh", "-c", "command -v mmcli >/dev/null 2>&1").Run() != nil {
		return
	}
	out, err := exec.Command("mmcli", "-m", "any", "-J").Output()
	if err != nil {
		return
	}
	var root map[string]any
	if json.Unmarshal(out, &root) != nil {
		return
	}
	flat := flattenJSON(root)
	info.Protocol = firstNonEmpty(info.Protocol, "modemmanager")
	info.Manufacturer = firstNonEmpty(info.Manufacturer, flat["modem.generic.manufacturer"])
	info.Model = firstNonEmpty(info.Model, flat["modem.generic.model"])
	info.Revision = firstNonEmpty(info.Revision, flat["modem.generic.revision"])
	info.IMEI = firstNonEmpty(info.IMEI, flat["modem.3gpp.imei"])
	info.Operator = firstNonEmpty(info.Operator, flat["modem.3gpp.operator-name"], flat["modem.3gpp.operator-code"])
	info.Technology = firstKnownTech(info.Technology, ratStringToTech(flat["modem.generic.access-technologies.value"]))
	info.Status = firstKnownReg(info.Status, registrationStringToStatus(flat["modem.3gpp.registration-state"]))
}

func splitATCSV(s string) []string {
	var parts []string
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '"':
			inQuote = !inQuote
		case ',':
			if !inQuote {
				parts = append(parts, strings.TrimSpace(b.String()))
				b.Reset()
				continue
			}
			b.WriteByte(ch)
		default:
			b.WriteByte(ch)
		}
	}
	parts = append(parts, strings.TrimSpace(b.String()))
	return parts
}

func setIntIfParsed(dst *int, value string) {
	if dst == nil {
		return
	}
	if v, err := strconv.Atoi(strings.TrimSpace(strings.Trim(value, "\""))); err == nil {
		*dst = v
	}
}

func parseHexOrDecimal32(value string) uint32 {
	value = strings.TrimSpace(strings.Trim(value, "\""))
	if value == "" || value == "-" {
		return 0
	}
	base := 10
	if strings.IndexFunc(value, func(r rune) bool { return (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f') }) >= 0 {
		base = 16
	}
	if v, err := strconv.ParseUint(value, base, 32); err == nil {
		return uint32(v)
	}
	return 0
}

func parseUint(value string) uint64 {
	value = strings.TrimSpace(strings.Trim(value, "\""))
	if value == "" || value == "-" {
		return 0
	}
	v, _ := strconv.ParseUint(value, 10, 64)
	return v
}

func parseOptionalInt(value string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(strings.Trim(value, "\"")))
	return v
}

func digitsOnly(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func escapeATString(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value)
}

func readUintFile(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return parseUint(string(data))
}

func firstNonZero(values ...uint64) uint64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstKnownTech(values ...Technology) Technology {
	for _, value := range values {
		if value != TechUnknown {
			return value
		}
	}
	return TechUnknown
}

func firstKnownReg(values ...RegistrationStatus) RegistrationStatus {
	for _, value := range values {
		if value != RegNotRegistered && value != RegUnknown {
			return value
		}
	}
	if len(values) > 0 {
		return values[0]
	}
	return RegNotRegistered
}

func parseColonValue(line string) string {
	if idx := strings.Index(line, ":"); idx >= 0 {
		line = line[idx+1:]
	}
	return strings.Trim(strings.TrimSpace(line), "\"")
}

func pdpTypeToIPVersion(value string) int {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "IP":
		return 4
	case "IPV6":
		return 6
	case "IPV4V6", "IPV4V6PDP", "NON-IP":
		return -1
	default:
		return 0
	}
}

func isFibocom(info *Info) bool {
	text := strings.ToLower(strings.Join([]string{info.Manufacturer, info.Model}, " "))
	return strings.Contains(text, "fibocom")
}

func inferSupportedTechnologies(info *Info) []Technology {
	text := strings.ToLower(strings.Join([]string{info.Manufacturer, info.Model, info.Revision}, " "))
	out := []Technology{TechGPRS, TechEDGE, TechUMTS, TechHSPA, TechLTE}
	if strings.Contains(text, "5g") || strings.Contains(text, "nr") || strings.Contains(text, "rm5") || strings.Contains(text, "fm350") || info.Technology == TechNR5G || info.Technology == TechNR5GNSA {
		out = append(out, TechNR5G)
	}
	return out
}

func ratStringToTech(value string) Technology {
	value = strings.ToUpper(strings.TrimSpace(value))
	switch {
	case strings.Contains(value, "NR5G-NSA"), strings.Contains(value, "5GNSA"):
		return TechNR5GNSA
	case strings.Contains(value, "NR5G"), strings.Contains(value, "5G"), strings.Contains(value, "NR"):
		return TechNR5G
	case strings.Contains(value, "LTE-A"), strings.Contains(value, "LTE_CA"), strings.Contains(value, "LTECA"):
		return TechLTEA
	case strings.Contains(value, "LTE"), strings.Contains(value, "EUTRAN"):
		return TechLTE
	case strings.Contains(value, "HSPA+"):
		return TechHSPAPlus
	case strings.Contains(value, "HSPA"), strings.Contains(value, "HSDPA"), strings.Contains(value, "HSUPA"):
		return TechHSPA
	case strings.Contains(value, "UMTS"), strings.Contains(value, "WCDMA"):
		return TechUMTS
	case strings.Contains(value, "EDGE"):
		return TechEDGE
	case strings.Contains(value, "GPRS"):
		return TechGPRS
	case strings.Contains(value, "GSM"):
		return TechGSM
	default:
		return TechUnknown
	}
}

func registrationStringToStatus(value string) RegistrationStatus {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(value, "roam"):
		return RegRoaming
	case strings.Contains(value, "home"), strings.Contains(value, "registered"):
		return RegHome
	case strings.Contains(value, "search"):
		return RegSearching
	case strings.Contains(value, "denied"):
		return RegDenied
	default:
		return RegUnknown
	}
}

func cellularNetInterface(devicePath string) string {
	base := filepath.Base(devicePath)
	if strings.HasPrefix(base, "wwan") || strings.HasPrefix(base, "rmnet") || strings.HasPrefix(base, "usb") {
		if _, err := os.Stat(filepath.Join("/sys/class/net", base)); err == nil {
			return base
		}
	}
	for _, class := range []string{"/sys/class/usbmisc/" + base + "/device", "/sys/class/wwan/" + base + "/device"} {
		if real, err := filepath.EvalSymlinks(class); err == nil {
			for dir := real; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
				if iface := firstNetChild(dir); iface != "" {
					return iface
				}
			}
		}
	}
	if iface := firstCellularNetInterface(); iface != "" {
		return iface
	}
	return ""
}

func firstNetChild(root string) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || found != "" || !d.IsDir() || filepath.Base(path) != "net" {
			return nil
		}
		entries, readErr := os.ReadDir(path)
		if readErr != nil {
			return nil
		}
		for _, entry := range entries {
			name := entry.Name()
			if _, statErr := os.Stat(filepath.Join("/sys/class/net", name)); statErr == nil {
				found = name
				return filepath.SkipAll
			}
		}
		return nil
	})
	return found
}

func firstCellularNetInterface() string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "wwan") || strings.HasPrefix(name, "rmnet") || strings.HasPrefix(name, "usb") {
			return name
		}
	}
	return ""
}

func findCDCWDMForDevice(devicePath string) string {
	base := filepath.Base(devicePath)
	for _, candidate := range []string{"/sys/class/net/" + base + "/device", "/sys/class/usbmisc/" + base + "/device"} {
		if real, err := filepath.EvalSymlinks(candidate); err == nil {
			for dir := real; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
				var found string
				_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
					if err != nil || found != "" || !d.IsDir() || filepath.Base(path) != "usbmisc" {
						return nil
					}
					entries, readErr := os.ReadDir(path)
					if readErr != nil {
						return nil
					}
					for _, entry := range entries {
						if strings.HasPrefix(entry.Name(), "cdc-wdm") {
							found = "/dev/" + entry.Name()
							return filepath.SkipAll
						}
					}
					return nil
				})
				if found != "" {
					return found
				}
			}
		}
	}
	matches, _ := filepath.Glob("/dev/cdc-wdm*")
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

func parseJSONSignal(data []byte, info *Info) {
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		return
	}
	flat := flattenJSON(raw)
	info.Technology = firstKnownTech(info.Technology, ratStringToTech(firstNonEmpty(flat["type"], flat["lte.type"], flat["nr5g.type"], flat["rat"])))
	setIntFromFlat(&info.Signal.RSSI, flat, "rssi", "lte.rssi", "gsm.rssi", "wcdma.rssi")
	setIntFromFlat(&info.Signal.RSRQ, flat, "rsrq", "lte.rsrq", "nr5g.rsrq")
	setIntFromFlat(&info.Signal.RSRP, flat, "rsrp", "lte.rsrp", "nr5g.rsrp")
	setIntFromFlat(&info.Signal.SINR, flat, "snr", "sinr", "lte.snr", "lte.sinr", "nr5g.snr", "nr5g.sinr")
}

func parseJSONServingSystem(data []byte, info *Info) {
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		return
	}
	flat := flattenJSON(raw)
	info.Status = firstKnownReg(info.Status, registrationStringToStatus(firstNonEmpty(flat["registration"], flat["registration_state"], flat["registration-state"])))
	info.Operator = firstNonEmpty(info.Operator, flat["plmn_description"], flat["plmn_description_raw"], flat["selected_network"], flat["network"])
	info.OperatorMCC = firstNonEmpty(info.OperatorMCC, flat["plmn_mcc"], flat["mcc"])
	info.OperatorMNC = firstNonEmpty(info.OperatorMNC, flat["plmn_mnc"], flat["mnc"])
	info.Technology = firstKnownTech(info.Technology, ratStringToTech(firstNonEmpty(flat["radio_interface"], flat["radio-interface"], flat["type"])))
	if strings.Contains(strings.ToLower(string(data)), "roam") {
		info.Status = RegRoaming
	}
}

func parseJSONCurrentSettings(data []byte, info *Info) {
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		return
	}
	flat := flattenJSON(raw)
	info.APN = firstNonEmpty(info.APN, flat["apn"])
	info.IPAddress = firstNonEmpty(info.IPAddress, flat["ipv4.ip"], flat["ip"], flat["ip-family.ipv4.address"])
	info.IPv6Address = firstNonEmpty(info.IPv6Address, flat["ipv6.ip"], flat["ip-family.ipv6.address"])
	info.DNS1 = firstNonEmpty(info.DNS1, flat["ipv4.dns1"], flat["dns1"])
	info.DNS2 = firstNonEmpty(info.DNS2, flat["ipv4.dns2"], flat["dns2"])
	if info.IPAddress != "" || info.IPv6Address != "" {
		info.Connected = true
	}
}

func flattenJSON(value any) map[string]string {
	out := make(map[string]string)
	var walk func(string, any)
	walk = func(prefix string, v any) {
		switch typed := v.(type) {
		case map[string]any:
			for k, child := range typed {
				key := strings.ToLower(strings.ReplaceAll(k, "-", "_"))
				if prefix != "" {
					key = prefix + "." + key
				}
				walk(key, child)
			}
		case []any:
			for i, child := range typed {
				walk(fmt.Sprintf("%s.%d", prefix, i), child)
			}
		case string:
			out[prefix] = strings.TrimSpace(typed)
		case float64:
			out[prefix] = strconv.FormatFloat(typed, 'f', -1, 64)
		case bool:
			out[prefix] = strconv.FormatBool(typed)
		}
	}
	walk("", value)
	return out
}

func setIntFromFlat(dst *int, flat map[string]string, keys ...string) {
	for _, key := range keys {
		if v, ok := flat[key]; ok {
			setIntIfParsed(dst, v)
			return
		}
	}
}

func (c *atController) findATPort(devicePath string) string {
	// If devicePath is already a serial port, use it directly
	if strings.HasPrefix(devicePath, "/dev/tty") {
		return devicePath
	}

	// For QMI/MBIM devices, find the companion AT port
	// Typical: /dev/cdc-wdm0 → /dev/ttyUSB2 (Quectel EC25/EM06)
	// Check sysfs USB tree for sibling tty devices
	base := filepath.Base(devicePath)
	sysPath := "/sys/class/usbmisc/" + base
	if _, err := os.Stat(sysPath); err != nil {
		sysPath = "/sys/class/net/" + base
	}

	// Resolve to USB device path
	realPath, err := filepath.EvalSymlinks(sysPath + "/device")
	if err != nil {
		// Fallback: try common serial ports
		for _, port := range []string{"/dev/ttyUSB2", "/dev/ttyUSB1", "/dev/ttyUSB0", "/dev/ttyACM0"} {
			if _, err := os.Stat(port); err == nil {
				return port
			}
		}
		return ""
	}

	// Walk up to the USB device root and find tty children
	usbRoot := filepath.Dir(realPath)
	matches, _ := filepath.Glob(usbRoot + "/*/tty*")
	for _, m := range matches {
		entries, _ := os.ReadDir(m)
		for _, e := range entries {
			port := "/dev/" + e.Name()
			if _, err := os.Stat(port); err == nil {
				return port
			}
		}
	}

	return ""
}

// atSession wraps serial I/O for AT commands.
type atSession struct {
	f       *os.File
	scanner *bufio.Scanner
}

func (a *atSession) send(cmd string) []string {
	a.f.Write([]byte(cmd + "\r\n"))

	var lines []string
	deadline := time.After(1500 * time.Millisecond)
	for {
		select {
		case <-deadline:
			return lines
		default:
			if a.scanner.Scan() {
				line := strings.TrimSpace(a.scanner.Text())
				if line == "OK" || line == "ERROR" || strings.HasPrefix(line, "+CME ERROR") {
					return lines
				}
				if line != "" && line != cmd {
					lines = append(lines, line)
				}
			} else {
				return lines
			}
		}
	}
}
