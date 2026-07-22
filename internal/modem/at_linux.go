//go:build linux

// AT command modem controller — pure Go, no CGo dependencies.
// Works with any modem exposing AT command serial ports (/dev/ttyUSB*, /dev/ttyACM*).
// Falls back to sysfs for device discovery.

package modem

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// atController communicates with modems via AT commands over serial ports.
// Falls back to sysfs/procfs for device info when AT ports aren't accessible.
type atController struct{}

// The RM520 vendor AT bridge is a single-command transport shared by the
// cellular and GNSS collectors. Concurrent CGI/microcom calls corrupt replies
// and leave helper processes behind.
var atBridgeMu sync.Mutex

// SMS storage and text mode are modem-global state. Keep send/list/delete
// operations together so a collector or a second WUSP request cannot change
// CPMS/CMGF halfway through another SMS transaction.
var smsOperationMu sync.Mutex

const smsToolDevicePath = "sms_tool"
const quectelATBridgePath = "/dev/ttyOUT2"

// errATBridgeResponseMismatch means the vendor CGI relayed a stale response
// from the persistent AT bridge. A control operation is deliberately not
// retried after this error because its effect on the modem is unknown.
var errATBridgeResponseMismatch = errors.New("AT bridge response did not match command")

var atDeviceExists = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (c *atController) Close() error { return nil }

func (c *atController) Discover() ([]string, error) {
	// Quectel SDX/RM520 embedded firmware exposes a vendor-managed AT PTY.
	// Prefer the bridge because atfwd owns the underlying at_mdm/at_usb nodes,
	// and all rmnet_data interfaces represent PDP muxes of this one modem.
	var devices []string
	seen := make(map[string]bool)

	add := func(path string) {
		if !seen[path] {
			seen[path] = true
			devices = append(devices, path)
		}
	}

	if bridge := stableQuectelATBridge(); bridge != "" {
		// QTI/Quectel embedded images expose the modem through this persistent
		// PTY bridge.  rmnet_* is a collection of PDP muxes, while at_mdm* and
		// at_usb* are endpoints owned by atfwd; none represent another modem.
		// Probing each one would serialize a complete AT sweep over the same
		// bridge and starve the WUSP collector for minutes.
		return []string{bridge}, nil
	}

	// 1. sysfs: WWAN network interfaces (most reliable)
	if entries, err := os.ReadDir("/sys/class/net"); err == nil {
		for _, e := range entries {
			name := e.Name()
			if isPrimaryCellularNetInterface(name) {
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
	for _, pattern := range []string{
		"/dev/ttyUSB*", "/dev/ttyACM*",
		// Qualcomm SDX platforms (including the RM520N-GL smart module)
		// expose the modem AT service through these character devices rather
		// than a USB tty.
		"/dev/at_mdm*", "/dev/at_usb*",
	} {
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, m := range matches {
				add(m)
			}
		}
	}

	if smsToolAvailable() {
		if iface := firstCellularNetInterface(); iface != "" {
			add(iface)
		}
		add(smsToolDevicePath)
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
		if c.enrichFromSMSTool(info) {
			c.enrichFromNetStats(devicePath, info)
			if hasCellularInfo(info) {
				return info, nil
			}
		}
		// No AT port — return sysfs-only data if we got anything
		if hasCellularInfo(info) {
			return info, nil
		}
		return nil, fmt.Errorf("no AT port found for %s", devicePath)
	}

	at, closeFn, err := c.openATSessionOnPortWithRetry(port, 3)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	info.Interface = devicePath
	info.Protocol = "at"
	info.CollectedAt = time.Now()
	_, _ = at.sendWithTimeout("AT", time.Second)

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
		info.ICCID = digitsOnly(val)
	} else if lines := at.send("AT+ICCID"); len(lines) > 0 {
		info.ICCID = digitsOnly(parseColonValue(lines[0]))
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
		for _, line := range lines {
			if !strings.HasPrefix(strings.TrimSpace(line), "+CPIN:") {
				continue
			}
			if strings.Contains(line, "READY") {
				info.SIMStatus = SIMReady
			} else if strings.Contains(line, "SIM PIN") {
				info.SIMStatus = SIMLocked
			} else {
				info.SIMStatus = SIMError
			}
			break
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
	if lines := at.send("AT+QRSRP"); len(lines) > 0 {
		parseQuectelMetricAverages(lines, "QRSRP", &info.Signal.RSRP)
	}
	if lines := at.send("AT+QRSRQ"); len(lines) > 0 {
		parseQuectelMetricAverages(lines, "QRSRQ", &info.Signal.RSRQ)
	}
	if lines := at.send("AT+QSINR"); len(lines) > 0 {
		parseQuectelMetricAverages(lines, "QSINR", &info.Signal.SINR)
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
	if lines := at.send("AT+QUIMSLOT?"); len(lines) > 0 {
		info.SIMSlot = parseQuectelSIMSlot(lines)
	}
	if lines := at.send("AT+CFUN?"); len(lines) > 0 {
		info.ModemFunctionality = parseFunctionality(lines[0])
	}
	if lines := at.send("AT+QTEMP"); len(lines) > 0 {
		info.TemperatureC = parseQuectelTemperature(lines)
	}
	if lines := at.send("AT+QNWCFG=\"lte_time_advance\",1;+QNWCFG=\"lte_time_advance\""); len(lines) > 0 {
		info.LTETimingAdvance = parseQuectelTimeAdvance(lines, "lte_time_advance")
	}
	if lines := at.send("AT+QNWCFG=\"nr5g_time_advance\",1;+QNWCFG=\"nr5g_time_advance\""); len(lines) > 0 {
		info.NR5GTimingAdvance = parseQuectelTimeAdvance(lines, "nr5g_time_advance")
	}
	if lines := at.send("AT+QGDCNT?;+QGDNRCNT?"); len(lines) > 0 {
		parseQuectelDataCounters(lines, info)
	}

	info.SupportedTechnologies = inferSupportedTechnologies(info)
	if info.Technology == TechNR5GNSA || hasLTEAndNRCarriers(info.CarrierAggregation) {
		info.NRMode = "NonStandalone"
	} else if info.Technology == TechNR5G {
		info.NRMode = "Standalone"
	} else if info.NRMode == "" {
		info.NRMode = "Unknown"
	}
	c.enrichFromNetStats(devicePath, info)
	if info.IPAddress != "" || info.IPv6Address != "" {
		info.Connected = true
	}

	return info, nil
}

func hasLTEAndNRCarriers(carriers []CarrierInfo) bool {
	var lte, nr bool
	for _, carrier := range carriers {
		switch strings.ToUpper(strings.TrimSpace(carrier.RAT)) {
		case "LTE":
			lte = true
		case "NR", "NR5G":
			nr = true
		}
	}
	return lte && nr
}

func (c *atController) GetSignal(devicePath string) (*SignalQuality, error) {
	port := c.findATPort(devicePath)
	if port == "" {
		if smsToolAvailable() {
			info := c.infoFromSysfs(devicePath)
			if c.enrichFromSMSTool(info) {
				return &info.Signal, nil
			}
		}
		return nil, fmt.Errorf("no AT port found for %s", devicePath)
	}
	at, closeFn, err := c.openATSessionOnPortWithRetry(port, 3)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	_, _ = at.sendWithTimeout("AT", time.Second)
	sig := c.parseSignal(at)
	return &sig, nil
}

func (c *atController) Connect(devicePath, apn string) error {
	apn = strings.TrimSpace(apn)
	if apn == "" {
		return fmt.Errorf("AT command connect requires APN")
	}
	if _, err := c.sendATCommand(devicePath, fmt.Sprintf("AT+CGDCONT=1,\"IPV4V6\",\"%s\"", escapeATString(apn)), 8); err != nil {
		return err
	}
	_, err := c.sendATCommand(devicePath, "AT+CGACT=1,1", 15)
	return err
}

func (c *atController) Disconnect(devicePath string) error {
	_, err := c.sendATCommand(devicePath, "AT+CGACT=0,1", 15)
	return err
}

func (c *atController) SetFunctionality(devicePath, mode string) error {
	value, err := functionalityATValue(mode)
	if err != nil {
		return err
	}
	_, err = c.sendATCommand(devicePath, "AT+CFUN="+value, 30)
	return err
}

func (c *atController) SetSIMSlot(devicePath string, slot int) error {
	if slot < 1 || slot > 4 {
		return fmt.Errorf("SIM slot must be between 1 and 4")
	}
	if _, err := c.sendATCommand(devicePath, "AT+CFUN=0", 30); err != nil {
		return err
	}
	if _, err := c.sendATCommand(devicePath, fmt.Sprintf("AT+QUIMSLOT=%d", slot), 15); err != nil {
		return err
	}
	_, err := c.sendATCommand(devicePath, "AT+CFUN=1", 45)
	return err
}

func (c *atController) SetIMEI(devicePath, imei string) error {
	imei = digitsOnly(imei)
	if len(imei) != 15 {
		return fmt.Errorf("IMEI must contain exactly 15 digits")
	}
	_, err := c.sendATCommand(devicePath, fmt.Sprintf("AT+EGMR=1,7,\"%s\"", imei), 15)
	return err
}

func (c *atController) SetAPNProfile(devicePath string, profile int, pdpType, apn string) error {
	apn = strings.TrimSpace(apn)
	if apn == "" {
		return fmt.Errorf("APN is required")
	}
	if profile <= 0 {
		profile = 1
	}
	pdpType = strings.ToUpper(strings.TrimSpace(pdpType))
	switch pdpType {
	case "", "IPV4V6":
		pdpType = "IPV4V6"
	case "IP", "IPV6":
	default:
		return fmt.Errorf("unsupported PDP type %q", pdpType)
	}
	_, err := c.sendATCommand(devicePath, fmt.Sprintf("AT+CGDCONT=%d,\"%s\",\"%s\"", profile, pdpType, escapeATString(apn)), 8)
	return err
}

func (c *atController) SetGNSS(devicePath string, enabled bool) error {
	if enabled {
		if lines, err := c.sendATCommand(devicePath, "AT+QGPS?", 5); err == nil && quecGPSIsEnabled(lines) {
			return nil
		}
		if _, err := c.sendATCommand(devicePath, "AT+QGPSCFG=\"nmeasrc\",1", 5); err != nil {
			// Older Quectel firmware can reject nmeasrc. The GNSS session itself
			// is still useful without on-demand NMEA sentences.
			_ = err
		}
		_, err := c.sendATCommand(devicePath, "AT+QGPS=1", 20)
		return err
	}
	_, err := c.sendATCommand(devicePath, "AT+QGPSEND", 10)
	return err
}

func (c *atController) GetGNSS(devicePath string) (*GNSSInfo, error) {
	info := &GNSSInfo{
		Status:    "Unknown",
		ModemPath: devicePath,
		Protocol:  "quectel-at",
		NMEA:      map[string]string{},
	}

	lines, err := c.sendATCommand(devicePath, "AT+QGPS?", 5)
	if err != nil {
		return nil, err
	}
	info.Enabled = quecGPSIsEnabled(lines)
	if !info.Enabled {
		info.Status = "Disabled"
		return info, nil
	}

	locationLines, err := c.sendATCommand(devicePath, "AT+QGPSLOC=2", 10)
	if err == nil {
		for _, line := range locationLines {
			if parsed, ok := parseQuectelGPSLocation(line); ok {
				*info = mergeGNSSInfo(*info, parsed)
				info.RawLocation = line
				break
			}
		}
	}

	for _, sentenceType := range []string{"GGA", "RMC", "GSA", "GSV"} {
		if nmea, ok := c.readQuectelNMEA(devicePath, sentenceType); ok {
			info.NMEA[sentenceType] = nmea
			if parsed := gnssInfoFromNMEA(nmea); parsed != nil {
				*info = mergeGNSSInfo(*info, *parsed)
			}
		}
	}

	if info.Status == "Unknown" {
		if info.Latitude != 0 || info.Longitude != 0 {
			info.Status = "Fix2D"
		} else {
			info.Status = "Searching"
		}
	}
	if info.LastFixTime.IsZero() && !info.UTC.IsZero() {
		info.LastFixTime = info.UTC
	}
	if info.LastFixTime.IsZero() && (info.Latitude != 0 || info.Longitude != 0) {
		info.LastFixTime = time.Now()
	}
	return info, nil
}

func (c *atController) readQuectelNMEA(devicePath, sentenceType string) (string, bool) {
	lines, err := c.sendATCommand(devicePath, fmt.Sprintf("AT+QGPSGNMEA=\"%s\"", sentenceType), 8)
	if err != nil {
		return "", false
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "+QGPSGNMEA:") {
			values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QGPSGNMEA:")))
			if len(values) > 0 {
				return values[0], true
			}
		}
		if strings.HasPrefix(line, "$") {
			return line, true
		}
	}
	return "", false
}

func (c *atController) SendSMS(devicePath string, phoneNumber, message string) error {
	smsOperationMu.Lock()
	defer smsOperationMu.Unlock()

	phoneNumber = strings.TrimSpace(phoneNumber)
	message = strings.TrimSpace(message)
	if phoneNumber == "" || message == "" {
		return fmt.Errorf("phone number and message are required")
	}
	if !validSMSPhoneNumber(phoneNumber) {
		return fmt.Errorf("invalid SMS phone number")
	}
	if len(message) > 1600 {
		return fmt.Errorf("SMS message exceeds 1600 bytes")
	}
	if smsToolAvailable() {
		out, err := runSMSToolSMS(40*time.Second, "send", phoneNumber, message)
		if err != nil {
			return fmt.Errorf("sms_tool send failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	const sendBridge = "/usrdata/simpleadmin/www/cgi-bin/send_sms"
	if filepath.Base(c.findATPort(devicePath)) == "ttyOUT2" {
		if info, err := os.Stat(sendBridge); err == nil && !info.IsDir() {
			atBridgeMu.Lock()
			defer atBridgeMu.Unlock()
			reapStaleATBridgeHelpers("/dev/ttyOUT2", 10*time.Second)
			out, err := runVendorCGI(sendBridge, "number="+url.QueryEscape(phoneNumber)+"&msg="+url.QueryEscape(message), 45*time.Second)
			if errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("SMS send timed out")
			}
			if err != nil || atOutputError(out) {
				return fmt.Errorf("SMS send failed: %v: %s", err, strings.TrimSpace(out))
			}
			return nil
		}
	}
	return fmt.Errorf("no native WMS or SMS AT bridge is available")
}

func (c *atController) ListSMS(devicePath string) (string, error) {
	smsOperationMu.Lock()
	defer smsOperationMu.Unlock()

	if smsToolAvailable() {
		out, err := runSMSToolSMS(25*time.Second, "-j", "recv")
		if err != nil {
			return "", fmt.Errorf("sms_tool recv failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return normalizeSMSInboxJSON(string(out))
	}
	var messages []atTextMessage
	var failures []string
	for _, storage := range []string{"SM", "ME"} {
		lines, err := c.sendATCommandWithRetry(devicePath, fmt.Sprintf(`AT+CMGF=1;+CPMS="%s";+CMGL="ALL"`, storage), 12, 1)
		if err != nil {
			failures = append(failures, storage+": "+err.Error())
			continue
		}
		parsed := parseATTextMessages(lines)
		for i := range parsed {
			parsed[i].Storage = storage
		}
		messages = append(messages, parsed...)
	}
	if len(messages) == 0 && len(failures) == 2 {
		return "", fmt.Errorf("list SMS failed: %s", strings.Join(failures, "; "))
	}
	payload, err := json.Marshal(messages)
	return string(payload), err
}

func (c *atController) DeleteSMS(devicePath string, index string) error {
	smsOperationMu.Lock()
	defer smsOperationMu.Unlock()

	index = strings.TrimSpace(index)
	if smsToolAvailable() {
		out, err := runSMSToolSMS(20*time.Second, "delete", index)
		if err != nil {
			return fmt.Errorf("sms_tool delete failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if strings.EqualFold(index, "all") {
		var failures []string
		for _, storage := range []string{"SM", "ME"} {
			if _, err := c.sendATCommand(devicePath, fmt.Sprintf(`AT+CMGF=1;+CPMS="%s";+CMGD=1,4`, storage), 20); err != nil {
				failures = append(failures, storage+": "+err.Error())
			}
		}
		if len(failures) == 2 {
			return fmt.Errorf("delete all SMS failed: %s", strings.Join(failures, "; "))
		}
		return nil
	}
	storage := "SM"
	indexParts := strings.SplitN(index, ":", 2)
	if len(indexParts) == 2 {
		storage = strings.ToUpper(strings.TrimSpace(indexParts[0]))
		index = strings.TrimSpace(indexParts[1])
	}
	if storage != "SM" && storage != "ME" {
		return fmt.Errorf("SMS storage must be SM or ME")
	}
	idx, err := strconv.Atoi(index)
	if err != nil || idx <= 0 {
		return fmt.Errorf("SMS index must be a positive integer or storage:index")
	}
	_, err = c.sendATCommand(devicePath, fmt.Sprintf(`AT+CMGF=1;+CPMS="%s";+CMGD=%d`, storage, idx), 15)
	return err
}

func runSMSToolSMS(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sms_tool", args...).CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("timed out after %s", timeout)
	}
	return out, err
}

type atTextMessage struct {
	Storage string `json:"storage,omitempty"`
	Index   int    `json:"index"`
	Status  string `json:"status,omitempty"`
	Number  string `json:"number,omitempty"`
	Time    string `json:"time,omitempty"`
	Body    string `json:"body,omitempty"`
}

func parseATTextMessages(lines []string) []atTextMessage {
	var out []atTextMessage
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "+CMGL:") {
			values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+CMGL:")))
			if len(values) < 1 {
				continue
			}
			idx, err := strconv.Atoi(strings.TrimSpace(values[0]))
			if err != nil || idx <= 0 {
				continue
			}
			msg := atTextMessage{Index: idx}
			if len(values) > 1 {
				msg.Status = values[1]
			}
			if len(values) > 2 {
				msg.Number = values[2]
			}
			if len(values) > 4 {
				msg.Time = values[4]
			}
			out = append(out, msg)
			continue
		}
		if len(out) > 0 && line != "" && !strings.HasPrefix(line, "+") {
			if out[len(out)-1].Body != "" {
				out[len(out)-1].Body += "\n"
			}
			out[len(out)-1].Body += normalizeSMSBody(line)
		}
	}
	for i := range out {
		out[i].Status = sanitizeSMSText(out[i].Status)
		out[i].Number = sanitizeSMSText(out[i].Number)
		out[i].Time = sanitizeSMSText(out[i].Time)
		out[i].Body = normalizeSMSBody(out[i].Body)
	}
	return out
}

// normalizeSMSInboxJSON makes sms_tool output safe to persist and display. It
// preserves the tool's JSON shape while normalizing textual values, so modem
// firmware can add metadata without forcing a portal schema change.
func normalizeSMSInboxJSON(raw string) (string, error) {
	var payload any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &payload); err != nil {
		return "", fmt.Errorf("sms_tool returned invalid JSON: %w", err)
	}
	normalized, ok := normalizeSMSJSONValue(payload, "")
	if !ok {
		return "", errors.New("sms_tool returned an unsupported JSON payload")
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("encode normalized SMS inbox: %w", err)
	}
	return string(encoded), nil
}

func normalizeSMSJSONValue(value any, field string) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		normalized := make(map[string]any, len(typed))
		for key, child := range typed {
			value, ok := normalizeSMSJSONValue(child, key)
			if !ok {
				return nil, false
			}
			normalized[key] = value
		}
		return normalized, true
	case []any:
		normalized := make([]any, len(typed))
		for i, child := range typed {
			value, ok := normalizeSMSJSONValue(child, field)
			if !ok {
				return nil, false
			}
			normalized[i] = value
		}
		return normalized, true
	case string:
		if isSMSBodyField(field) {
			return normalizeSMSBody(typed), true
		}
		return sanitizeSMSText(typed), true
	case nil, bool, float64:
		return value, true
	default:
		return nil, false
	}
}

func isSMSBodyField(field string) bool {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "body", "message", "text", "content":
		return true
	default:
		return false
	}
}

func normalizeSMSBody(value string) string {
	value = strings.TrimSpace(value)
	if decoded, ok := decodeExplicitUCS2(value); ok {
		value = decoded
	} else if decoded, ok := decodeLikelyUCS2Body(value); ok {
		value = decoded
	}
	return sanitizeSMSText(value)
}

// Quectel integrations sometimes mark text-mode UCS-2 explicitly. Decoding
// only marked or BOM-prefixed data avoids corrupting ordinary hexadecimal OTPs.
func decodeExplicitUCS2(value string) (string, bool) {
	encoded := strings.TrimSpace(value)
	upper := strings.ToUpper(encoded)
	explicit := false
	for _, prefix := range []string{"UCS2:", "UCS-2:", "UTF16BE:"} {
		if strings.HasPrefix(upper, prefix) {
			encoded = strings.TrimSpace(encoded[len(prefix):])
			explicit = true
			break
		}
	}
	if len(encoded) < 4 || len(encoded)%4 != 0 {
		return "", false
	}
	bytes, err := hex.DecodeString(encoded)
	if err != nil {
		return "", false
	}

	littleEndian := len(bytes) >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe
	hasBOM := littleEndian || (len(bytes) >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff)
	if !explicit && !hasBOM {
		return "", false
	}
	if hasBOM {
		bytes = bytes[2:]
	}
	if len(bytes) == 0 || len(bytes)%2 != 0 {
		return "", false
	}

	units := make([]uint16, 0, len(bytes)/2)
	for i := 0; i < len(bytes); i += 2 {
		if littleEndian {
			units = append(units, uint16(bytes[i])|uint16(bytes[i+1])<<8)
		} else {
			units = append(units, uint16(bytes[i])<<8|uint16(bytes[i+1]))
		}
	}
	decoded := string(utf16.Decode(units))
	if strings.ContainsRune(decoded, unicode.ReplacementChar) {
		return "", false
	}
	return decoded, true
}

// Some Quectel SMS helpers return UTF-16BE message bodies as bare hex without
// an encoding marker. Decode only when the shape is strongly text-like so OTPs,
// IDs, and other genuine hexadecimal payloads remain untouched.
func decodeLikelyUCS2Body(value string) (string, bool) {
	encoded := strings.TrimSpace(value)
	if len(encoded) < 16 || len(encoded)%4 != 0 || strings.ContainsAny(encoded, " \t\r\n") {
		return "", false
	}
	for _, r := range encoded {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return "", false
		}
	}

	bytes, err := hex.DecodeString(encoded)
	if err != nil || len(bytes) < 8 || len(bytes)%2 != 0 {
		return "", false
	}
	zeroHighBytes := 0
	units := make([]uint16, 0, len(bytes)/2)
	for i := 0; i < len(bytes); i += 2 {
		if bytes[i] == 0 {
			zeroHighBytes++
		}
		units = append(units, uint16(bytes[i])<<8|uint16(bytes[i+1]))
	}
	if zeroHighBytes*2 < len(units) {
		return "", false
	}

	decoded := string(utf16.Decode(units))
	if strings.ContainsRune(decoded, unicode.ReplacementChar) {
		return "", false
	}
	decoded = sanitizeSMSText(decoded)
	if !looksLikeHumanSMS(decoded) {
		return "", false
	}
	return decoded, true
}

func looksLikeHumanSMS(value string) bool {
	value = strings.TrimSpace(value)
	if len([]rune(value)) < 4 {
		return false
	}
	printable := 0
	lettersOrSpaces := 0
	for _, r := range value {
		if r == '\n' || r == '\t' || unicode.IsPrint(r) {
			printable++
		}
		if unicode.IsLetter(r) || unicode.IsSpace(r) {
			lettersOrSpaces++
		}
	}
	runes := len([]rune(value))
	if runes == 0 || printable*100/runes < 90 {
		return false
	}
	return lettersOrSpaces > 0 && lettersOrSpaces*100/runes >= 15
}

func sanitizeSMSText(value string) string {
	value = strings.ToValidUTF8(value, string(utf8.RuneError))
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return -1
		}
		return r
	}, value)
	return strings.TrimSpace(value)
}

func validSMSPhoneNumber(value string) bool {
	for i, r := range value {
		if r == '+' && i == 0 {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	digits := digitsOnly(value)
	return len(digits) >= 3 && len(digits) <= 15
}

func (c *atController) sendATCommand(devicePath, cmd string, timeoutSeconds int) ([]string, error) {
	return c.sendATCommandWithRetry(devicePath, cmd, timeoutSeconds, 3)
}

func (c *atController) sendATCommandWithRetry(devicePath, cmd string, timeoutSeconds, attempts int) ([]string, error) {
	if attempts <= 0 {
		attempts = 1
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	port := c.findATPort(devicePath)
	var lastErr error
	if port != "" {
		for attempt := 1; attempt <= attempts; attempt++ {
			at, closeFn, err := c.openATSessionOnPort(port)
			if err != nil {
				lastErr = err
				c.unlockStaleSocat(port)
				time.Sleep(time.Duration(attempt) * 150 * time.Millisecond)
				continue
			}
			_, _ = at.sendWithTimeout("AT", time.Second)
			lines, err := at.sendWithTimeout(cmd, time.Duration(timeoutSeconds)*time.Second)
			closeFn()
			if err == nil {
				return lines, nil
			}
			lastErr = err
			if errors.Is(err, errATBridgeResponseMismatch) {
				return lines, err
			}
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
	}
	if smsToolAvailable() {
		for attempt := 1; attempt <= attempts; attempt++ {
			lines, err := runSMSToolAT(cmd, timeoutSeconds)
			if err == nil {
				return lines, nil
			}
			lastErr = err
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no AT port found for %s", devicePath)
}

func (c *atController) openATSession(devicePath string) (*atSession, func(), error) {
	port := c.findATPort(devicePath)
	if port == "" {
		return nil, func() {}, fmt.Errorf("no AT port found for %s", devicePath)
	}
	return c.openATSessionOnPort(port)
}

func (c *atController) openATSessionOnPort(port string) (*atSession, func(), error) {
	if filepath.Base(port) == "ttyOUT2" {
		const cgiAT = "/usrdata/simpleadmin/www/cgi-bin/get_atcommand"
		if info, err := os.Stat(cgiAT); err == nil && !info.IsDir() {
			return &atSession{port: port, cgiAT: cgiAT}, func() {}, nil
		}
		if microcom, err := exec.LookPath("microcom"); err == nil {
			return &atSession{port: port, microcom: microcom}, func() {}, nil
		}
	}
	fd, err := unix.Open(port, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open %s: %w", port, err)
	}
	f := os.NewFile(uintptr(fd), port)
	if f == nil {
		_ = unix.Close(fd)
		return nil, func() {}, fmt.Errorf("open %s: invalid file descriptor", port)
	}
	return &atSession{f: f, reader: bufio.NewReader(f)}, func() { _ = f.Close() }, nil
}

func (c *atController) openATSessionOnPortWithRetry(port string, attempts int) (*atSession, func(), error) {
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		at, closeFn, err := c.openATSessionOnPort(port)
		if err == nil {
			return at, closeFn, nil
		}
		lastErr = err
		c.unlockStaleSocat(port)
		time.Sleep(time.Duration(attempt) * 150 * time.Millisecond)
	}
	return nil, func() {}, lastErr
}

func (c *atController) unlockStaleSocat(port string) {
	// The SDX/RM520 bridge is a long-lived service owned by the firmware.
	// Killing socat to "unlock" a transient client failure tears down the only
	// usable AT path.  The lock left by an interrupted microcom invocation is
	// the recoverable part, so clear only a demonstrably stale lock.
	base := filepath.Base(strings.TrimSpace(port))
	if base == "" || base == "." {
		return
	}
	clearStaleMicrocomLock(filepath.Join("/var/lock", "LCK.."+base))
}

func (c *atController) enrichFromSMSTool(info *Info) bool {
	if info == nil || !smsToolAvailable() {
		return false
	}
	ran := false
	run := func(cmd string, timeout int) []string {
		lines, err := runSMSToolAT(cmd, timeout)
		if err == nil && len(lines) > 0 {
			ran = true
			return lines
		}
		return nil
	}

	info.Protocol = "sms_tool"
	info.CollectedAt = time.Now()
	if iface := firstCellularNetInterface(); iface != "" {
		info.Interface = iface
	}

	if lines := run("ATI", 5); len(lines) > 0 && info.Model == "" {
		info.Model = strings.Join(lines, " ")
	}
	if lines := run("AT+CGMI", 5); len(lines) > 0 && info.Manufacturer == "" {
		info.Manufacturer = strings.TrimSpace(lines[0])
	}
	if lines := run("AT+CGMM", 5); len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
		info.Model = strings.TrimSpace(lines[0])
	}
	if lines := run("AT+CGMR", 5); len(lines) > 0 && info.Revision == "" {
		info.Revision = strings.TrimSpace(lines[0])
	}
	if lines := run("AT+CGSN", 5); len(lines) > 0 && info.IMEI == "" {
		info.IMEI = digitsOnly(lines[0])
	}
	if lines := run("AT+CIMI", 5); len(lines) > 0 && info.IMSI == "" {
		info.IMSI = digitsOnly(lines[0])
	}
	if lines := run("AT+ICCID", 5); len(lines) > 0 && info.ICCID == "" {
		info.ICCID = digitsOnly(parseColonValue(lines[0]))
	} else if lines := run("AT+CCID", 5); len(lines) > 0 && info.ICCID == "" {
		info.ICCID = digitsOnly(parseColonValue(lines[0]))
	}
	if lines := run("AT+CNUM", 5); len(lines) > 0 && info.MSISDN == "" {
		info.MSISDN = parseCNUM(lines[0])
	}
	if lines := run("AT+CPIN?", 5); len(lines) > 0 {
		info.SIMStatus = parseCPIN(lines[0])
	}
	if lines := run("AT+CSQ", 5); len(lines) > 0 {
		parseCSQ(lines[0], &info.Signal)
	}
	if lines := run("AT+QCSQ", 5); len(lines) > 0 {
		c.parseQuectelSignal(lines[0], &info.Signal)
	} else if lines := run("AT+CESQ", 5); len(lines) > 0 {
		c.parseCESQ(lines[0], &info.Signal)
	}
	if lines := run("AT+COPS?", 5); len(lines) > 0 {
		parseCOPS(lines[0], info)
	}
	for _, cmd := range []string{"AT+C5GREG?", "AT+CEREG?", "AT+CGREG?", "AT+CREG?"} {
		if lines := run(cmd, 5); len(lines) > 0 && parseRegistrationLine(lines[0], info) {
			break
		}
	}
	if lines := run("AT+CGDCONT?", 5); len(lines) > 0 {
		parseCGDCONT(lines, info)
	}
	if lines := run("AT+CGCONTRDP", 8); len(lines) > 0 {
		c.parseCGCONTRDP(lines, info)
	}
	if lines := run("AT+QMAP=\"WWAN\"", 5); len(lines) > 0 {
		c.parseQuectelWANIP(lines, info)
	}
	if lines := run("AT+QNWINFO", 5); len(lines) > 0 {
		c.parseQuectelNetworkInfo(lines[0], info)
	}
	if lines := run("AT+QSPN", 5); len(lines) > 0 {
		c.parseQuectelOperator(lines[0], info)
	}
	if lines := run("AT+QENG=\"servingcell\"", 8); len(lines) > 0 {
		c.parseQuectelServingCell(lines, &info.Signal)
		c.parseQuectelServingCellInfo(lines, info)
	}
	if lines := run("AT+QRSRP", 5); len(lines) > 0 {
		parseQuectelMetricAverages(lines, "QRSRP", &info.Signal.RSRP)
	}
	if lines := run("AT+QRSRQ", 5); len(lines) > 0 {
		parseQuectelMetricAverages(lines, "QRSRQ", &info.Signal.RSRQ)
	}
	if lines := run("AT+QSINR", 5); len(lines) > 0 {
		parseQuectelMetricAverages(lines, "QSINR", &info.Signal.SINR)
	}
	if lines := run("AT+QCAINFO", 8); len(lines) > 0 {
		info.CarrierAggregation = parseQuectelCarrierAggregation(lines)
	}
	if lines := run("AT+QENG=\"neighbourcell\"", 8); len(lines) > 0 {
		info.NeighborCells = append(info.NeighborCells, parseQuectelNeighborCells(lines)...)
	}
	if lines := run("AT+QNWCFG=\"nr5g_meas_info\"", 8); len(lines) > 0 {
		info.NeighborCells = append(info.NeighborCells, parseQuectelNR5GMeasInfo(lines)...)
	}
	if lines := run("AT+CPMS?", 5); len(lines) > 0 {
		c.parseSMSStorage(lines[0], info)
	}
	if lines := run("AT+QUIMSLOT?", 5); len(lines) > 0 {
		info.SIMSlot = parseQuectelSIMSlot(lines)
	}
	if lines := run("AT+CFUN?", 5); len(lines) > 0 {
		info.ModemFunctionality = parseFunctionality(lines[0])
	}
	if lines := run("AT+QTEMP", 5); len(lines) > 0 {
		info.TemperatureC = parseQuectelTemperature(lines)
	}
	if lines := run("AT+QNWCFG=\"lte_time_advance\",1;+QNWCFG=\"lte_time_advance\"", 5); len(lines) > 0 {
		info.LTETimingAdvance = parseQuectelTimeAdvance(lines, "lte_time_advance")
	}
	if lines := run("AT+QNWCFG=\"nr5g_time_advance\",1;+QNWCFG=\"nr5g_time_advance\"", 5); len(lines) > 0 {
		info.NR5GTimingAdvance = parseQuectelTimeAdvance(lines, "nr5g_time_advance")
	}
	if lines := run("AT+QGDCNT?;+QGDNRCNT?", 5); len(lines) > 0 {
		parseQuectelDataCounters(lines, info)
	}

	info.SupportedTechnologies = inferSupportedTechnologies(info)
	if info.Technology == TechNR5GNSA {
		info.NRMode = "NonStandalone"
	} else if info.Technology == TechNR5G {
		info.NRMode = "Standalone"
	} else if info.NRMode == "" {
		info.NRMode = "Unknown"
	}
	return ran
}

func smsToolAvailable() bool {
	_, err := exec.LookPath("sms_tool")
	return err == nil
}

func runSMSToolAT(cmd string, timeoutSeconds int) ([]string, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	out, err := exec.Command("sms_tool", "at", cmd, "-t", strconv.Itoa(timeoutSeconds)).CombinedOutput()
	lines := cleanATCommandOutput(string(out), cmd)
	if atOutputError(string(out)) {
		return lines, fmt.Errorf("modem returned error for %q: %s", cmd, atErrorLine(string(out)))
	}
	if err != nil {
		return lines, fmt.Errorf("sms_tool at %q failed: %w: %s", cmd, err, strings.TrimSpace(string(out)))
	}
	return lines, nil
}

func cleanATCommandOutput(raw, cmd string) []string {
	cmd = strings.TrimSpace(cmd)
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || line == cmd || line == "OK" || line == "ERROR" {
			continue
		}
		// Quectel's vendor CGI includes the command that was actually relayed
		// by microcom. Drop all AT command echoes, including stale ones, before
		// handing the response to individual parsers.
		upper := strings.ToUpper(line)
		if upper == "AT" || strings.HasPrefix(upper, "AT+") || strings.HasPrefix(upper, "AT^") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(line, "AT command") || strings.HasPrefix(line, ">") ||
			strings.HasPrefix(lower, "content-type:") ||
			strings.HasPrefix(lower, "microcom:") ||
			strings.HasPrefix(lower, "timeout:") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func atOutputError(raw string) bool {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "ERROR" || strings.HasPrefix(line, "+CME ERROR") || strings.HasPrefix(line, "+CMS ERROR") {
			return true
		}
	}
	return false
}

func atErrorLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "ERROR" || strings.HasPrefix(line, "+CME ERROR") || strings.HasPrefix(line, "+CMS ERROR") {
			return line
		}
	}
	return "ERROR"
}

func hasCellularInfo(info *Info) bool {
	if info == nil {
		return false
	}
	return info.Model != "" ||
		info.Manufacturer != "" ||
		info.IMEI != "" ||
		info.IMSI != "" ||
		info.ICCID != "" ||
		info.Operator != "" ||
		(info.Interface != "" && filepath.Base(info.Interface) != smsToolDevicePath && isCellularNetInterfaceCandidate(filepath.Base(info.Interface))) ||
		info.Signal.RSSI != 0 ||
		info.Signal.RSRP != 0 ||
		info.TxBytes != 0 ||
		info.RxBytes != 0
}

// ── Signal parsing ──────────────────────────────────────────────────────────

func (c *atController) parseSignal(at *atSession) SignalQuality {
	sig := SignalQuality{}

	// Basic CSQ
	if lines := at.send("AT+CSQ"); len(lines) > 0 {
		parseCSQ(lines[0], &sig)
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
	if lines := at.send("AT+QRSRP"); len(lines) > 0 {
		parseQuectelMetricAverages(lines, "QRSRP", &sig.RSRP)
	}
	if lines := at.send("AT+QRSRQ"); len(lines) > 0 {
		parseQuectelMetricAverages(lines, "QRSRQ", &sig.RSRQ)
	}
	if lines := at.send("AT+QSINR"); len(lines) > 0 {
		parseQuectelMetricAverages(lines, "QSINR", &sig.SINR)
	}

	return sig
}

func parseCSQ(line string, sig *SignalQuality) {
	if sig == nil || !strings.HasPrefix(line, "+CSQ:") {
		return
	}
	parts := strings.Split(strings.TrimPrefix(line, "+CSQ:"), ",")
	if len(parts) == 0 {
		return
	}
	if csq, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil && csq >= 0 && csq <= 31 {
		sig.CSQ = csq
		sig.RSSI = -113 + csq*2
		sig.Bars = csqToBars(csq)
	}
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

func parseCNUM(line string) string {
	if !strings.Contains(line, ",") {
		return ""
	}
	parts := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+CNUM:")))
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(strings.Trim(parts[1], "\""))
}

func parseCPIN(line string) SIMStatus {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "READY"):
		return SIMReady
	case strings.Contains(upper, "SIM PIN"), strings.Contains(upper, "SIM PUK"):
		return SIMLocked
	case strings.Contains(upper, "ERROR"):
		return SIMError
	default:
		return SIMAbsent
	}
}

func parseCOPS(line string, info *Info) {
	if info == nil || !strings.HasPrefix(line, "+COPS:") {
		return
	}
	parts := splitATCSV(strings.TrimPrefix(line, "+COPS:"))
	if len(parts) >= 3 {
		info.Operator = strings.Trim(parts[2], "\"")
	}
	if len(parts) >= 4 {
		info.Technology = copsTechToTech(strings.TrimSpace(parts[3]))
	}
}

func parseRegistrationLine(line string, info *Info) bool {
	if info == nil {
		return false
	}
	prefix := ""
	for _, candidate := range []string{"+C5GREG:", "+CEREG:", "+CGREG:", "+CREG:"} {
		if strings.HasPrefix(line, candidate) {
			prefix = candidate
			break
		}
	}
	if prefix == "" {
		return false
	}
	parts := splitATCSV(strings.TrimPrefix(line, prefix))
	statIdx := 1
	if len(parts) == 1 {
		statIdx = 0
	}
	if len(parts) <= statIdx {
		return false
	}
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
	return info.Status != RegNotRegistered
}

func parseCGDCONT(lines []string, info *Info) {
	if info == nil {
		return
	}
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "+CGDCONT:") {
			continue
		}
		parts := splitATCSV(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "+CGDCONT:")))
		if len(parts) >= 3 {
			pdpType := strings.ToUpper(strings.TrimSpace(parts[1]))
			info.APN = strings.TrimSpace(parts[2])
			info.IPVersion = pdpTypeToIPVersion(pdpType)
			return
		}
	}
}

func parseQuectelSIMSlot(lines []string) int {
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "+QUIMSLOT:") {
			continue
		}
		values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "+QUIMSLOT:")))
		if len(values) > 0 {
			if slot, err := strconv.Atoi(strings.TrimSpace(values[0])); err == nil {
				return slot
			}
		}
	}
	return 0
}

func parseFunctionality(line string) string {
	if strings.HasPrefix(strings.TrimSpace(line), "+CFUN:") {
		line = parseColonValue(line)
	}
	switch strings.TrimSpace(line) {
	case "0":
		return "Disabled"
	case "1":
		return "Full"
	case "4":
		return "LowPower"
	default:
		return strings.TrimSpace(line)
	}
}

func quecGPSIsEnabled(lines []string) bool {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "+QGPS:") {
			values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QGPS:")))
			return len(values) > 0 && strings.TrimSpace(values[0]) == "1"
		}
	}
	return false
}

func parseQuectelGPSLocation(line string) (GNSSInfo, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "+QGPSLOC:") {
		return GNSSInfo{}, false
	}
	values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QGPSLOC:")))
	if len(values) < 3 {
		return GNSSInfo{}, false
	}
	lat, errLat := strconv.ParseFloat(strings.Trim(values[1], "\""), 64)
	lon, errLon := strconv.ParseFloat(strings.Trim(values[2], "\""), 64)
	if errLat != nil || errLon != nil || (lat == 0 && lon == 0) {
		return GNSSInfo{}, false
	}
	info := GNSSInfo{
		Enabled:        true,
		Status:         "Fix2D",
		Latitude:       lat,
		Longitude:      lon,
		RawLocation:    line,
		FixQuality:     valueAt(values, 5),
		LastFixTime:    time.Now(),
		Protocol:       "quectel-at",
		SatellitesUsed: int(parseUint(valueAt(values, 10))),
	}
	if info.SatellitesUsed > 0 {
		info.SatellitesInView = info.SatellitesUsed
	}
	info.HDOP = parseFloatDefault(valueAt(values, 3), 0)
	info.Altitude = parseFloatDefault(valueAt(values, 4), 0)
	info.Course = parseFloatDefault(valueAt(values, 6), 0)
	info.SpeedKPH = parseFloatDefault(valueAt(values, 7), 0)
	switch strings.TrimSpace(info.FixQuality) {
	case "3":
		info.Status = "Fix3D"
	case "0", "":
		info.Status = "NoFix"
	default:
		info.Status = "Fix2D"
	}
	if ts := parseQuectelGPSTime(valueAt(values, 0), valueAt(values, 9)); !ts.IsZero() {
		info.UTC = ts
		info.LastFixTime = ts
	}
	return info, true
}

func parseQuectelGPSTime(rawTime, rawDate string) time.Time {
	rawTime = strings.TrimSpace(strings.Trim(rawTime, "\""))
	rawDate = strings.TrimSpace(strings.Trim(rawDate, "\""))
	if len(rawTime) < 6 {
		return time.Time{}
	}
	hour, errH := strconv.Atoi(rawTime[0:2])
	minute, errM := strconv.Atoi(rawTime[2:4])
	secondFloat, errS := strconv.ParseFloat(rawTime[4:], 64)
	if errH != nil || errM != nil || errS != nil {
		return time.Time{}
	}
	second := int(secondFloat)
	nsec := int((secondFloat - float64(second)) * 1e9)
	now := time.Now().UTC()
	year, month, day := now.Date()
	if len(rawDate) == 6 {
		if parsedDay, err := strconv.Atoi(rawDate[0:2]); err == nil {
			day = parsedDay
		}
		if parsedMonth, err := strconv.Atoi(rawDate[2:4]); err == nil && parsedMonth >= 1 && parsedMonth <= 12 {
			month = time.Month(parsedMonth)
		}
		if parsedYear, err := strconv.Atoi(rawDate[4:6]); err == nil {
			if parsedYear >= 70 {
				year = 1900 + parsedYear
			} else {
				year = 2000 + parsedYear
			}
		}
	}
	return time.Date(year, month, day, hour, minute, second, nsec, time.UTC)
}

func gnssInfoFromNMEA(sentence string) *GNSSInfo {
	fields := strings.Split(strings.TrimSpace(sentence), ",")
	if len(fields) == 0 {
		return nil
	}
	talker := strings.TrimPrefix(fields[0], "$")
	switch {
	case strings.HasSuffix(talker, "GGA"):
		return gnssInfoFromGGA(fields, sentence)
	case strings.HasSuffix(talker, "RMC"):
		return gnssInfoFromRMC(fields, sentence)
	case strings.HasSuffix(talker, "GSA"):
		return gnssInfoFromGSA(fields, sentence)
	case strings.HasSuffix(talker, "GSV"):
		return gnssInfoFromGSV(fields, sentence)
	default:
		return nil
	}
}

func gnssInfoFromGGA(fields []string, raw string) *GNSSInfo {
	if len(fields) < 10 {
		return nil
	}
	lat, lon, ok := parseNMEALatLon(fields[2], fields[3], fields[4], fields[5])
	if !ok {
		return nil
	}
	fixQuality := strings.TrimSpace(fields[6])
	if fixQuality == "0" {
		return &GNSSInfo{Enabled: true, Status: "NoFix", FixQuality: fixQuality, NMEA: map[string]string{"GGA": raw}}
	}
	sats := int(parseUint(fields[7]))
	info := &GNSSInfo{
		Enabled:          true,
		Status:           "Fix3D",
		Latitude:         lat,
		Longitude:        lon,
		Altitude:         parseFloatDefault(fields[9], 0),
		HDOP:             parseFloatDefault(fields[8], 0),
		FixQuality:       fixQuality,
		SatellitesUsed:   sats,
		SatellitesInView: sats,
		UTC:              parseNMEATimestamp(fields[1], ""),
		NMEA:             map[string]string{"GGA": raw},
	}
	info.LastFixTime = info.UTC
	return info
}

func gnssInfoFromRMC(fields []string, raw string) *GNSSInfo {
	if len(fields) < 10 || strings.TrimSpace(fields[2]) != "A" {
		return nil
	}
	lat, lon, ok := parseNMEALatLon(fields[3], fields[4], fields[5], fields[6])
	if !ok {
		return nil
	}
	info := &GNSSInfo{
		Enabled:     true,
		Status:      "Fix2D",
		Latitude:    lat,
		Longitude:   lon,
		SpeedKPH:    parseFloatDefault(fields[7], 0) * 1.852,
		Course:      parseFloatDefault(fields[8], 0),
		UTC:         parseNMEATimestamp(fields[1], fields[9]),
		LastFixTime: parseNMEATimestamp(fields[1], fields[9]),
		NMEA:        map[string]string{"RMC": raw},
	}
	return info
}

func gnssInfoFromGSA(fields []string, raw string) *GNSSInfo {
	if len(fields) < 3 {
		return nil
	}
	status := "NoFix"
	switch strings.TrimSpace(fields[2]) {
	case "2":
		status = "Fix2D"
	case "3":
		status = "Fix3D"
	}
	hdop := 0.0
	if len(fields) > 16 {
		hdop = parseFloatDefault(fields[16], 0)
	}
	return &GNSSInfo{Enabled: true, Status: status, HDOP: hdop, FixQuality: strings.TrimSpace(fields[2]), NMEA: map[string]string{"GSA": raw}}
}

func gnssInfoFromGSV(fields []string, raw string) *GNSSInfo {
	if len(fields) < 4 {
		return nil
	}
	return &GNSSInfo{Enabled: true, SatellitesInView: int(parseUint(fields[3])), NMEA: map[string]string{"GSV": raw}}
}

func parseNMEALatLon(rawLat, ns, rawLon, ew string) (float64, float64, bool) {
	lat, ok := parseNMEACoordinate(rawLat, ns)
	if !ok {
		return 0, 0, false
	}
	lon, ok := parseNMEACoordinate(rawLon, ew)
	if !ok {
		return 0, 0, false
	}
	return lat, lon, true
}

func parseNMEACoordinate(raw, hemisphere string) (float64, bool) {
	raw = strings.TrimSpace(raw)
	hemisphere = strings.ToUpper(strings.TrimSpace(hemisphere))
	if raw == "" || hemisphere == "" {
		return 0, false
	}
	degreeDigits := 2
	if hemisphere == "E" || hemisphere == "W" {
		degreeDigits = 3
	}
	if len(raw) <= degreeDigits {
		return 0, false
	}
	degrees, err := strconv.ParseFloat(raw[:degreeDigits], 64)
	if err != nil {
		return 0, false
	}
	minutes, err := strconv.ParseFloat(raw[degreeDigits:], 64)
	if err != nil {
		return 0, false
	}
	value := degrees + minutes/60
	if hemisphere == "S" || hemisphere == "W" {
		value = -value
	}
	return value, true
}

func parseNMEATimestamp(rawTime, rawDate string) time.Time {
	return parseQuectelGPSTime(rawTime, rawDate)
}

func mergeGNSSInfo(base, update GNSSInfo) GNSSInfo {
	if update.Enabled {
		base.Enabled = true
	}
	if update.Status != "" && update.Status != "Unknown" {
		base.Status = update.Status
	}
	if update.Latitude != 0 || update.Longitude != 0 {
		base.Latitude = update.Latitude
		base.Longitude = update.Longitude
	}
	if update.Altitude != 0 {
		base.Altitude = update.Altitude
	}
	if update.SpeedKPH != 0 {
		base.SpeedKPH = update.SpeedKPH
	}
	if update.Course != 0 {
		base.Course = update.Course
	}
	if update.HDOP != 0 {
		base.HDOP = update.HDOP
	}
	if update.FixQuality != "" {
		base.FixQuality = update.FixQuality
	}
	if update.SatellitesUsed != 0 {
		base.SatellitesUsed = update.SatellitesUsed
	}
	if update.SatellitesInView != 0 {
		base.SatellitesInView = update.SatellitesInView
	}
	if !update.UTC.IsZero() {
		base.UTC = update.UTC
	}
	if !update.LastFixTime.IsZero() {
		base.LastFixTime = update.LastFixTime
	}
	if update.RawLocation != "" {
		base.RawLocation = update.RawLocation
	}
	if base.NMEA == nil {
		base.NMEA = map[string]string{}
	}
	for key, value := range update.NMEA {
		if value != "" {
			base.NMEA[key] = value
		}
	}
	if update.ModemPath != "" {
		base.ModemPath = update.ModemPath
	}
	if update.Protocol != "" {
		base.Protocol = update.Protocol
	}
	return base
}

func functionalityATValue(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "1", "full", "on", "enabled", "enable":
		return "1", nil
	case "0", "disabled", "off", "disable":
		return "0", nil
	case "4", "lowpower", "low_power", "airplane", "flight":
		return "4", nil
	case "reset", "restart", "reboot":
		return "1,1", nil
	default:
		return "", fmt.Errorf("unsupported modem functionality %q", mode)
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
				carrier.Band = "B" + digitsOnly(upper[strings.Index(upper, "BAND")+len("BAND"):])
				bandIdx = i
			case strings.Contains(upper, "NR5G BAND"):
				carrier.RAT = "NR"
				carrier.Band = "N" + digitsOnly(upper[strings.Index(upper, "BAND")+len("BAND"):])
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

func parseQuectelMetricAverages(lines []string, metric string, dst *int) {
	if dst == nil || metric == "" {
		return
	}
	prefix := "+" + strings.ToUpper(metric) + ":"
	values := make([]int, 0, 8)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(line), prefix) {
			continue
		}
		payload := strings.TrimSpace(line[len(prefix):])
		for _, part := range splitATCSV(payload) {
			if v, ok := parseQuectelMetricValue(part, metric); ok {
				values = append(values, v)
			}
		}
	}
	if len(values) == 0 {
		return
	}
	sum := 0
	for _, value := range values {
		sum += value
	}
	*dst = sum / len(values)
}

func parseQuectelMetricValue(value, metric string) (int, bool) {
	raw := strings.TrimSpace(strings.Trim(value, "\""))
	if raw == "" || strings.EqualFold(raw, "LTE") || strings.EqualFold(raw, "NR5G") || raw == "-" {
		return 0, false
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	switch strings.ToUpper(metric) {
	case "QRSRP":
		if v == -32768 || v == -37625 || v == -140 || v > 0 || v < -180 {
			return 0, false
		}
	case "QRSRQ":
		if v == -32768 || v == 0 || v > 0 || v < -60 {
			return 0, false
		}
	case "QSINR":
		if v == -32768 || v == -37625 {
			return 0, false
		}
		if v >= 100 || v <= -100 {
			v = parseQuectelSINR(raw, "NR")
		}
		if v < -50 || v > 80 {
			return 0, false
		}
	}
	return v, true
}

func parseQuectelTemperature(lines []string) int {
	values := make([]int, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+QTEMP:") {
			continue
		}
		parts := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QTEMP:")))
		if len(parts) < 2 {
			continue
		}
		temp, err := strconv.Atoi(strings.TrimSpace(strings.Trim(parts[1], "\"")))
		if err != nil || temp < -40 || temp > 125 {
			continue
		}
		values = append(values, temp)
	}
	if len(values) == 0 {
		return 0
	}
	sum := 0
	for _, value := range values {
		sum += value
	}
	return (sum + len(values)/2) / len(values)
}

func parseQuectelTimeAdvance(lines []string, name string) int {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+QNWCFG:") || !strings.Contains(strings.ToLower(line), name) {
			continue
		}
		values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QNWCFG:")))
		for i := len(values) - 1; i >= 1; i-- {
			if v, err := strconv.Atoi(strings.TrimSpace(strings.Trim(values[i], "\""))); err == nil && v >= 0 {
				return v
			}
		}
	}
	return 0
}

func parseQuectelDataCounters(lines []string, info *Info) {
	if info == nil {
		return
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "+QGDNRCNT:"):
			values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QGDNRCNT:")))
			if len(values) >= 2 {
				info.RxBytes = firstNonZero(info.RxBytes, parseUint(values[0]))
				info.TxBytes = firstNonZero(info.TxBytes, parseUint(values[1]))
			}
		case strings.HasPrefix(line, "+QGDCNT:"):
			values := splitATCSV(strings.TrimSpace(strings.TrimPrefix(line, "+QGDCNT:")))
			if len(values) >= 2 {
				info.TxBytes = firstNonZero(info.TxBytes, parseUint(values[0]))
				info.RxBytes = firstNonZero(info.RxBytes, parseUint(values[1]))
			}
		}
	}
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
		if cell.RAT != "LTE" && !strings.Contains(cell.RAT, "NR") {
			continue
		}
		cell.Frequency = parseUint(values[2])
		if strings.TrimSpace(values[3]) == "-" {
			continue
		}
		cell.PCI = parseUint(values[3])
		if cell.RAT == "LTE" || strings.Contains(cell.RAT, "NR") {
			// RM520 LTE/NR QENG neighbor rows report RSRQ before RSRP.
			cell.RSRQ = parseOptionalInt(values[4])
			cell.RSRP = parseOptionalInt(values[5])
		}
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

func parseFloatDefault(value string, fallback float64) float64 {
	value = strings.TrimSpace(strings.Trim(value, "\""))
	if value == "" || value == "-" {
		return fallback
	}
	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return v
}

func valueAt(values []string, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return strings.TrimSpace(values[index])
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
	if isCellularNetInterfaceCandidate(base) {
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
	if iface := defaultRouteCellularInterface("/proc/net/route"); iface != "" {
		return iface
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		name := entry.Name()
		if isPrimaryCellularNetInterface(name) {
			return name
		}
	}
	if !smsToolAvailable() {
		return ""
	}
	for _, entry := range entries {
		name := entry.Name()
		if isCellularNetInterfaceCandidate(name) {
			return name
		}
	}
	return ""
}

func defaultRouteCellularInterface(routePath string) string {
	raw, err := os.ReadFile(routePath)
	if err != nil {
		return ""
	}
	return parseDefaultRouteCellularInterface(string(raw))
}

func parseDefaultRouteCellularInterface(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x1 == 0 {
			continue
		}
		if isPrimaryCellularNetInterface(fields[0]) {
			return fields[0]
		}
	}
	return ""
}

func isPrimaryCellularNetInterface(name string) bool {
	for _, prefix := range []string{"wwan", "rmnet", "qmimux", "mhi", "usb"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func isCellularNetInterfaceCandidate(name string) bool {
	if name == "" {
		return false
	}
	if isPrimaryCellularNetInterface(name) {
		return true
	}
	lower := strings.ToLower(name)
	for _, prefix := range []string{"lo", "tun", "utun", "wg", "wlan", "wifi", "phy", "ifb", "veth", "docker", "tailscale", "zt"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	switch lower {
	case "br-lan", "lan", "lan0":
		return false
	case "bridge0", "wan", "wan0", "eth0", "eth1":
		return true
	}
	return strings.HasPrefix(lower, "br-wan") || strings.HasPrefix(lower, "eth")
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

func stableQuectelATBridge() string {
	if atDeviceExists(quectelATBridgePath) {
		return quectelATBridgePath
	}
	return ""
}

func isContendedQuectelATPort(path string) bool {
	base := filepath.Base(strings.TrimSpace(path))
	return strings.HasPrefix(base, "at_usb") || strings.HasPrefix(base, "at_mdm")
}

func normalizeATPortCandidate(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if isContendedQuectelATPort(path) {
		if bridge := stableQuectelATBridge(); bridge != "" {
			return bridge
		}
	}
	return path
}

func (c *atController) findATPort(devicePath string) string {
	devicePath = strings.TrimSpace(devicePath)
	// If devicePath is already a serial port, use it directly
	if strings.HasPrefix(devicePath, "/dev/tty") ||
		strings.HasPrefix(devicePath, "/dev/at_mdm") ||
		strings.HasPrefix(devicePath, "/dev/at_usb") {
		return normalizeATPortCandidate(devicePath)
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
		for _, port := range []string{quectelATBridgePath, "/dev/ttyUSB2", "/dev/ttyUSB1", "/dev/ttyUSB0", "/dev/ttyACM0", "/dev/at_mdm0", "/dev/at_usb0"} {
			candidate := normalizeATPortCandidate(port)
			if atDeviceExists(candidate) {
				return candidate
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
			candidate := normalizeATPortCandidate(port)
			if atDeviceExists(candidate) {
				return candidate
			}
		}
	}

	return ""
}

// atSession wraps serial I/O for AT commands.
type atSession struct {
	f        *os.File
	reader   *bufio.Reader
	port     string
	microcom string
	cgiAT    string
}

func (a *atSession) send(cmd string) []string {
	lines, _ := a.sendWithTimeout(cmd, 1500*time.Millisecond)
	return lines
}

func (a *atSession) sendWithTimeout(cmd string, timeout time.Duration) ([]string, error) {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	if a.cgiAT != "" {
		atBridgeMu.Lock()
		defer atBridgeMu.Unlock()
		// get_atcommand delegates to microcom.  The vendor CGI does not remove
		// an empty or dead lock itself, causing every query to back off until the
		// process timeout.  Clean it while holding the shared bridge lock so a
		// live concurrent request cannot be disturbed.
		attempts := 1
		if isBridgeReadOnlyATCommand(cmd) {
			// The bridge can retain one reply after a restarted caller. Repeating
			// a read command is safe and drains that stale reply without risking a
			// duplicated SMS or a repeated modem mutation.
			attempts = 3
		}
		var lastLines []string
		for attempt := 0; attempt < attempts; attempt++ {
			reapStaleATBridgeHelpers(a.port, 10*time.Second)
			clearStaleMicrocomLock(filepath.Join("/var/lock", "LCK.."+filepath.Base(a.port)))
			raw, err := runATBridgeCGI(a.cgiAT, cmd, timeout)
			lines := cleanATCommandOutput(raw, cmd)
			lastLines = lines
			if !cgiATResponseMatches(raw, cmd) {
				if attempt+1 < attempts {
					continue
				}
				return lines, fmt.Errorf("%w: %q", errATBridgeResponseMismatch, cmd)
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return lines, fmt.Errorf("AT command %q timed out", cmd)
			}
			if atOutputError(raw) {
				return lines, fmt.Errorf("AT command %q failed: %s", cmd, atErrorLine(raw))
			}
			if err != nil {
				return lines, fmt.Errorf("AT bridge %q failed: %w", cmd, err)
			}
			return lines, nil
		}
		return lastLines, fmt.Errorf("%w: %q", errATBridgeResponseMismatch, cmd)
	}
	if a.microcom != "" {
		atBridgeMu.Lock()
		defer atBridgeMu.Unlock()
		lockPath := filepath.Join("/var/lock", "LCK.."+filepath.Base(a.port))
		clearStaleMicrocomLock(lockPath)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		millis := int(timeout / time.Millisecond)
		command := exec.CommandContext(ctx, a.microcom, "-t", strconv.Itoa(millis), a.port)
		command.Stdin = strings.NewReader(cmd + "\r\n")
		output, err := command.CombinedOutput()
		_ = os.Remove(lockPath)
		lines := cleanATCommandOutput(string(output), cmd)
		if ctx.Err() != nil {
			return lines, fmt.Errorf("AT command %q timed out", cmd)
		}
		if atOutputError(string(output)) {
			return lines, fmt.Errorf("AT command %q failed: %s", cmd, atErrorLine(string(output)))
		}
		if err != nil {
			return lines, fmt.Errorf("microcom %q failed: %w", cmd, err)
		}
		return lines, nil
	}
	if err := a.f.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = err
	}
	if _, err := a.f.Write([]byte(cmd + "\r\n")); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	var lines []string
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return lines, fmt.Errorf("AT command %q timed out", cmd)
		}
		pollTimeout := int(remaining / time.Millisecond)
		if pollTimeout < 1 {
			pollTimeout = 1
		}
		fds := []unix.PollFd{{Fd: int32(a.f.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, pollTimeout)
		if err != nil {
			return lines, err
		}
		if n == 0 {
			return lines, fmt.Errorf("AT command %q timed out", cmd)
		}
		raw, err := a.reader.ReadString('\n')
		if err != nil {
			return lines, err
		}
		line := strings.TrimSpace(raw)
		if line == "" || line == cmd {
			continue
		}
		if line == "OK" {
			return lines, nil
		}
		if line == "ERROR" || strings.HasPrefix(line, "+CME ERROR") || strings.HasPrefix(line, "+CMS ERROR") {
			return lines, fmt.Errorf("AT command %q failed: %s", cmd, line)
		}
		lines = append(lines, line)
	}
}

// runATBridgeCGI executes the vendor get_atcommand CGI in its own process
// group. The CGI invokes microcom itself; killing only the parent shell leaves
// that child holding the output pipe and makes exec.Wait block indefinitely.
// On timeout we kill the CGI group, which releases that transient microcom but
// intentionally leaves the firmware-owned socat bridge untouched.
func runATBridgeCGI(cgiPath, atCommand string, timeout time.Duration) (string, error) {
	return runVendorCGI(cgiPath, "atcmd="+url.QueryEscape(atCommand), timeout)
}

func runVendorCGI(cgiPath, query string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	command := exec.Command(cgiPath)
	command.Env = append(os.Environ(), "QUERY_STRING="+query)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		return output.String(), err
	}

	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return output.String(), err
	case <-ctx.Done():
		// Negative PID addresses the dedicated process group created above.
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		<-done
		return output.String(), ctx.Err()
	}
}

func cgiATResponseMatches(raw, cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	// get_atcommand prints its requested command before a blank line, then the
	// microcom response. Only the latter confirms which command was received by
	// the modem; the first echo always matches even when the response is stale.
	normalized := strings.ReplaceAll(raw, "\r", "")
	_, response, found := strings.Cut(normalized, "\n\n")
	if !found {
		return false
	}
	for _, line := range strings.Split(response, "\n") {
		if strings.TrimSpace(line) == cmd {
			return true
		}
	}
	return false
}

func isBridgeReadOnlyATCommand(cmd string) bool {
	upper := strings.ToUpper(strings.TrimSpace(cmd))
	if upper == "AT" || upper == "ATI" || strings.HasSuffix(upper, "?") {
		return true
	}
	for _, prefix := range []string{
		"AT+CGMI", "AT+CGMM", "AT+CGMR", "AT+GSN", "AT+CGSN", "AT+CIMI", "AT+CCID", "AT+ICCID", "AT+CNUM",
		"AT+CSQ", "AT+CESQ", "AT+QCSQ", "AT+QENG=", "AT+QRSRP", "AT+QRSRQ", "AT+QSINR", "AT+QNWINFO", "AT+QSPN",
		"AT+QCAINFO", "AT+QTEMP", "AT+CGPADDR", "AT+CGCONTRDP", "AT+QMAP=", "AT+QGPSLOC", "AT+QGPSGNMEA=",
	} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func clearStaleMicrocomLock(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		_ = os.Remove(path)
		return
	}
	if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
		_ = os.Remove(path)
	}
}

// reapStaleATBridgeHelpers clears orphaned CGI/microcom pairs left behind by
// older agents. The vendor's permanent socat process is intentionally never a
// candidate. A normal CGI round trip is measured in milliseconds, so a helper
// older than the grace period can no longer be a healthy modem operation.
func reapStaleATBridgeHelpers(port string, grace time.Duration) {
	if filepath.Base(port) != "ttyOUT2" || grace <= 0 {
		return
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	var stale []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		command := strings.ReplaceAll(string(cmdline), "\x00", " ")
		isCGI := strings.Contains(command, "/cgi-bin/get_atcommand")
		isMicrocom := strings.Contains(command, "microcom") && strings.Contains(command, filepath.Base(port))
		if !isCGI && !isMicrocom {
			continue
		}
		if age, ok := procAge(pid); ok && age >= grace {
			stale = append(stale, pid)
		}
	}
	for _, pid := range stale {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func procAge(pid int) (time.Duration, bool) {
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	end := strings.LastIndex(string(stat), ")")
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(string(stat)[end+1:])
	// /proc/<pid>/stat field 22 is starttime. The command name is field 2,
	// so it is index 19 after trimming the closing parenthesis.
	if len(fields) <= 19 {
		return 0, false
	}
	startTicks, err := strconv.ParseFloat(fields[19], 64)
	if err != nil {
		return 0, false
	}
	uptime, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	uptimeFields := strings.Fields(string(uptime))
	if len(uptimeFields) == 0 {
		return 0, false
	}
	uptimeSeconds, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil {
		return 0, false
	}
	// Linux embedded targets, including this QTI image, report starttime in
	// USER_HZ ticks (100Hz). The grace period is deliberately large enough
	// that a small platform variation cannot affect live requests.
	ageSeconds := uptimeSeconds - startTicks/100
	if ageSeconds < 0 {
		return 0, false
	}
	return time.Duration(ageSeconds * float64(time.Second)), true
}
