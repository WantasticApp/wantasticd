//go:build linux

// AT command modem controller — pure Go, no CGo dependencies.
// Works with any modem exposing AT command serial ports (/dev/ttyUSB*, /dev/ttyACM*).
// Falls back to sysfs for device discovery.

package modem

import (
	"bufio"
	"fmt"
	"os"
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
	if lines := at.send("AT+CGMR"); len(lines) > 0 {
		info.Revision = lines[0]
	}
	if lines := at.send("AT+GSN"); len(lines) > 0 {
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
				parts := strings.Split(line, ",")
				if len(parts) >= 3 {
					info.APN = strings.Trim(parts[2], "\"")
					break
				}
			}
		}
	}

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
	return fmt.Errorf("AT command connect not implemented — use NetworkManager or uqmi")
}

func (c *atController) Disconnect(devicePath string) error {
	return fmt.Errorf("AT command disconnect not implemented — use NetworkManager or uqmi")
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
	for _, cmd := range []string{"AT+CEREG?", "AT+CREG?"} {
		if lines := at.send(cmd); len(lines) > 0 {
			line := lines[0]
			prefix := "+CEREG:"
			if strings.HasPrefix(line, "+CREG:") {
				prefix = "+CREG:"
			}
			if strings.HasPrefix(line, prefix) {
				parts := strings.Split(strings.TrimPrefix(line, prefix), ",")
				if len(parts) >= 2 {
					switch strings.TrimSpace(parts[1]) {
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
				if len(parts) >= 4 {
					if tac, err := strconv.ParseUint(strings.Trim(parts[2], "\""), 16, 32); err == nil {
						info.TAC = uint32(tac)
					}
					if ci, err := strconv.ParseUint(strings.Trim(parts[3], "\""), 16, 32); err == nil {
						info.CellID = uint32(ci)
					}
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
	case "0":  return TechGSM
	case "1":  return TechGSM // GSM Compact
	case "2":  return TechUMTS
	case "3":  return TechEDGE
	case "4":  return TechHSPA
	case "5":  return TechHSPA
	case "6":  return TechHSPA
	case "7":  return TechLTE
	case "8":  return TechLTEA // LTE-CA (EC-GSM-IoT)
	case "11": return TechNR5G
	case "12": return TechNR5GNSA
	case "13": return TechNR5G // NR-U
	default:   return TechUnknown
	}
}

func csqToBars(csq int) int {
	switch {
	case csq >= 20: return 5
	case csq >= 15: return 4
	case csq >= 10: return 3
	case csq >= 5:  return 2
	case csq >= 1:  return 1
	default:        return 0
	}
}

// findATPort locates the AT command port for a given modem device.
// infoFromSysfs reads modem identity from USB descriptor sysfs files.
// Available even when AT ports can't be opened (permissions, modem busy).
// Paths: /sys/class/net/<iface>/device/../{manufacturer,product,serial}
//        /sys/class/usbmisc/<dev>/device/../{manufacturer,product,serial}
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
