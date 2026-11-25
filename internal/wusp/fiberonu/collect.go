// Package fiberonu collects the EcoNet EN7528 XPON ONU data surface:
// /proc/pon_phy (optical module DDMI), /proc/xpon (PON MAC state, GPON
// activation state machine, GEM counters) and the boa cgi-bin API on
// loopback (vendor device identity). It is stdlib-only, like fiberolt, so
// it builds for any Go target the ONU can run.
package fiberonu

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// Options locates the vendor surfaces. Defaults point at the standard
// EcoNet/CMCC layout; tests override them.
type Options struct {
	ProcPonPhyDir string
	ProcXponDir   string
	CGIBaseURL    string

	// Network sources; empty means the standard ONU paths.
	TcapiPath      string // /userfs/bin/tcapi
	ProcNetDir     string // /proc/net
	SysClassNetDir string // /sys/class/net
	TmpDir         string // /tmp (cfg_manager list files)

	// Exec runs a read-only command; nil runs it for real. Tests inject
	// fixture output here.
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
	// IfaceAddrs returns each interface's IPv4 addresses in CIDR form; nil
	// asks the kernel over netlink (net.Interfaces).
	IfaceAddrs func() (map[string][]string, error)
}

func (o Options) ponPhyDir() string {
	if o.ProcPonPhyDir == "" {
		return "/proc/pon_phy"
	}
	return o.ProcPonPhyDir
}

func (o Options) xponDir() string {
	if o.ProcXponDir == "" {
		return "/proc/xpon"
	}
	return o.ProcXponDir
}

func (o Options) cgiBase() string {
	if o.CGIBaseURL == "" {
		return "http://127.0.0.1"
	}
	return o.CGIBaseURL
}

// setStatus writes the Status/StatusDetail pair. Status is "ok" only when
// at least one source produced data; the first failure degrades it.
type statusWriter struct {
	msg     *wusp.Message
	failed  string
	details []string
}

func (s *statusWriter) fail(status, detail string) {
	if s.failed == "" {
		s.failed = status
	}
	if detail != "" && len(s.details) < 3 {
		s.details = append(s.details, detail)
	}
}

func (s *statusWriter) finish(enabled bool, ok bool) {
	status := "ok"
	if s.failed != "" {
		status = s.failed
	}
	detail := strings.Join(s.details, "; ")
	s.msg.Set(wusp.WUSPONUPrefix+"Status", wusp.String(status))
	s.msg.Set(wusp.WUSPONUPrefix+"StatusDetail", wusp.String(detail))
	if enabled && ok {
		s.msg.Set(wusp.WUSPONUPrefix+"LastCollectTime", wusp.Uint(uint64(time.Now().Unix())))
	}
}

// CollectONU fills Device.WUSP_ONU.* from the vendor surfaces. Every source
// failure degrades to Status/StatusDetail; it never fails the whole collect.
func CollectONU(ctx context.Context, opts Options, enabled bool, msg *wusp.Message) {
	msg.Set(wusp.WUSPONUPrefix+"Installed", wusp.Bool(true))
	msg.Set(wusp.WUSPONUPrefix+"Platform", wusp.String("onu"))
	if !enabled {
		msg.Set(wusp.WUSPONUPrefix+"Status", wusp.String("disabled"))
		return
	}

	st := &statusWriter{msg: msg}
	ok := false

	// Vendor identity via the loopback boa API (no authentication from
	// localhost). Failure is non-fatal: proc sources still collect.
	if info := fetchSysinfo(ctx, opts.cgiBase()); len(info) > 0 {
		ok = true
		applySysinfo(msg, info)
	} else {
		st.fail("cgi_error", "getSysteminfo.cgi unreachable")
	}

	// PON MAC state + activation + counters.
	if pon := readFile(filepath.Join(opts.xponDir(), "ponInfo")); pon != "" {
		ok = true
		applyPonInfo(msg, pon)
	} else {
		st.fail("read_error", "cannot read /proc/xpon/ponInfo")
	}
	if data := readFile(filepath.Join(opts.xponDir(), "data")); data != "" {
		ok = true
		applyPonData(msg, data)
	}

	// Optical PHY status + DDMI.
	if info := readFile(filepath.Join(opts.ponPhyDir(), "info")); info != "" {
		ok = true
		if phy := parsePhyStatus(info); phy != "" {
			msg.Set(wusp.WUSPONUPrefix+"PhyStatus", wusp.String(phy))
		}
	}
	applyDDMI(msg, opts.ponPhyDir())
	applyPonPhyTcapi(ctx, opts, msg)

	// Register-authoritative values (cgo /dev/mem); silently skipped when
	// the SDK layer is unavailable and the proc values stand.
	applySDKState(msg)

	// Full network state: interfaces, routes, iptables, DHCP, DNS, WLAN.
	wlan := collectNetwork(ctx, opts, msg)

	// The same radios, SSIDs and clients as TR-181 Device.WiFi.*, which the
	// console's Radios / Wi-Fi clients read. nl80211 is absent on this
	// driver, so the generic linux.wifi collector cannot fill them.
	collectWiFiTR181(ctx, opts, wlan, msg)

	st.finish(enabled, ok)
}

// fetchSysinfo reads getSysteminfo.cgi and returns the Name=Value pairs.
func fetchSysinfo(ctx context.Context, base string) map[string]string {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/cgi-bin/getSysteminfo.cgi", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil
	}
	return parseSysinfo(string(body))
}

// parseSysinfo extracts Name=Value pairs from the cgi HTML fragment.
func parseSysinfo(text string) map[string]string {
	values := make(map[string]string)
	for _, token := range strings.FieldsFunc(text, func(r rune) bool { return r == '<' || r == '>' }) {
		token = strings.TrimSpace(token)
		if i := strings.IndexByte(token, '='); i > 0 {
			key := strings.TrimSpace(token[:i])
			val := strings.TrimSpace(token[i+1:])
			if key != "" && val != "" {
				values[key] = val
			}
		}
	}
	return values
}

func applySysinfo(msg *wusp.Message, info map[string]string) {
	set := func(key, path string) {
		if v, ok := info[key]; ok && strings.TrimSpace(v) != "" {
			msg.Set(path, wusp.String(strings.TrimSpace(v)))
		}
	}
	set("GPON_SN", wusp.WUSPONUPrefix+"SerialNumber")
	set("Macaddress", wusp.WUSPONUPrefix+"MacAddress")
	set("OUI", wusp.WUSPONUPrefix+"OUI")
	set("Manufacturer", wusp.WUSPONUPrefix+"Manufacturer")
	set("ModelName", wusp.WUSPONUPrefix+"ModelName")
	set("SWVersion", wusp.WUSPONUPrefix+"FirmwareVersion")
	set("HWVersion", wusp.WUSPONUPrefix+"HardwareVersion")
	if mode, ok := info["PON_MODE"]; ok {
		mode = strings.ToLower(strings.TrimSpace(mode))
		switch mode {
		case "xpon", "gpon", "epon":
			msg.Set(wusp.WUSPONUPrefix+"Mode", wusp.String(mode))
		}
	}
}

// applyPonInfo parses "show"-style register dumps from /proc/xpon/ponInfo:
//
//	Mode: GPON
//	G_ACTIVATION     (0xBFB640BC): 0x1
//	DBG_RX_GEM_CNT              (0xBFB64300): 0x0
func applyPonInfo(msg *wusp.Message, text string) {
	register := func(name string) (uint64, bool) {
		idx := strings.Index(text, name)
		if idx < 0 {
			return 0, false
		}
		rest := text[idx+len(name):]
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			rest = rest[:i]
		}
		colon := strings.LastIndex(rest, ":")
		if colon < 0 {
			return 0, false
		}
		val := strings.TrimSpace(rest[colon+1:])
		if strings.HasPrefix(val, "0x") {
			val = val[2:]
		}
		v, err := strconv.ParseUint(val, 16, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	if mode := parseMode(text); mode != "" {
		if _, present := msg.Get(wusp.WUSPONUPrefix + "Mode"); !present {
			msg.Set(wusp.WUSPONUPrefix+"Mode", wusp.String(mode))
		}
	}
	if activation, ok := register("G_ACTIVATION"); ok {
		if activation >= 1 && activation <= 5 {
			msg.Set(wusp.WUSPONUPrefix+"ActivationState", wusp.String(fmt.Sprintf("O%d", activation)))
		}
	}
	if v, ok := register("DBG_RX_GEM_CNT"); ok {
		msg.Set(wusp.WUSPONUPrefix+"GemRxCount", wusp.Uint(v))
	}
	if v, ok := register("DBG_TX_GEM_CNT"); ok {
		msg.Set(wusp.WUSPONUPrefix+"GemTxCount", wusp.Uint(v))
	}
	if v, ok := register("DBG_RX_CRC_ERR_CNT"); ok {
		msg.Set(wusp.WUSPONUPrefix+"RxCrcErrorCount", wusp.Uint(v))
	}
	var hec uint64
	for _, name := range []string{"DBG_GEM_HEC_ONE_ERR_CNT", "DBG_GEM_HEC_TWO_ERR_CNT", "DBG_GEM_HEC_UC_ERR_CNT"} {
		if v, ok := register(name); ok {
			hec += v
		}
	}
	if hec > 0 {
		msg.Set(wusp.WUSPONUPrefix+"GemHecErrorCount", wusp.Uint(hec))
	}
}

// applyPonData parses /proc/xpon/data struct dumps:
//
//	gpPonSysData->sysLinkStatus: 0
//	gpPonSysData->sysOnuType: 2
//	gpPhyData->phy_link_status: 0
func applyPonData(msg *wusp.Message, text string) {
	value := func(name string) (uint64, bool) {
		idx := strings.Index(text, name)
		if idx < 0 {
			return 0, false
		}
		rest := text[idx+len(name):]
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			rest = rest[:i]
		}
		colon := strings.LastIndex(rest, ":")
		if colon < 0 {
			return 0, false
		}
		val := strings.TrimSpace(rest[colon+1:])
		base := 10
		if strings.HasPrefix(val, "0x") {
			val = val[2:]
			base = 16
		}
		v, err := strconv.ParseUint(val, base, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	if v, ok := value("sysLinkStatus"); ok {
		status := "down"
		if v != 0 {
			status = "up"
		}
		msg.Set(wusp.WUSPONUPrefix+"LinkStatus", wusp.String(status))
	}
	if v, ok := value("sysOnuType"); ok {
		msg.Set(wusp.WUSPONUPrefix+"OnuType", wusp.Uint(v))
	}
	if v, ok := value("sysOltType"); ok {
		msg.Set(wusp.WUSPONUPrefix+"OltType", wusp.String(fmt.Sprintf("%08x", v)))
	}
	if v, ok := value("rogue_state"); ok {
		msg.Set(wusp.WUSPONUPrefix+"RogueState", wusp.Bool(v != 0))
	}
}

// parseMode extracts the "Mode: GPON" line value.
func parseMode(text string) string {
	idx := strings.Index(text, "Mode:")
	if idx < 0 {
		return ""
	}
	rest := text[idx+len("Mode:"):]
	if i := strings.IndexByte(rest, '\n'); i >= 0 {
		rest = rest[:i]
	}
	mode := strings.ToLower(strings.TrimSpace(rest))
	switch mode {
	case "gpon", "epon", "xpon":
		return mode
	default:
		return ""
	}
}

// parsePhyStatus extracts the "PHY Status: unplug" word.
func parsePhyStatus(text string) string {
	idx := strings.Index(text, "PHY Status:")
	if idx < 0 {
		return ""
	}
	rest := text[idx+len("PHY Status:"):]
	if i := strings.IndexByte(rest, '('); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimSpace(rest)
}

// applyDDMI reads the scalar DDMI files and the ddmi dump. While the
// optical module is unplugged the reads fail with I2C errors; those are
// skipped silently and the fields stay unset.
func applyDDMI(msg *wusp.Message, dir string) {
	scalar := map[string]string{
		"Temperature": wusp.WUSPONUPrefix + "Temperature",
		"VCC":         wusp.WUSPONUPrefix + "Voltage",
		"BiasCurrent": wusp.WUSPONUPrefix + "BiasCurrent",
		"RSSICurrent": wusp.WUSPONUPrefix + "RSSI",
		"BER":         wusp.WUSPONUPrefix + "BER",
	}
	for file, path := range scalar {
		text := readFile(filepath.Join(dir, file))
		if v, ok := firstFloat(text); ok {
			msg.Set(path, wusp.Float(v))
		}
	}
	// LOS is 0 when the module sees signal and nonzero on true loss. The old
	// code published Los=true for ANY readable value (including 0), so a
	// healthy link reported "loss of signal". Publish the actual state, and
	// leave Los unset when the read failed (I2C error) rather than asserting
	// loss, so a transient DDMI read glitch can't flap the link to "No light".
	if los := readFile(filepath.Join(dir, "LOS")); los != "" {
		if v, ok := firstFloat(los); ok {
			msg.Set(wusp.WUSPONUPrefix+"Los", wusp.Bool(v != 0))
		}
	}
	// The ddmi dump carries the full SFF-8472 set (temp/VCC/bias/TX/RX)
	// when the module is powered; parse TX/RX power from it.
	if dump := readFile(filepath.Join(dir, "ddmi")); dump != "" && !strings.Contains(dump, "Error!") {
		if v, ok := parseDDMIValue(dump, "TX Power"); ok {
			msg.Set(wusp.WUSPONUPrefix+"TxPower", wusp.Float(v))
		}
		if v, ok := parseDDMIValue(dump, "RX Power"); ok {
			msg.Set(wusp.WUSPONUPrefix+"RxPower", wusp.Float(v))
		}
	}
}

// firstFloat returns the first floating point number in the text, skipping
// vendor error dumps ("Error! phy_I2C_read ...").
func firstFloat(text string) (float64, bool) {
	if text == "" || strings.Contains(text, "Error!") {
		return 0, false
	}
	fields := strings.Fields(text)
	for _, field := range fields {
		field = strings.Trim(field, "(),")
		if v, err := strconv.ParseFloat(field, 64); err == nil {
			return v, true
		}
	}
	return 0, false
}

// parseDDMIValue finds "<key> <value>" (with optional colon) in the ddmi
// dump; value must parse as float.
func parseDDMIValue(text, key string) (float64, bool) {
	idx := strings.Index(text, key)
	if idx < 0 {
		return 0, false
	}
	rest := text[idx+len(key):]
	if i := strings.IndexByte(rest, '\n'); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSpace(rest)
	rest = strings.TrimLeft(rest, ":")
	return firstFloat(rest)
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
