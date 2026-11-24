package fiberolt

import (
	"context"
	"strconv"
	"strings"

	"wantastic-agent/internal/wusp"
)

// CollectOLT fills Device.WUSP_OLT.* from the vendor goform API, the FOS
// command line (cli, optional), and the platform sysinfo file. Every source
// failure degrades to the corresponding Status/StatusDetail fields; it never
// fails the whole collect. enabled mirrors the backend's persisted Enable
// flag.
func CollectOLT(ctx context.Context, api *Client, cli *CLI, enabled bool, msg *wusp.Message) {
	collect(ctx, envFor(api, cli), enabled, msg)
}

// Identity is the OLT's own identity from getSysStatus.
type Identity struct {
	DeviceName, SerialNumber, SoftwareVersion, HardwareVersion, MAC string
}

// CollectOLTEnv is CollectOLT with a full Env (AutoSave hooks) and the
// OLT identity seen during the cycle (zero when the OLT was unreachable).
func CollectOLTEnv(ctx context.Context, env *Env, enabled bool, msg *wusp.Message) Identity {
	c := collect(ctx, env, enabled, msg)
	if c == nil {
		return Identity{}
	}
	doc, err := c.Doc("sysStatus")
	if err != nil {
		return Identity{}
	}
	return Identity{
		DeviceName: strings.TrimSpace(Str(doc["deviceName"])), SerialNumber: strings.TrimSpace(Str(doc["sn"])),
		SoftwareVersion: strings.TrimSpace(Str(doc["softwareVersion"])), HardwareVersion: strings.TrimSpace(Str(doc["hardwareVersion"])),
		MAC: strings.TrimSpace(Str(doc["mac"])),
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
