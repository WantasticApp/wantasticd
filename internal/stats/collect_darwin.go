//go:build darwin

package stats

import (
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/iwinfo"
)

var loggedLocationWarning sync.Once

// collectWiFiStatistics - implementation for macOS
// Priority: 1) Native CoreWLAN (via CGo/Objective-C)  2) system_profiler fallback
func collectWiFiStatistics() ([]WiFiInterfaceInfo, bool) {
	// Try native CoreWLAN first (no exec.Command, direct framework calls)
	if ifaces, connected := collectWiFiStatisticsNative(); len(ifaces) > 0 {
		return ifaces, connected
	}

	// Fallback: parse system_profiler output (for older macOS or CGo issues)
	out, err := exec.Command("system_profiler", "SPAirPortDataType").Output()
	if err != nil {
		log.Printf("Failed to execute system_profiler: %v", err)
		return []WiFiInterfaceInfo{}, false
	}

	output := string(out)
	var interfaces []WiFiInterfaceInfo
	var currentIface *WiFiInterfaceInfo

	lines := strings.Split(output, "\n")
	inInterfacesSection := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if trimmed == "Interfaces:" {
			inInterfacesSection = true
			continue
		}

		if !inInterfacesSection {
			continue
		}

		// Check for a new interface (e.g., "        en0:")
		if strings.HasSuffix(line, ":") && strings.HasPrefix(line, "        ") && !strings.HasPrefix(line, "         ") {
			if currentIface != nil {
				interfaces = append(interfaces, *currentIface)
			}
			name := strings.TrimSpace(strings.TrimSuffix(line, ":"))
			currentIface = &WiFiInterfaceInfo{
				Name:      name,
				Connected: false,
			}
			continue
		}

		if currentIface == nil {
			continue
		}

		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "MAC Address":
			currentIface.MAC = value
		case "Status":
			if value == "Connected" {
				currentIface.Connected = true
			}
		case "PHY Mode":
			currentIface.PHYMode = value
		case "Security":
			currentIface.Security = value
		case "Channel":
			// value is like "36 (5GHz, 80MHz)"
			valParts := strings.Fields(value)
			if len(valParts) > 0 {
				if ch, err := strconv.Atoi(valParts[0]); err == nil {
					currentIface.Channel = ch
				}
			}
		case "Signal / Noise":
			// value is like "-69 dBm / -91 dBm"
			valParts := strings.Split(value, " / ")
			if len(valParts) == 2 {
				sigStr := strings.TrimSuffix(valParts[0], " dBm")
				noiseStr := strings.TrimSuffix(valParts[1], " dBm")
				if s, err := strconv.Atoi(sigStr); err == nil {
					currentIface.Signal = s
				}
				if n, err := strconv.Atoi(noiseStr); err == nil {
					currentIface.Noise = n
				}
				if currentIface.Noise != 0 {
					currentIface.SNR = currentIface.Signal - currentIface.Noise
				}
			}
		case "Transmit Rate":
			if rate, err := strconv.Atoi(value); err == nil {
				currentIface.Bitrate = rate
			}
		case "MCS Index":
			if mcs, err := strconv.Atoi(value); err == nil {
				currentIface.MCSIndex = mcs
			}
		case "Current Network Information":
			// The next line is likely the SSID followed by a colon
			if i+1 < len(lines) {
				nextLine := lines[i+1]
				if strings.HasPrefix(nextLine, "            ") && strings.HasSuffix(strings.TrimSpace(nextLine), ":") {
					ssid := strings.TrimSpace(strings.TrimSuffix(nextLine, ":"))
					if ssid == "<redacted>" || ssid == "" {
						// Fallback: try to get SSID via airport utility
						if realSSID, err := getSSIDFromAirport(); err == nil && realSSID != "" {
							ssid = realSSID
						}
					}
					// If still redacted, suppress it and warn user
					if ssid == "<redacted>" {
						ssid = ""
						loggedLocationWarning.Do(func() {
							log.Println("WARNING: SSID is redacted. To view SSID on macOS, enable Location Services for this application (System Settings > Privacy & Security > Location Services).")
						})
					}
					currentIface.SSID = ssid
					i++ // Skip SSID line
				}
			}
		case "Other Local Wi-Fi Networks":
			// Parse nearby networks
			for j := i + 1; j < len(lines); j++ {
				line := lines[j]
				// Nearby networks SSIDs are at 12 spaces indentation
				if !strings.HasPrefix(line, "            ") || strings.HasPrefix(line, "             ") {
					if strings.TrimSpace(line) == "" {
						continue
					}
					// If we hit something less indented than 12 spaces, we're out of the section
					// But we must be careful about empty lines or sub-indents
					if !strings.HasPrefix(line, "            ") {
						i = j - 1 // Update main loop index
						break
					}
					continue
				}

				if strings.HasSuffix(strings.TrimSpace(line), ":") {
					nearby := NearbyNetwork{
						SSID: strings.TrimSpace(strings.TrimSuffix(line, ":")),
					}
					// Parse sub-fields of this nearby network
					for k := j + 1; k < len(lines); k++ {
						subLine := lines[k]
						if !strings.HasPrefix(subLine, "              ") {
							j = k - 1
							break
						}
						subTrimmed := strings.TrimSpace(subLine)
						subParts := strings.SplitN(subTrimmed, ":", 2)
						if len(subParts) == 2 {
							k := strings.TrimSpace(subParts[0])
							v := strings.TrimSpace(subParts[1])
							switch k {
							case "PHY Mode":
								nearby.PHYMode = v
							case "Security":
								nearby.Security = v
							case "Channel":
								parts := strings.Fields(v)
								if len(parts) > 0 {
									nearby.Channel, _ = strconv.Atoi(parts[0])
								}
							case "Signal / Noise":
								parts := strings.Split(v, " / ")
								if len(parts) == 2 {
									sig, _ := strconv.Atoi(strings.TrimSuffix(parts[0], " dBm"))
									noise, _ := strconv.Atoi(strings.TrimSuffix(parts[1], " dBm"))
									nearby.Signal = sig
									nearby.Noise = noise
								}
							}
						}
						j = k
					}
					// Only include nearby networks with real SSIDs (filter out <redacted>)
					if nearby.SSID != "" && nearby.SSID != "<redacted>" {
						currentIface.Nearby = append(currentIface.Nearby, nearby)
					}
				}
				i = j
			}
		}
	}

	if currentIface != nil {
		interfaces = append(interfaces, *currentIface)
	}

	connected := false
	for _, iface := range interfaces {
		if iface.Connected {
			connected = true
			break
		}
	}

	return interfaces, connected
}

// getSSIDFromAirport gets SSID via iwinfo (which uses airport CLI or CoreWLAN).
func getSSIDFromAirport() (string, error) {
	info, err := iwinfo.GetInfo("en0")
	if err != nil {
		return "", err
	}
	return info.SSID, nil
}

// getHostUptime returns the host device uptime in seconds
func getHostUptime() float64 {
	out, err := exec.Command("sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return 0
	}
	// Output format: { sec = 1706050000, usec = 0 } Fri Jan 24 ...
	s := string(out)
	if idx := strings.Index(s, "sec = "); idx != -1 {
		s = s[idx+6:]
		if comma := strings.Index(s, ","); comma != -1 {
			s = s[:comma]
			if bootTime, err := strconv.ParseInt(s, 10, 64); err == nil {
				return time.Since(time.Unix(bootTime, 0)).Seconds()
			}
		}
	}
	return 0
}

// collectNetworkInterfaceStatistics collects network interface statistics using net package and netstat
func collectNetworkInterfaceStatistics() ([]InterfaceInfo, uint64, uint64) {
	var interfaces []InterfaceInfo
	var totalTx, totalRx uint64

	netIfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Failed to get network interfaces: %v", err)
		return interfaces, 0, 0
	}

	for _, netIface := range netIfaces {
		// Stats via netstat
		rx, tx, _ := getInterfaceStats(netIface.Name)
		totalRx += rx
		totalTx += tx

		if netIface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Basic info
		iface := InterfaceInfo{
			Name:    netIface.Name,
			MAC:     netIface.HardwareAddr.String(),
			Up:      netIface.Flags&net.FlagUp != 0,
			RxBytes: rx,
			TxBytes: tx,
		}

		// IPs
		if ips := getInterfaceIPs(netIface.Name); len(ips) > 0 {
			iface.IPs = ips
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces, totalTx, totalRx
}

func getInterfaceStats(name string) (uint64, uint64, error) {
	out, err := exec.Command("netstat", "-b", "-I", name).Output()
	if err != nil {
		return 0, 0, err
	}

	// Parse netstat output
	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return 0, 0, nil
	}

	fields := strings.Fields(lines[1])
	// Typical output: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
	// Index:          0    1   2       3       4     5     6      7     8     9      10
	// Sometimes Address is missing if interface is down or special? But usually netstat -b -I shows it.

	if len(fields) >= 10 {
		rx, _ := strconv.ParseUint(fields[6], 10, 64)
		tx, _ := strconv.ParseUint(fields[9], 10, 64)
		return rx, tx, nil
	}

	return 0, 0, nil
}

func collectCPUUsage() string {
	out, err := exec.Command("top", "-l", "1", "-n", "0").Output()
	if err != nil {
		return "0%"
	}
	// CPU usage: 5.40% user, 6.27% sys, 88.32% idle
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "CPU usage:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				usageParts := strings.Split(parts[1], ",")
				if len(usageParts) > 0 {
					return strings.TrimSpace(usageParts[0]) + " (u)"
				}
			}
		}
	}
	return "0%"
}

func collectSystemMemory() (uint64, uint64) {
	// Total Memory
	totalOut, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return 0, 0
	}
	total, _ := strconv.ParseUint(strings.TrimSpace(string(totalOut)), 10, 64)

	// Used Memory via vm_stat
	// Pages free:                               284145.
	// Pages active:                            1385685.
	// Pages inactive:                           773954.
	// Pages speculative:                         11075.
	// Pages throttled:                               0.
	// Pages wired down:                         372861.
	// Pages purgeable:                           32942.
	// "Translation faults":                  197587849.

	vmOut, err := exec.Command("vm_stat").Output()
	if err != nil {
		return 0, total
	}

	var pagesActive, pagesWired, pagesCompressed uint64
	lines := strings.SplitSeq(string(vmOut), "\n")
	for line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) != 2 {
			continue
		}
		key := strings.TrimSpace(fields[0])
		valStr := strings.TrimSpace(strings.TrimSuffix(fields[1], "."))
		val, _ := strconv.ParseUint(valStr, 10, 64)

		switch key {
		case "Pages active":
			pagesActive = val
		case "Pages wired down":
			pagesWired = val
		case "Pages occupied by compressor":
			pagesCompressed = val
		}
	}

	// Page size is typically 4096 bytes on macOS (arm64/amd64)
	// We could use `pagesize` command to be sure, but 4096 is safe assumption or we can query it.
	// Let's rely on standard page size (4096).
	pageSize := uint64(4096)

	// App Memory = (Anonymous + Purgeable) ... simplified: Wired + Active + Compressed
	used := (pagesActive + pagesWired + pagesCompressed) * pageSize

	if used > total {
		used = total // clamping just in case
	}

	return used, total
}

// collectMeshStatistics - stub for macOS
func collectMeshStatistics() *MeshInfo {
	return nil
}
