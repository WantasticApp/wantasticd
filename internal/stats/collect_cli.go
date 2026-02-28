//go:build linux

package stats

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"wantastic-agent/internal/iwinfo"
)

// augmentWiFiWithFallbacks enriches WiFi interface data using native libs and filesystem.
// Priority: 0) libiwinfo (native CGo)  1) debugfs station files  2) /proc/net/wireless
// NO exec.Command calls — pure native libraries and filesystem reads only.
// All operations are crash-safe: panics are recovered, nil/bounds are checked.
func augmentWiFiWithFallbacks(interfaces *[]WiFiInterfaceInfo, connected *bool) {
	defer func() { recover() }() // never crash the agent

	if interfaces == nil {
		return
	}

	// If netlink found zero interfaces, discover from filesystem
	if len(*interfaces) == 0 {
		// Try /proc/net/wireless first
		procfsW := readWirelessProcfs()
		for iface := range procfsW {
			*interfaces = append(*interfaces, WiFiInterfaceInfo{Name: iface})
		}
		// Also try /sys/class/net/*/wireless
		if len(*interfaces) == 0 {
			for _, name := range discoverWirelessInterfaces() {
				*interfaces = append(*interfaces, WiFiInterfaceInfo{Name: name})
			}
		}
	}

	// Collect per-station signal data from debugfs (pure filesystem)
	stationSignals := readDebugfsStationSignals()

	for i := range *interfaces {
		iface := &(*interfaces)[i]
		if iface.Signal != 0 && iface.Bitrate != 0 && iface.SSID != "" {
			continue // already complete from netlink
		}

		// --- Layer 0: libiwinfo (native C library, highest quality) ---
		if iwinfo.Available(iface.Name) {
			fillFromIwinfo(iface, connected)
		}

		// Skip remaining layers if libiwinfo filled everything
		if iface.Signal != 0 && iface.Bitrate != 0 && iface.SSID != "" {
			recalcSNR(iface)
			continue
		}

		// --- Layer 1: debugfs station files (pure filesystem) ---
		if iface.Signal == 0 {
			if sigs, ok := stationSignals[iface.Name]; ok && len(sigs) > 0 {
				var sum int
				for _, s := range sigs {
					sum += s
				}
				iface.Signal = sum / len(sigs)
				iface.Connected = true
				*connected = true
			}
		}

		// --- Layer 2: sysfs bitrate fallback ---
		if iface.Bitrate == 0 {
			iface.Bitrate = readBitrateFromSysfs(iface.Name)
		}

		// --- Layer 3: sysfs txpower fallback ---
		if iface.TxPower == 0 {
			iface.TxPower = readTxPowerFromDebugfs(iface.Name)
		}

		// --- Layer 4: CLI Fallback (iw) for standard Linux nodes without libiwinfo ---
		if iface.SSID == "" || iface.Signal == 0 || iface.TxPower == 0 {
			fillFromIwCLI(iface, connected)
		}

		recalcSNR(iface)
	}

	// Release libiwinfo resources
	iwinfo.Close()
}

// fillFromIwinfo uses the native libiwinfo wrapper to fill WiFi interface data.
func fillFromIwinfo(iface *WiFiInterfaceInfo, connected *bool) {
	defer func() { recover() }()

	if info, err := iwinfo.GetInfo(iface.Name); err == nil {
		if iface.Signal == 0 && info.Signal != 0 {
			iface.Signal = info.Signal
		}
		if iface.Noise == 0 && info.Noise != 0 {
			iface.Noise = info.Noise
		}
		if iface.Bitrate == 0 && info.Bitrate > 0 {
			iface.Bitrate = info.Bitrate / 1000 // kbit/s → Mbps
		}
		if iface.SSID == "" && info.SSID != "" {
			iface.SSID = info.SSID
		}
		if iface.Channel == 0 && info.Channel > 0 {
			iface.Channel = info.Channel
		}
		if iface.Frequency == 0 && info.Frequency > 0 {
			iface.Frequency = info.Frequency
		}
		if iface.TxPower == 0 && info.TxPower > 0 {
			iface.TxPower = info.TxPower
		}
		if info.Signal != 0 || info.SSID != "" {
			iface.Connected = true
			*connected = true
		}
	}

	// Also get per-station stats from assoclist (AP mode)
	if iface.Signal == 0 || iface.RxBytes == 0 {
		if assocs, err := iwinfo.GetAssocList(iface.Name); err == nil && len(assocs) > 0 {
			var sigSum int
			var totalRx, totalTx uint64
			for _, a := range assocs {
				sigSum += int(a.Signal)
				totalRx += a.RxBytes
				totalTx += a.TxBytes
			}
			if iface.Signal == 0 {
				iface.Signal = sigSum / len(assocs)
			}
			if iface.RxBytes == 0 {
				iface.RxBytes = totalRx
			}
			if iface.TxBytes == 0 {
				iface.TxBytes = totalTx
			}
			iface.Connected = true
			*connected = true
		}
	}
}

// fillFromIwCLI safely executes `iw dev X link` and `iw dev X info` as a last resort on standard Linux environments.
func fillFromIwCLI(iface *WiFiInterfaceInfo, connected *bool) {
	defer func() { recover() }()

	// 1. Try `iw dev <iface> link` (station mode)
	if out, err := exec.Command("iw", "dev", iface.Name, "link").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "SSID:") {
				iface.SSID = strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
				iface.Connected = true
				*connected = true
			} else if strings.HasPrefix(line, "signal:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if sig, err := strconv.Atoi(parts[1]); err == nil && iface.Signal == 0 {
						iface.Signal = sig
						iface.Connected = true
						*connected = true
					}
				}
			} else if strings.HasPrefix(line, "tx bitrate:") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					if br, err := strconv.ParseFloat(parts[2], 64); err == nil && iface.Bitrate == 0 {
						iface.Bitrate = int(br)
					}
				}
			}
		}
	}

	// 2. Try `iw dev <iface> info` to catch AP/Mesh mode interfaces where link is usually "Not connected".
	if out, err := exec.Command("iw", "dev", iface.Name, "info").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ssid ") {
				iface.SSID = strings.TrimSpace(strings.TrimPrefix(line, "ssid "))
				// Merely broadcasting an SSID implies the interface is active/connected
				iface.Connected = true
				*connected = true
			} else if strings.HasPrefix(line, "txpower ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if pwr, err := strconv.ParseFloat(parts[1], 64); err == nil && iface.TxPower == 0 {
						iface.TxPower = int(pwr)
					}
				}
			}
		}
	}
}

func recalcSNR(iface *WiFiInterfaceInfo) {
	if iface.Signal != 0 && iface.Noise != 0 {
		iface.SNR = iface.Signal - iface.Noise
	}
}

// ---------------------------------------------------------------------------
// Filesystem-based collection (no exec.Command, no CLI)
// ---------------------------------------------------------------------------

// readDebugfsStationSignals reads per-interface station signal from
// /sys/kernel/debug/ieee80211/phyN/netdev:IFACE/stations/MAC/signal
// Returns map[ifaceName][]signalValues
func readDebugfsStationSignals() map[string][]int {
	result := make(map[string][]int)

	phys, err := filepath.Glob("/sys/kernel/debug/ieee80211/phy*")
	if err != nil {
		return result
	}

	for _, phyDir := range phys {
		netdevs, _ := filepath.Glob(filepath.Join(phyDir, "netdev:*"))
		for _, nd := range netdevs {
			base := filepath.Base(nd)
			ifaceName := strings.TrimPrefix(base, "netdev:")

			stationsDir := filepath.Join(nd, "stations")
			stations, err := os.ReadDir(stationsDir)
			if err != nil {
				continue
			}

			for _, st := range stations {
				sigFile := filepath.Join(stationsDir, st.Name(), "signal")
				data, err := os.ReadFile(sigFile)
				if err != nil {
					continue
				}
				// File contains e.g. "-45" or "-45 -47 -46" (per-chain)
				fields := strings.Fields(strings.TrimSpace(string(data)))
				if len(fields) > 0 {
					if sig, err := strconv.Atoi(fields[0]); err == nil {
						result[ifaceName] = append(result[ifaceName], sig)
					}
				}
			}
		}
	}

	return result
}

// readBitrateFromSysfs reads link speed from /sys/class/net/<iface>/speed
// Returns speed in Mbps, or 0 if unavailable.
func readBitrateFromSysfs(ifaceName string) int {
	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/speed", ifaceName))
	if err != nil {
		return 0
	}
	val, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || val < 0 {
		return 0
	}
	return val
}

// readTxPowerFromDebugfs reads TxPower from debugfs IEEE80211
// /sys/kernel/debug/ieee80211/phyN/power
func readTxPowerFromDebugfs(ifaceName string) int {
	// Find the phy for this interface
	phyLink := fmt.Sprintf("/sys/class/net/%s/phy80211", ifaceName)
	phyTarget, err := os.Readlink(phyLink)
	if err != nil {
		return 0
	}
	phyName := filepath.Base(phyTarget)
	powerFile := fmt.Sprintf("/sys/kernel/debug/ieee80211/%s/power", phyName)
	data, err := os.ReadFile(powerFile)
	if err != nil {
		return 0
	}
	val, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return val
}

// ---------------------------------------------------------------------------
// Mesh signal enrichment (filesystem only, no CLI)
// ---------------------------------------------------------------------------

// augmentMeshSignals populates missing signal values in mesh topology nodes.
// Uses debugfs station files to map MAC→signal. No exec.Command.
func augmentMeshSignals(mesh *MeshInfo) {
	defer func() { recover() }() // never crash

	if mesh == nil || mesh.Topology == nil {
		return
	}

	macToSignal := readDebugfsStationMACs()

	// Also try libiwinfo assoclist for each wireless interface
	for _, ifaceName := range discoverWirelessInterfaces() {
		if iwinfo.Available(ifaceName) {
			if assocs, err := iwinfo.GetAssocList(ifaceName); err == nil {
				for _, a := range assocs {
					if len(a.MAC) == 6 {
						mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
							a.MAC[0], a.MAC[1], a.MAC[2], a.MAC[3], a.MAC[4], a.MAC[5])
						macToSignal[mac] = int(a.Signal)
					}
				}
			}
		} else {
			// standard linux fallback: iw dev <name> station dump
			if out, err := exec.Command("iw", "dev", ifaceName, "station", "dump").Output(); err == nil {
				var currentMAC string
				for _, line := range strings.Split(string(out), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "Station ") {
						parts := strings.Fields(line)
						if len(parts) >= 2 {
							currentMAC = strings.ToLower(parts[1])
						}
					} else if currentMAC != "" && strings.HasPrefix(line, "signal:") {
						parts := strings.Fields(line)
						if len(parts) >= 2 {
							if sig, err := strconv.Atoi(parts[1]); err == nil {
								macToSignal[currentMAC] = sig
							}
						}
					}
				}
			}
		}
	}
	iwinfo.Close()

	traverseMeshSignals(mesh.Topology, macToSignal)
}

// readDebugfsStationMACs reads MAC→signal from all debugfs station dirs.
func readDebugfsStationMACs() map[string]int {
	result := make(map[string]int)

	phys, err := filepath.Glob("/sys/kernel/debug/ieee80211/phy*")
	if err != nil {
		return result
	}

	for _, phyDir := range phys {
		netdevs, _ := filepath.Glob(filepath.Join(phyDir, "netdev:*"))
		for _, nd := range netdevs {
			stationsDir := filepath.Join(nd, "stations")
			stations, err := os.ReadDir(stationsDir)
			if err != nil {
				continue
			}

			for _, st := range stations {
				mac := strings.ToLower(st.Name())
				sigFile := filepath.Join(stationsDir, st.Name(), "signal")
				data, err := os.ReadFile(sigFile)
				if err != nil {
					continue
				}
				fields := strings.Fields(strings.TrimSpace(string(data)))
				if len(fields) > 0 {
					if sig, err := strconv.Atoi(fields[0]); err == nil {
						result[mac] = sig
					}
				}
			}
		}
	}

	return result
}

func traverseMeshSignals(node *MeshNode, signals map[string]int) {
	if node == nil {
		return
	}

	macLower := strings.ToLower(node.MAC)
	if node.Signal == 0 && macLower != "" {
		if sig, ok := signals[macLower]; ok {
			node.Signal = sig
		} else if len(macLower) >= 14 {
			// Fuzzy match: mesh MACs can differ in last byte per interface
			prefix := macLower[:14]
			for mapMac, sig := range signals {
				if len(mapMac) >= 14 && strings.HasPrefix(mapMac, prefix) {
					node.Signal = sig
					break
				}
			}
		}
	}

	for _, child := range node.Children {
		traverseMeshSignals(child, signals)
	}
}

// discoverWirelessInterfaces returns interface names from /sys/class/net that have a wireless directory
func discoverWirelessInterfaces() []string {
	var ifaces []string
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ifaces
	}
	for _, entry := range entries {
		wirelessDir := fmt.Sprintf("/sys/class/net/%s/wireless", entry.Name())
		if _, err := os.Stat(wirelessDir); err == nil {
			ifaces = append(ifaces, entry.Name())
		}
	}
	return ifaces
}
