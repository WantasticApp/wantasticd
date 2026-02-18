//go:build linux

package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/wifi"
)

// collectWiFiStatistics collects WiFi statistics using github.com/mdlayher/wifi
// and other Linux-specific sources for better embedded device support.
func collectWiFiStatistics() ([]WiFiInterfaceInfo, bool) {
	var wifiInterfaces []WiFiInterfaceInfo
	var connected bool

	// Create WiFi client
	client, err := wifi.New()
	if err != nil {
		log.Printf("WiFi client creation failed: %v", err)
		return wifiInterfaces, false
	}
	defer client.Close()

	// Get all WiFi interfaces
	interfaces, err := client.Interfaces()
	if err != nil {
		log.Printf("Failed to get WiFi interfaces: %v", err)
		return wifiInterfaces, false
	}

	// Get noise levels from /proc/net/wireless
	noiseLevels := parseProcNetWireless()

	for _, iface := range interfaces {
		wifiInfo := WiFiInterfaceInfo{
			Name:      iface.Name,
			MAC:       iface.HardwareAddr.String(),
			Connected: false,
		}

		if noise, ok := noiseLevels[iface.Name]; ok {
			wifiInfo.Noise = noise
		}

		// Try to get BSS info for associated network
		if bss, err := client.BSS(iface); err == nil && bss != nil {
			wifiInfo.SSID = bss.SSID
			wifiInfo.Connected = (bss.Status == wifi.BSSStatusAssociated)
			wifiInfo.Frequency = bss.Frequency
			wifiInfo.Channel = frequencyToChannel(bss.Frequency)
			if wifiInfo.Connected {
				connected = true
			}
		}

		// Fallback: If SSID is empty (likely AP mode or BSS failed), try 'iw' command
		if wifiInfo.SSID == "" {
			if info, err := getWiFiInfoFromIW(iface.Name); err == nil {
				wifiInfo.SSID = info.SSID
				wifiInfo.Frequency = info.Frequency
				wifiInfo.Channel = info.Channel
				wifiInfo.TxPower = info.TxPower
				wifiInfo.Connected = true // If we have an SSID in AP mode, we are "connected"/active
				connected = true
			}
		}

		// Get detailed station info
		stationInfos, err := client.StationInfo(iface)
		if err == nil {
			for _, station := range stationInfos {
				wifiInfo.Signal = station.Signal
				if wifiInfo.Noise != 0 {
					wifiInfo.SNR = wifiInfo.Signal - wifiInfo.Noise
				}
				wifiInfo.Bitrate = station.TransmitBitrate / 1000000
				wifiInfo.RxBytes = uint64(station.ReceivedBytes)
				wifiInfo.TxBytes = uint64(station.TransmittedBytes)
				wifiInfo.RxPackets = uint64(station.ReceivedPackets)
				wifiInfo.TxPackets = uint64(station.TransmittedPackets)
				// Break after first station record for the interface
				break
			}
		}

		// Collect nearby networks via 'iw scan dump'
		// This uses the kernel scan cache and doesn't trigger an active scan
		if nearby, err := collectNearbyNetworks(iface.Name); err == nil {
			wifiInfo.Nearby = nearby
		}

		wifiInterfaces = append(wifiInterfaces, wifiInfo)
	}

	return wifiInterfaces, connected
}

func frequencyToChannel(freq int) int {
	if freq >= 2412 && freq <= 2484 {
		if freq == 2484 {
			return 14
		}
		return (freq-2412)/5 + 1
	} else if freq >= 5180 && freq <= 5825 {
		return (freq-5180)/5 + 36
	} else if freq >= 5945 && freq <= 7125 {
		return (freq-5945)/5 + 1
	}
	return 0
}

func parseProcNetWireless() map[string]int {
	noises := make(map[string]int)
	data, err := os.ReadFile("/proc/net/wireless")
	if err != nil {
		return noises
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if !strings.Contains(line, ":") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		iface := strings.TrimSpace(strings.Split(fields[0], ":")[0])
		// noise is field 4 (0-indexed)
		if noise, err := strconv.Atoi(strings.TrimSuffix(fields[4], ".")); err == nil {
			noises[iface] = noise
		}
	}
	return noises
}

func collectNearbyNetworks(iface string) ([]NearbyNetwork, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try 'iw dev <iface> scan dump'
	out, err := exec.CommandContext(ctx, "iw", "dev", iface, "scan", "dump").Output()
	if err != nil {
		return nil, err
	}

	var networks []NearbyNetwork
	var current *NearbyNetwork

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BSS ") {
			if current != nil && current.SSID != "" {
				networks = append(networks, *current)
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				bssid := strings.Split(parts[1], "(")[0]
				current = &NearbyNetwork{BSSID: bssid}
			}
			continue
		}

		if current == nil {
			continue
		}

		if strings.HasPrefix(line, "SSID: ") {
			current.SSID = strings.TrimPrefix(line, "SSID: ")
		} else if strings.HasPrefix(line, "freq: ") {
			if freq, err := strconv.Atoi(strings.TrimPrefix(line, "freq: ")); err == nil {
				current.Channel = frequencyToChannel(freq)
			}
		} else if strings.HasPrefix(line, "signal: ") {
			// signal: -61.00 dBm
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val := strings.TrimSuffix(fields[1], ".00")
				if sig, err := strconv.Atoi(val); err == nil {
					current.Signal = sig
				}
			}
		}
	}

	if current != nil && current.SSID != "" {
		networks = append(networks, *current)
	}

	return networks, nil
}

// Simple struct to hold parsed iw info
type iwInfo struct {
	SSID      string
	Frequency int
	Channel   int
	TxPower   int
}

// getWiFiInfoFromIW parses 'iw dev <iface> info' to get SSID, freq, txpower
// Useful for AP mode where mdlayher/wifi BSS() might not return the hosted SSID.
func getWiFiInfoFromIW(iface string) (*iwInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Output format of 'iw dev <iface> info':
	// Interface wlan0
	// 	ifindex 4
	// 	wdev 0x1
	// 	addr 00:11:22:33:44:55
	// 	ssid MyNetwork
	// 	type AP
	// 	wiphy 0
	// 	channel 36 (5180 MHz), width: 20 MHz, center1: 5180 MHz
	// 	txpower 23.00 dBm
	out, err := exec.CommandContext(ctx, "iw", "dev", iface, "info").Output()
	if err != nil {
		return nil, err
	}

	info := &iwInfo{}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ssid ") {
			info.SSID = strings.TrimPrefix(line, "ssid ")
		} else if strings.HasPrefix(line, "channel ") {
			// channel 36 (5180 MHz), ...
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if ch, err := strconv.Atoi(fields[1]); err == nil {
					info.Channel = ch
				}
			}
			if strings.Contains(line, "(") && strings.Contains(line, "MHz)") {
				// Extract frequency
				start := strings.Index(line, "(") + 1
				end := strings.Index(line, " MHz)")
				if start > 0 && end > start {
					if freq, err := strconv.Atoi(line[start:end]); err == nil {
						info.Frequency = freq
					}
				}
			}
		} else if strings.HasPrefix(line, "txpower ") {
			// txpower 23.00 dBm
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val := strings.TrimSuffix(fields[1], ".00")
				if pwr, err := strconv.Atoi(val); err == nil {
					info.TxPower = pwr
				}
			}
		}
	}

	if info.SSID == "" {
		return nil, fmt.Errorf("no SSID found")
	}

	// If channel/freq missing but we have one, map the other
	if info.Channel != 0 && info.Frequency == 0 {
		// Approx mapping not implemented backwards here easily, but usually both present
	} else if info.Frequency != 0 && info.Channel == 0 {
		info.Channel = frequencyToChannel(info.Frequency)
	}

	return info, nil
}

// collectNetworkInterfaceStatistics collects network interface statistics from /sys/class/net
func collectNetworkInterfaceStatistics() ([]InterfaceInfo, uint64, uint64) {
	var interfaces []InterfaceInfo
	var totalTx, totalRx uint64

	// Read network interfaces from /sys/class/net
	netDir := "/sys/class/net"
	entries, err := os.ReadDir(netDir)
	if err != nil {
		log.Printf("Failed to read network interfaces: %v", err)
		return interfaces, 0, 0
	}

	for _, entry := range entries {
		ifaceName := entry.Name()

		// Get interface statistics from /sys/class/net
		rxBytes, _ := readUint64FromFile(filepath.Join(netDir, ifaceName, "statistics", "rx_bytes"))
		txBytes, _ := readUint64FromFile(filepath.Join(netDir, ifaceName, "statistics", "tx_bytes"))

		// Always add to totals
		totalRx += rxBytes
		totalTx += txBytes

		// Skip filtered interfaces for the detailed list
		if ifaceName == "lo" || strings.HasPrefix(ifaceName, "veth") ||
			strings.HasPrefix(ifaceName, "docker") || strings.HasPrefix(ifaceName, "br-") {
			continue
		}

		iface := InterfaceInfo{
			Name:    ifaceName,
			Up:      isInterfaceUp(ifaceName),
			RxBytes: rxBytes, // Use the value read above
			TxBytes: txBytes, // Use the value read above
		}

		// Get MAC address
		if mac, err := getInterfaceMAC(ifaceName); err == nil {
			iface.MAC = mac
		}

		// Get IP addresses
		if ips, err := getInterfaceIPs(ifaceName); err == nil {
			iface.IPs = ips
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces, totalTx, totalRx
}

// isInterfaceUp checks if a network interface is up
func isInterfaceUp(ifaceName string) bool {
	operstateFile := filepath.Join("/sys/class/net", ifaceName, "operstate")
	data, err := os.ReadFile(operstateFile)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "up"
}

// getInterfaceMAC gets the MAC address of a network interface
func getInterfaceMAC(ifaceName string) (string, error) {
	macFile := filepath.Join("/sys/class/net", ifaceName, "address")
	data, err := os.ReadFile(macFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// collectMeshStatistics detects and collects mesh network data
func collectMeshStatistics() *MeshInfo {
	// 1. Try EasyMesh (IEEE 1905.1) - usually primary if it exists
	if mesh := collectEasyMeshLowLevel(); mesh != nil {
		return mesh
	}

	// 1b. Try QSDK EasyMesh (via device.getRealTopo) - specific to Qualcomm SDK
	if mesh := collectQSDKMesh(); mesh != nil {
		return mesh
	}

	// 2. Try OpenMesh (BATMAN) via File System (more reliable on non-controller nodes)
	if mesh := collectBatmanFileSystem(); mesh != nil {
		return mesh
	}

	// 3. Try OpenMesh (BATMAN) via Netlink
	if mesh := collectOpenMeshNetlink(); mesh != nil {
		return mesh
	}

	// 4. Try 802.11s via File System
	if mesh := collect80211sMesh(); mesh != nil {
		return mesh
	}

	return nil
}

func collectEasyMeshLowLevel() *MeshInfo {
	// Protocol check: IEEE 1905.1 (EasyMesh) uses EtherType 0x893a
	// Low level check: see if the ether-type is handled by any socket/daemon
	// or look for the 1905.1 configuration files/daemons
	isEasyMesh := false

	// Check for common EasyMesh daemons/state
	paths := []string{
		"/usr/sbin/map-agent",
		"/usr/sbin/map-controller",
		"/etc/config/multiap",
		"/tmp/state/multiap",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			isEasyMesh = true
			break
		}
	}

	// Low-level check: Check bridge FDB for Multi-AP multicast MAC (01:80:c2:00:00:13)
	if !isEasyMesh {
		if checkBridgeFDBForMultiAP() {
			isEasyMesh = true
		}
	}

	if !isEasyMesh {
		return nil
	}

	// If we detected EasyMesh, use the primary IPC (ubus) to get the topology
	return collectEasyMesh()
}

func checkBridgeFDBForMultiAP() bool {
	// Multi-AP / IEEE 1905.1 multicast MAC
	const multiAPMAC = "01:80:c2:00:00:13"

	fdb, err := os.ReadFile("/proc/net/bridge/fdb")
	if err != nil {
		// Try alternative: /sys/class/net/br-*/brforward
		return false
	}

	return strings.Contains(string(fdb), multiAPMAC)
}

func collectOpenMeshNetlink() *MeshInfo {
	// Generic Netlink constants for batman-adv
	const (
		batadvFamilyName        = "batadv"
		batadvCmdGetOriginators = 1
		batadvAttrOriginator    = 1
		batadvAttrNeighbor      = 2
		batadvAttrTQ            = 3
		batadvAttrMeshIface     = 7 // dev index
	)

	// Dial Generic Netlink
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil
	}
	defer c.Close()

	// Resolve the batman-adv family
	f, err := c.GetFamily(batadvFamilyName)
	if err != nil {
		return nil
	}

	mesh := &MeshInfo{
		Protocol: "openmesh",
		Role:     "node",
		IsCenter: false,
	}

	// Check gateway mode via sysfs
	if data, err := os.ReadFile("/sys/class/net/bat0/mesh/gw_mode"); err == nil {
		mode := strings.TrimSpace(string(data))
		if mode == "server" {
			mesh.IsCenter = true
			mesh.Role = "gateway"
		}
	}

	// Get bat0 ifindex
	batIface, err := net.InterfaceByName("bat0")
	if err != nil {
		return nil
	}

	// Build request for originators
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(batadvAttrMeshIface, uint32(batIface.Index))
	b, err := ae.Encode()
	if err != nil {
		return nil
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: batadvCmdGetOriginators,
			Version: f.Version,
		},
		Data: b,
	}

	msgs, err := c.Execute(req, f.ID, netlink.Request|netlink.Dump)
	if err != nil {
		return nil
	}

	root := &MeshNode{Name: "Mesh Originators", Role: mesh.Role}
	for _, m := range msgs {
		ad, err := netlink.NewAttributeDecoder(m.Data)
		if err != nil {
			continue
		}

		var origMAC net.HardwareAddr
		var tq uint8

		for ad.Next() {
			switch ad.Type() {
			case batadvAttrOriginator:
				origMAC = ad.Bytes()
			case batadvAttrTQ:
				tq = ad.Uint8()
			}
		}

		if origMAC != nil {
			sig := -100 + (int(tq) * 70 / 255)
			root.Children = append(root.Children, &MeshNode{
				Name:   fmt.Sprintf("Originator %s", origMAC.String()),
				MAC:    origMAC.String(),
				Signal: sig,
				Role:   "peer",
			})
		}
	}

	if len(root.Children) > 0 {
		mesh.Topology = root
		return mesh
	}

	return nil
}

func collectEasyMesh() *MeshInfo {
	// Check if ubus is available
	if _, err := exec.LookPath("ubus"); err != nil {
		return nil
	}

	// Try common EasyMesh ubus objects
	objects := []string{"ieee1905.topology", "mesh", "multiap", "map"}
	var out []byte
	var err error
	var foundObj string

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, obj := range objects {
		out, err = exec.CommandContext(ctx, "ubus", "call", obj, "get").Output()
		if err == nil {
			foundObj = obj
			break
		}
		// Some implementations use 'show' or 'status' instead of 'get'
		out, err = exec.CommandContext(ctx, "ubus", "call", obj, "show").Output()
		if err == nil {
			foundObj = obj
			break
		}
	}

	if foundObj == "" {
		return nil
	}

	var data struct {
		IsController bool `json:"is_controller"`
		Controller   bool `json:"controller"` // Some versions use this
		Nodes        []struct {
			MAC      string `json:"mac"`
			Hops     int    `json:"hops"`
			Upstream string `json:"upstream"`
			Type     string `json:"type"`
		} `json:"nodes"`
	}

	if err := json.Unmarshal(out, &data); err != nil {
		return nil
	}

	isController := data.IsController || data.Controller
	mesh := &MeshInfo{
		Protocol: "easymesh",
		Role:     "agent",
		IsCenter: isController,
	}
	if isController {
		mesh.Role = "controller"
	}

	// Build a simple tree for the topology if we are the center
	if isController && len(data.Nodes) > 0 {
		root := &MeshNode{Name: "Controller", Role: "controller"}
		nodeMap := make(map[string]*MeshNode)

		for _, n := range data.Nodes {
			node := &MeshNode{
				MAC:  n.MAC,
				Role: n.Type,
			}
			nodeMap[n.MAC] = node
		}

		for _, n := range data.Nodes {
			if n.Upstream == "" || n.Upstream == "00:00:00:00:00:00" {
				root.Children = append(root.Children, nodeMap[n.MAC])
			} else if parent, ok := nodeMap[strings.ToLower(n.Upstream)]; ok {
				parent.Children = append(parent.Children, nodeMap[n.MAC])
			}
		}
		mesh.Topology = root
	}

	// Fallback/Augment: Check local UCI config if on OpenWrt
	if mesh.Role == "agent" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "uci", "-q", "get", "multiap.agent.controller_mac").Output(); err == nil {
			mesh.Name = "EasyMesh Node (via UCI)"
			if mesh.Topology == nil {
				mesh.Topology = &MeshNode{
					Name: "Upstream Controller",
					MAC:  strings.TrimSpace(string(out)),
					Role: "controller",
				}
			}
		}
	}

	return mesh
}

func collectQSDKMesh() *MeshInfo {
	// Check if ubus is available
	if _, err := exec.LookPath("ubus"); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// QSDK specific command: ubus call device getRealTopo
	out, err := exec.CommandContext(ctx, "ubus", "call", "device", "getRealTopo").Output()
	if err != nil {
		return nil
	}

	// Structure based on user provided JSON
	var data struct {
		Topo []struct {
			MAC      string `json:"mac"`
			PMAC     string `json:"pMac"` // Parent MAC
			Hops     int    `json:"hops"`
			IP       string `json:"ip"`
			Backhaul string `json:"backhaul"`
			Name     string `json:"name"`
		} `json:"topo"`
	}

	if err := json.Unmarshal(out, &data); err != nil {
		return nil
	}

	if len(data.Topo) == 0 {
		return nil
	}

	mesh := &MeshInfo{
		Protocol: "easymesh-qsdk",
		Role:     "controller", // Assumption: if we can see the full topo, we are likely the controller
		IsCenter: true,
	}

	// Build the tree
	// 1. Create all nodes and put them in a map
	nodeMap := make(map[string]*MeshNode)
	var root *MeshNode

	for _, n := range data.Topo {
		node := &MeshNode{
			Name: n.Name,
			MAC:  n.MAC,
			IP:   n.IP,
			Role: "agent", // Default role
		}
		if n.Hops == 0 {
			node.Role = "controller" // 0 hops usually means self/controller
			root = node
		}
		nodeMap[n.MAC] = node
	}

	// 2. Link children to parents
	for _, n := range data.Topo {
		if n.PMAC == "" {
			continue // Root or detached
		}

		child := nodeMap[n.MAC]
		parent, ok := nodeMap[n.PMAC]
		if ok {
			parent.Children = append(parent.Children, child)
		}
	}

	// If we found a root (hop 0), use it. Otherwise, create a synthetic root if possible?
	// The provided JSON shows hop 0 for the device itself.
	if root != nil {
		mesh.Topology = root
	} else if len(nodeMap) > 0 {
		// Fallback: if no hop 0 found, just attach everything to a dummy root?
		// Or maybe pick one with lowest hops?
		// For now, if no root is identified, return nil or maybe just the list attached to a dummy?
		// Let's return the first one found as root or nil?
		// Actually, if we have data but no clear root, we might want to show something.
		// But usually one node has hops=0.
		// Let's check if we have any nodes at all.
		// If no hops=0 node, maybe we are an agent seeing the topology?
		// But getRealTopo usually runs on the controller.
		// Let's leave Topology nil if no root found, but still return mesh info?
		// If Topology is nil, UI might not show graph.
		// Let's try to find a node with empty pMac as root if hops=0 didn't catch it.
		for _, n := range data.Topo {
			if n.PMAC == "" {
				root = nodeMap[n.MAC]
				break
			}
		}
		mesh.Topology = root
	}

	return mesh
}

func collectBatmanFileSystem() *MeshInfo {
	batDir := "/sys/class/net/bat0/mesh"
	if _, err := os.Stat(batDir); err != nil {
		return nil
	}

	mesh := &MeshInfo{
		Protocol: "batman-adv",
		Role:     "node",
	}

	// Get role/gw_mode
	if data, err := os.ReadFile(filepath.Join(batDir, "gw_mode")); err == nil {
		mode := strings.TrimSpace(string(data))
		mesh.Role = mode
		if mode == "server" {
			mesh.IsCenter = true
		}
	}

	// Get topology from debugfs
	// Default debugfs path for batman-adv originators
	debugPath := "/sys/kernel/debug/batman_adv/bat0/originators"
	data, err := os.ReadFile(debugPath)
	if err != nil {
		// Try alternative path (sometimes nested differently) via glob
		matches, globErr := filepath.Glob("/sys/kernel/debug/batman_adv/*/originators")
		if globErr == nil && len(matches) > 0 {
			data, err = os.ReadFile(matches[0])
		}

		if err != nil {
			return mesh
		}
	}

	root := &MeshNode{Name: "BATMAN Topology", Role: mesh.Role}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		// Expected format: Originator      last-seen (# sec) TQ [expected-iface]:  Next Hop [IF]
		// Example: 00:11:22:33:44:55   0.450s   (234) [  eth0]: 00:11:22:33:44:55 ( 234)
		if len(fields) < 5 || !strings.Contains(fields[0], ":") {
			continue
		}

		mac := fields[0]
		signal := calculateSignalFromBatman(fields)
		root.Children = append(root.Children, &MeshNode{
			Name:   fmt.Sprintf("Node %s", mac),
			MAC:    mac,
			Signal: signal,
			Role:   "peer",
		})
	}

	if len(root.Children) > 0 {
		mesh.Topology = root
	}

	return mesh
}

func collect80211sMesh() *MeshInfo {
	// Detect 11s mesh interfaces by looking for 'mesh' config in sysfs
	// /sys/class/net/*/mesh directory exists for 11s interfaces
	netDir := "/sys/class/net"
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return nil
	}

	var meshIface string
	for _, entry := range entries {
		meshPath := filepath.Join(netDir, entry.Name(), "mesh")
		if info, err := os.Stat(meshPath); err == nil && info.IsDir() {
			meshIface = entry.Name()
			break
		}
	}

	if meshIface == "" {
		return nil
	}

	mesh := &MeshInfo{
		Protocol: "802.11s",
		Role:     "node",
	}

	// Read Mesh ID
	if data, err := os.ReadFile(filepath.Join(netDir, meshIface, "mesh/id")); err == nil {
		mesh.Name = fmt.Sprintf("Mesh: %s", strings.TrimSpace(string(data)))
	}

	// Try to get neighbors from /proc/net/ieee80211s/ (some kernels)
	// or /sys/kernel/debug/cfg80211/phy*/... (hard to find dynamically)
	// For now, we mainly report the mesh presence and ID if neighbors file isn't found

	return mesh
}

func calculateSignalFromBatman(fields []string) int {
	// Example BATMAN output: eth0   00:11:22:33:44:55   ( 234) [  1.0]
	// TQ (Transmission Quality) is usually in the parentheses
	for _, f := range fields {
		if strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")") {
			tqStr := strings.Trim(f, "()")
			if tq, err := strconv.Atoi(tqStr); err == nil {
				// Convert TQ (0-255) to a pseudo-signal strength (-100 to -30)
				return -100 + (tq * 70 / 255)
			}
		}
	}
	return 0
}

// getHostUptime returns the host device uptime in seconds
func getHostUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(data))
	if len(parts) > 0 {
		if uptime, err := strconv.ParseFloat(parts[0], 64); err == nil {
			return uptime
		}
	}
	return 0
}

// readUint64FromFile reads a uint64 value from a file
func readUint64FromFile(filePath string) (uint64, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, err
	}

	str := strings.TrimSpace(string(data))
	return strconv.ParseUint(str, 10, 64)
}
func collectCPUUsage() string {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "0%"
	}
	fields := strings.Fields(string(data))
	if len(fields) > 0 {
		return fields[0] + " (avg1)"
	}
	return "0%"
}

func collectSystemMemory() (uint64, uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}

	var total, available, free, buffers, cached uint64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		val, _ := strconv.ParseUint(fields[1], 10, 64)
		val *= 1024 // kB to Bytes

		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = val
		case strings.HasPrefix(line, "MemAvailable:"):
			available = val
		case strings.HasPrefix(line, "MemFree:"):
			free = val
		case strings.HasPrefix(line, "Buffers:"):
			buffers = val
		case strings.HasPrefix(line, "Cached:"):
			cached = val
		}
	}

	// MemAvailable is the most accurate metric for "available" memory on modern Linux
	// If MemAvailable is present (kernel >= 3.14), Used = Total - Available
	if available > 0 {
		return total - available, total
	}

	// Fallback for older kernels
	return total - (free + buffers + cached), total
}
