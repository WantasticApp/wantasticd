//go:build linux

package stats

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/wifi"
	"github.com/prometheus/procfs"
	"github.com/prometheus/procfs/sysfs"
)

// collectWiFiStatistics collects WiFi statistics using mdlayher/wifi v0.7.2
// Pure Go via nl80211 netlink — no exec.Command fallbacks.
func collectWiFiStatistics() ([]WiFiInterfaceInfo, bool) {
	var wifiInterfaces []WiFiInterfaceInfo
	var connected bool

	client, err := wifi.New()
	if err != nil {
		log.Printf("WiFi client creation failed: %v", err)
		return wifiInterfaces, false
	}
	defer client.Close()

	interfaces, err := client.Interfaces()
	if err != nil {
		log.Printf("Failed to get WiFi interfaces: %v", err)
		return wifiInterfaces, false
	}

	// Collect noise data from SurveyInfo (replaces /proc/net/wireless parsing)
	// Map frequency → noise for noise lookup by interface frequency
	noiseByFreq := make(map[int]int)
	for _, iface := range interfaces {
		surveys, err := client.SurveyInfo(iface)
		if err == nil {
			for _, s := range surveys {
				if s.Noise != 0 {
					noiseByFreq[s.Frequency] = s.Noise
				}
			}
		}
	}

	for _, iface := range interfaces {
		wifiInfo := WiFiInterfaceInfo{
			Name:      iface.Name,
			MAC:       iface.HardwareAddr.String(),
			Connected: false,
			Frequency: iface.Frequency,
			Channel:   frequencyToChannel(iface.Frequency),
		}

		// Get noise for this interface's frequency
		if noise, ok := noiseByFreq[iface.Frequency]; ok {
			wifiInfo.Noise = noise
		}

		// BSS info — works for station mode
		if bss, err := client.BSS(iface); err == nil && bss != nil {
			wifiInfo.SSID = bss.SSID
			wifiInfo.Connected = (bss.Status == wifi.BSSStatusAssociated)
			wifiInfo.Frequency = int(bss.Frequency)
			wifiInfo.Channel = frequencyToChannel(int(bss.Frequency))
			if wifiInfo.Connected {
				connected = true
			}
		}

		// For AP mode — Interface.Type tells us the operating mode
		if iface.Type == wifi.InterfaceTypeAP && wifiInfo.SSID == "" {
			// In AP mode, the SSID isn't in BSS — read from sysfs or nl80211 interface info
			if ssid, err := readSSIDFromSysfs(iface.Name); err == nil && ssid != "" {
				wifiInfo.SSID = ssid
				wifiInfo.Connected = true
				connected = true
			}
		}

		// Station info — signal, bitrate, rx/tx stats
		stationInfos, err := client.StationInfo(iface)
		if err == nil {
			for _, station := range stationInfos {
				wifiInfo.Signal = station.Signal
				if wifiInfo.Noise != 0 {
					wifiInfo.SNR = wifiInfo.Signal - wifiInfo.Noise
				}
				// Bitrate is in bits/sec, convert to Mbps
				wifiInfo.Bitrate = station.TransmitBitrate / 1000000
				wifiInfo.RxBytes = uint64(station.ReceivedBytes)
				wifiInfo.TxBytes = uint64(station.TransmittedBytes)
				wifiInfo.RxPackets = uint64(station.ReceivedPackets)
				wifiInfo.TxPackets = uint64(station.TransmittedPackets)
				break // First station usage as representative
			}
		}

		// Nearby networks via AccessPoints (replaces `iw scan dump`)
		if nearby, err := collectNearbyNetworks(client, iface); err == nil {
			wifiInfo.Nearby = nearby
		}

		wifiInterfaces = append(wifiInterfaces, wifiInfo)
	}

	return wifiInterfaces, connected
}

// readSSIDFromSysfs reads the SSID for AP-mode interfaces from nl80211 via sysfs
func readSSIDFromSysfs(ifaceName string) (string, error) {
	paths := []string{
		fmt.Sprintf("/sys/class/net/%s/ssid", ifaceName),
		fmt.Sprintf("/tmp/hostapd_%s.conf", ifaceName),
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			content := strings.TrimSpace(string(data))
			if strings.Contains(p, "hostapd") {
				for _, line := range strings.Split(content, "\n") {
					if strings.HasPrefix(line, "ssid=") {
						return strings.TrimPrefix(line, "ssid="), nil
					}
				}
			} else {
				return content, nil
			}
		}
	}
	return "", fmt.Errorf("SSID not found")
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

// collectNearbyNetworks uses Client.AccessPoints to get cached scan results
func collectNearbyNetworks(client *wifi.Client, iface *wifi.Interface) ([]NearbyNetwork, error) {
	bssList, err := client.AccessPoints(iface)
	if err != nil {
		return nil, err
	}

	var networks []NearbyNetwork
	for _, bss := range bssList {
		if bss.SSID == "" {
			continue
		}
		network := NearbyNetwork{
			SSID:    bss.SSID,
			BSSID:   bss.BSSID.String(),
			Signal:  int(bss.Signal / 100), // mBm to dBm
			Channel: frequencyToChannel(int(bss.Frequency)),
		}
		// Security info from RSN IE
		if bss.RSN.IsInitialized() {
			network.Security = bss.RSN.String()
		}
		networks = append(networks, network)
	}

	return networks, nil
}

// collectNetworkInterfaceStatistics collects network interface statistics using prometheus/procfs
func collectNetworkInterfaceStatistics() ([]InterfaceInfo, uint64, uint64) {
	var interfaces []InterfaceInfo
	var totalTx, totalRx uint64

	fs, err := procfs.NewFS("/proc")
	if err != nil {
		log.Printf("Failed to open procfs: %v", err)
		return interfaces, 0, 0
	}

	netDev, err := fs.NetDev()
	if err != nil {
		log.Printf("Failed to get NetDev stats: %v", err)
		return interfaces, 0, 0
	}

	// Use sysfs for interface attributes (address, operstate)
	sfs, err := sysfs.NewFS("/sys")
	var netClass sysfs.NetClass
	if err == nil {
		netClass, _ = sfs.NetClass()
	}

	for ifaceName, stats := range netDev {
		// always add to totals
		totalRx += stats.RxBytes
		totalTx += stats.TxBytes

		// Skip filtered interfaces for the detailed list
		if ifaceName == "lo" || strings.HasPrefix(ifaceName, "veth") ||
			strings.HasPrefix(ifaceName, "docker") || strings.HasPrefix(ifaceName, "br-") {
			continue
		}

		iface := InterfaceInfo{
			Name:    ifaceName,
			RxBytes: stats.RxBytes,
			TxBytes: stats.TxBytes,
		}

		// Augment with sysfs data if available
		if netClass != nil {
			if nc, ok := netClass[ifaceName]; ok {
				iface.MAC = nc.Address
				if nc.OperState == "up" {
					iface.Up = true
				}
			}
		} else {
			// Fallback if sysfs failed
			iface.Up = isInterfaceUp(ifaceName)
			if mac, err := getInterfaceMAC(ifaceName); err == nil {
				iface.MAC = mac
			}
		}

		if ips, err := getInterfaceIPs(ifaceName); err == nil {
			iface.IPs = ips
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces, totalTx, totalRx
}

func isInterfaceUp(ifaceName string) bool {
	operstateFile := filepath.Join("/sys/class/net", ifaceName, "operstate")
	data, err := os.ReadFile(operstateFile)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "up"
}

func getInterfaceMAC(ifaceName string) (string, error) {
	macFile := filepath.Join("/sys/class/net", ifaceName, "address")
	data, err := os.ReadFile(macFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// collectMeshStatistics detects and collects mesh network data
// (Same pure Go logic as before via ubus.go and netlink)
func collectMeshStatistics() *MeshInfo {
	// 1. Try EasyMesh (IEEE 1905.1)
	if mesh := collectEasyMeshLowLevel(); mesh != nil {
		return mesh
	}

	// 1b. Try QSDK EasyMesh
	if mesh := collectQSDKMesh(); mesh != nil {
		return mesh
	}

	// 2. Try OpenMesh (BATMAN) via File System
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

// collectEasyMeshLowLevel, checkBridgeFDBForMultiAP, collectOpenMeshNetlink,
// collectEasyMesh, readUCIValue, collectQSDKMesh, collectBatmanFileSystem,
// collect80211sMesh, calculateSignalFromBatman functions remain unchanged
// as they are already pure Go implementations.

func collectEasyMeshLowLevel() *MeshInfo {
	isEasyMesh := false
	paths := []string{
		"/usr/sbin/map-agent",
		"/usr/sbin/map-controller",
		"/etc/config/multiap",
		"/tmp/state/multiap",
		"/var/run/ezmesh-agent-cmd.fifo", // QSDK ezmesh
		"/var/run/wsplcd.lock",           // QSDK wsplcd (Son/Hy-Fi)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			isEasyMesh = true
			break
		}
	}
	if !isEasyMesh {
		if checkBridgeFDBForMultiAP() {
			isEasyMesh = true
		}
	}
	if !isEasyMesh {
		return nil
	}
	return collectEasyMesh()
}

func checkBridgeFDBForMultiAP() bool {
	const multiAPMAC = "01:80:c2:00:00:13"
	fdb, err := os.ReadFile("/proc/net/bridge/fdb")
	if err != nil {
		return false
	}
	return strings.Contains(string(fdb), multiAPMAC)
}

func collectOpenMeshNetlink() *MeshInfo {
	const (
		batadvFamilyName        = "batadv"
		batadvCmdGetOriginators = 1
		batadvAttrOriginator    = 1
		batadvAttrTQ            = 3
		batadvAttrMeshIface     = 7
	)

	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil
	}
	defer c.Close()

	f, err := c.GetFamily(batadvFamilyName)
	if err != nil {
		return nil
	}

	mesh := &MeshInfo{
		Protocol: "openmesh",
		Role:     "node",
		IsCenter: false,
	}

	if data, err := os.ReadFile("/sys/class/net/bat0/mesh/gw_mode"); err == nil {
		mode := strings.TrimSpace(string(data))
		if mode == "server" {
			mesh.IsCenter = true
			mesh.Role = "gateway"
		}
	}

	batIface, err := net.InterfaceByName("bat0")
	if err != nil {
		return nil
	}

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
	if !ubusAvailable() {
		return nil
	}

	objects := []string{"ieee1905.topology", "mesh", "multiap", "map"}
	var out []byte
	var err error
	var foundObj string

	for _, obj := range objects {
		out, err = ubusCall(obj, "get", 5*time.Second)
		if err == nil {
			foundObj = obj
			break
		}
		out, err = ubusCall(obj, "show", 5*time.Second)
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
		Controller   bool `json:"controller"`
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

	if mesh.Role == "agent" {
		if controllerMAC, err := readUCIValue("multiap", "agent", "controller_mac"); err == nil {
			mesh.Name = "EasyMesh Node"
			if mesh.Topology == nil {
				mesh.Topology = &MeshNode{
					Name: "Upstream Controller",
					MAC:  controllerMAC,
					Role: "controller",
				}
			}
		}
	}

	return mesh
}

func readUCIValue(config, section, option string) (string, error) {
	configPath := fmt.Sprintf("/etc/config/%s", config)
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(data), "\n")
	inSection := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "config ") && strings.Contains(line, section) {
			inSection = true
			continue
		}
		if inSection && strings.HasPrefix(line, "config ") {
			inSection = false
		}
		if inSection && strings.HasPrefix(line, "option "+option) {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				val := strings.Join(parts[2:], " ")
				val = strings.Trim(val, "'\"")
				return val, nil
			}
		}
	}
	return "", fmt.Errorf("UCI value not found")
}

func collectQSDKMesh() *MeshInfo {
	if !ubusAvailable() {
		return nil
	}

	out, err := ubusCall("device", "getRealTopo", 5*time.Second)
	if err != nil {
		return nil
	}

	var data struct {
		Topo []struct {
			MAC      string `json:"mac"`
			PMAC     string `json:"pMac"`
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
		Role:     "controller",
		IsCenter: true,
	}

	nodeMap := make(map[string]*MeshNode)
	var root *MeshNode

	for _, n := range data.Topo {
		node := &MeshNode{
			Name: n.Name,
			MAC:  n.MAC,
			IP:   n.IP,
			Role: "agent",
		}
		if n.Hops == 0 {
			node.Role = "controller"
			root = node
		}
		nodeMap[n.MAC] = node
	}

	for _, n := range data.Topo {
		if n.PMAC == "" {
			continue
		}
		child := nodeMap[n.MAC]
		parent, ok := nodeMap[n.PMAC]
		if ok {
			parent.Children = append(parent.Children, child)
		}
	}

	if root != nil {
		mesh.Topology = root
	} else if len(nodeMap) > 0 {
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

	if data, err := os.ReadFile(filepath.Join(batDir, "gw_mode")); err == nil {
		mode := strings.TrimSpace(string(data))
		mesh.Role = mode
		if mode == "server" {
			mesh.IsCenter = true
		}
	}

	debugPath := "/sys/kernel/debug/batman_adv/bat0/originators"
	data, err := os.ReadFile(debugPath)
	if err != nil {
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

	if data, err := os.ReadFile(filepath.Join(netDir, meshIface, "mesh/id")); err == nil {
		mesh.Name = fmt.Sprintf("Mesh: %s", strings.TrimSpace(string(data)))
	}

	return mesh
}

func calculateSignalFromBatman(fields []string) int {
	for _, f := range fields {
		if strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")") {
			tqStr := strings.Trim(f, "()")
			if tq, err := strconv.Atoi(tqStr); err == nil {
				return -100 + (tq * 70 / 255)
			}
		}
	}
	return 0
}

// getHostUptime returns the host device uptime in seconds
func getHostUptime() float64 {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return 0
	}
	stat, err := fs.Stat()
	if err != nil {
		return 0
	}
	// procfs.Stat has BootTime (seconds since epoch).
	// Uptime = Now - BootTime.
	return float64(time.Now().Unix() - int64(stat.BootTime))
}

// collectCPUUsage returns load info using procfs
func collectCPUUsage() string {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return "0%"
	}

	load, err := fs.LoadAvg()
	if err != nil {
		return "0%"
	}

	return fmt.Sprintf("%.2f (avg1)", load.Load1)
}

// collectSystemMemory returns memory info using procfs
func collectSystemMemory() (uint64, uint64) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return 0, 0
	}

	mem, err := fs.Meminfo()
	if err != nil {
		return 0, 0
	}

	// MemTotal and MemAvailable are in kB in /proc/meminfo.
	// procfs exposes them as pointers to uint64.
	if mem.MemTotal == nil {
		return 0, 0
	}
	total := *mem.MemTotal * 1024

	var available uint64
	if mem.MemAvailable != nil {
		available = *mem.MemAvailable * 1024
	} else if mem.MemFree != nil && mem.Buffers != nil && mem.Cached != nil {
		// Fallback for older kernels
		available = (*mem.MemFree + *mem.Buffers + *mem.Cached) * 1024
	}

	return total - available, total
}
