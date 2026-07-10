package platforms

import (
	"fmt"
	"net"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// meshNode is a simplified mesh topology node shared by platform collectors.
type meshNode struct {
	id       string
	name     string
	mac      string
	ip       string
	signal   int
	role     string
	children []*meshNode
}

type meshSnapshot struct {
	protocol       string
	role           string
	implementation string
	topology       *meshNode
	sampleTime     time.Time
}

// flattenMeshTopology writes mesh nodes as TR-181 DataElements devices.
func flattenMeshTopology(msg *wusp.Message, node *meshNode, index int) int {
	if node == nil {
		return index
	}
	index++
	prefix := fmt.Sprintf("Device.WiFi.DataElements.Network.Device.%d.", index)

	if mac, ok := parseMeshMAC(node.mac); ok {
		msg.Set(prefix+"ID", wusp.MAC(mac))
	}
	if node.name != "" {
		msg.Set(prefix+"X_WANTASTIC_Hostname", wusp.String(node.name))
	}
	if node.ip != "" {
		msg.Set(prefix+"X_WANTASTIC_IPAddress", wusp.String(node.ip))
	}
	if node.signal != 0 {
		msg.Set(prefix+"X_WANTASTIC_Signal", wusp.Int(int64(node.signal)))
	}
	if node.role != "" {
		msg.Set(prefix+"X_WANTASTIC_Role", wusp.String(node.role))
	}

	for _, child := range node.children {
		index = flattenMeshTopology(msg, child, index)
	}
	return index
}

func appendMeshSnapshot(msg *wusp.Message, snapshot meshSnapshot) {
	if msg == nil {
		return
	}
	protocol := normalizeMeshProtocol(snapshot.protocol)
	if protocol == "" && snapshot.topology == nil {
		return
	}
	if protocol == "" {
		protocol = "Unknown"
	}
	implementation := normalizeMeshImplementation(snapshot.implementation, protocol)
	if snapshot.sampleTime.IsZero() {
		snapshot.sampleTime = time.Now().UTC()
	}

	msg.Set("Device.WUSP_MeshTelemetry.Enable", wusp.Bool(true))
	msg.Set("Device.WUSP_MeshTelemetry.Status", wusp.String("Collecting"))
	msg.Set("Device.WUSP_MeshTelemetry.LastSampleTime", wusp.Time(snapshot.sampleTime.UTC()))
	msg.Set("Device.WUSP_MeshTelemetry.ProtocolNumberOfEntries", wusp.Uint(1))
	msg.Set("Device.WUSP_MeshTelemetry.Protocol.1.Alias", wusp.String("protocol-1"))
	msg.Set("Device.WUSP_MeshTelemetry.Protocol.1.Name", wusp.String(protocol))
	msg.Set("Device.WUSP_MeshTelemetry.Protocol.1.Implementation", wusp.String(implementation))
	msg.Set("Device.WUSP_MeshTelemetry.Protocol.1.Status", wusp.String("Running"))
	msg.Set("Device.WUSP_MeshTelemetry.Protocol.1.Writable", wusp.Bool(false))
	if protocol == "EasyMesh" || protocol == "MultiAP" {
		msg.Set("Device.WUSP_MeshTelemetry.Protocol.1.StandardMultiAPReference", wusp.String("Device.WiFi.MultiAP."))
	}

	nodes := flattenMeshNodes(snapshot.topology)
	msg.Set("Device.WUSP_MeshTelemetry.NodeNumberOfEntries", wusp.Uint(uint64(len(nodes))))
	msg.Set("Device.WUSP_MeshTelemetry.LinkNumberOfEntries", wusp.Uint(uint64(countMeshLinks(snapshot.topology))))
	if len(nodes) == 0 {
		return
	}

	nodeIndex := make(map[*meshNode]int, len(nodes))
	apDeviceCount := 0
	for i, node := range nodes {
		index := i + 1
		nodeIndex[node] = index
		prefix := fmt.Sprintf("Device.WUSP_MeshTelemetry.Node.%d.", index)
		msg.Set(prefix+"Alias", wusp.String(fmt.Sprintf("node-%d", index)))
		msg.Set(prefix+"NodeID", wusp.String(meshNodeID(node, index)))
		msg.Set(prefix+"Role", wusp.String(normalizeMeshRole(firstNonEmpty(node.role, snapshot.role))))
		msg.Set(prefix+"Status", wusp.String("Online"))
		msg.Set(prefix+"NeighborCount", wusp.Uint(uint64(len(node.children))))
		if node.name != "" {
			msg.Set(prefix+"Hostname", wusp.String(node.name))
		}
		if node.ip != "" {
			msg.Set(prefix+"Address", wusp.String(node.ip))
		}
		msg.Set(prefix+"LastSeen", wusp.Time(snapshot.sampleTime.UTC()))

		dataElementsPrefix := fmt.Sprintf("Device.WiFi.DataElements.Network.Device.%d.", index)
		if mac, ok := parseMeshMAC(node.mac); ok {
			msg.Set(dataElementsPrefix+"ID", wusp.MAC(mac))
			apDeviceCount++
			apPrefix := fmt.Sprintf("Device.WiFi.MultiAP.APDevice.%d.", apDeviceCount)
			msg.Set(apPrefix+"MACAddress", wusp.MAC(mac))
			msg.Set(apPrefix+"LastContactTime", wusp.Time(snapshot.sampleTime.UTC()))
			if protocol == "EasyMesh" || protocol == "MultiAP" || protocol == "OpenMesh" {
				msg.Set(apPrefix+"AssocIEEE1905DeviceRef", wusp.String(dataElementsPrefix))
			}
			if index == 1 || normalizeMeshRole(firstNonEmpty(node.role, snapshot.role)) == "Controller" {
				msg.Set(apPrefix+"BackhaulLinkType", wusp.String("None"))
			} else {
				msg.Set(apPrefix+"BackhaulLinkType", wusp.String("Wi-Fi"))
			}
			msg.Set(apPrefix+"BackhaulMACAddress", wusp.MAC(mac))
			if node.signal != 0 {
				msg.Set(apPrefix+"BackhaulSignalStrength", wusp.Uint(uint64(signalDBMToRCPI(node.signal))))
			}
		}
	}
	msg.Set("Device.WiFi.DataElements.Network.DeviceNumberOfEntries", wusp.Uint(uint64(len(nodes))))
	msg.Set("Device.WiFi.MultiAP.APDeviceNumberOfEntries", wusp.Uint(uint64(apDeviceCount)))

	linkIndex := 0
	appendMeshLinks(msg, snapshot.topology, nodeIndex, &linkIndex)
}

func flattenMeshNodes(root *meshNode) []*meshNode {
	if root == nil {
		return nil
	}
	nodes := []*meshNode{root}
	for _, child := range root.children {
		nodes = append(nodes, flattenMeshNodes(child)...)
	}
	return nodes
}

func countMeshLinks(node *meshNode) int {
	if node == nil {
		return 0
	}
	count := len(node.children)
	for _, child := range node.children {
		count += countMeshLinks(child)
	}
	return count
}

func appendMeshLinks(msg *wusp.Message, node *meshNode, nodeIndex map[*meshNode]int, linkIndex *int) {
	if node == nil {
		return
	}
	source := nodeIndex[node]
	for _, child := range node.children {
		target := nodeIndex[child]
		if source > 0 && target > 0 {
			*linkIndex = *linkIndex + 1
			prefix := fmt.Sprintf("Device.WUSP_MeshTelemetry.Link.%d.", *linkIndex)
			msg.Set(prefix+"Alias", wusp.String(fmt.Sprintf("link-%d", *linkIndex)))
			msg.Set(prefix+"SourceNode", wusp.String(fmt.Sprintf("Device.WUSP_MeshTelemetry.Node.%d.", source)))
			msg.Set(prefix+"TargetNode", wusp.String(fmt.Sprintf("Device.WUSP_MeshTelemetry.Node.%d.", target)))
			msg.Set(prefix+"Status", wusp.String("Up"))
			if child.signal != 0 {
				quality := signalDBMToQuality(child.signal)
				msg.Set(prefix+"SignalQuality", wusp.Uint(uint64(quality)))
				msg.Set(prefix+"Metric", wusp.Uint(uint64(100-quality)))
			}
		}
		appendMeshLinks(msg, child, nodeIndex, linkIndex)
	}
}

func normalizeMeshProtocol(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch {
	case normalized == "":
		return ""
	case strings.Contains(normalized, "easy"):
		return "EasyMesh"
	case strings.Contains(normalized, "multiap") || strings.Contains(normalized, "multi-ap"):
		return "MultiAP"
	case strings.Contains(normalized, "openmesh") || strings.Contains(normalized, "open mesh"):
		return "OpenMesh"
	case strings.Contains(normalized, "802.11s") || strings.Contains(normalized, "ieee80211s") || strings.Contains(normalized, "11s"):
		return "IEEE80211s"
	case strings.Contains(normalized, "batman"):
		return "BATMANAdv"
	case strings.Contains(normalized, "olsr"):
		return "OLSR"
	case strings.Contains(normalized, "babel"):
		return "Babel"
	default:
		return "Unknown"
	}
}

func normalizeMeshImplementation(value, protocol string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(normalized, "openwrt"):
		return "OpenWrt"
	case strings.Contains(normalized, "hostapd"):
		return "hostapd"
	case strings.Contains(normalized, "wpa"):
		return "wpa_supplicant"
	case strings.Contains(normalized, "mesh11sd"):
		return "mesh11sd"
	case strings.Contains(normalized, "batman"):
		return "batman-adv"
	case strings.Contains(normalized, "olsr"):
		return "olsrd"
	case strings.Contains(normalized, "babel"):
		return "babeld"
	case strings.Contains(strings.ToLower(protocol), "batman"):
		return "batman-adv"
	case normalized != "":
		return "Vendor"
	default:
		return "Unknown"
	}
}

func normalizeMeshRole(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch {
	case normalized == "":
		return "Unknown"
	case strings.Contains(normalized, "controller") || strings.Contains(normalized, "center") || strings.Contains(normalized, "gateway") || normalized == "root":
		return "Controller"
	case strings.Contains(normalized, "client") || strings.Contains(normalized, "sta"):
		return "Client"
	case strings.Contains(normalized, "edge"):
		return "Edge"
	default:
		return "Relay"
	}
}

func meshNodeID(node *meshNode, index int) string {
	if node == nil {
		return fmt.Sprintf("node-%d", index)
	}
	for _, candidate := range []string{node.id, node.mac, node.name, node.ip} {
		if candidate = strings.TrimSpace(candidate); candidate != "" {
			return candidate
		}
	}
	return fmt.Sprintf("node-%d", index)
}

func parseMeshMAC(value string) (net.HardwareAddr, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, false
	}
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 || isZeroMAC(mac) {
		return nil, false
	}
	return mac, true
}

func signalDBMToQuality(signal int) int {
	switch {
	case signal >= -50:
		return 100
	case signal <= -100:
		return 0
	default:
		return (signal + 100) * 2
	}
}

func signalDBMToRCPI(signal int) int {
	rcpi := (signal + 110) * 2
	if rcpi < 0 {
		return 0
	}
	if rcpi > 255 {
		return 255
	}
	return rcpi
}
