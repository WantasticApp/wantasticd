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
	id        string
	name      string
	mac       string
	ip        string
	signal    int
	role      string
	parentID  string
	parentMAC string
	children  []*meshNode
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

	// Keep independent roots independent. Choosing one node heuristically and
	// attaching every other root to it fabricates parent MACs and hop counts,
	// producing a convincing but incorrect star topology. Explicit children,
	// parent hints and collector link evidence are still assembled by
	// attachMeshParentHints.
	roots := attachMeshParentHints(normalizedMeshRoots(snapshot.topology))
	nodes := flattenMeshForest(roots)
	msg.Set("Device.WUSP_MeshTelemetry.NodeNumberOfEntries", wusp.Uint(uint64(len(nodes))))
	msg.Set("Device.WUSP_MeshTelemetry.LinkNumberOfEntries", wusp.Uint(uint64(countMeshLinksForRoots(roots))))
	if len(nodes) == 0 {
		return
	}

	nodeIndex := make(map[*meshNode]int, len(nodes))
	parentByNode := make(map[*meshNode]*meshNode, len(nodes))
	depthByNode := make(map[*meshNode]int, len(nodes))
	indexMeshTree(roots, nil, 0, parentByNode, depthByNode, make(map[*meshNode]struct{}, len(nodes)))
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
		if mac, ok := parseMeshMAC(node.mac); ok {
			msg.Set(prefix+"MACAddress", wusp.MAC(mac))
		}
		if parent := parentByNode[node]; parent != nil {
			if parentIndex := nodeIndex[parent]; parentIndex > 0 {
				msg.Set(prefix+"ParentNode", wusp.String(meshNodePath(parentIndex)))
			}
			if parentMAC, ok := parseMeshMAC(parent.mac); ok {
				msg.Set(prefix+"ParentMACAddress", wusp.MAC(parentMAC))
			}
		} else if parentMAC, ok := parseMeshMAC(node.parentMAC); ok {
			msg.Set(prefix+"ParentMACAddress", wusp.MAC(parentMAC))
		}
		msg.Set(prefix+"HopCount", wusp.Uint(uint64(depthByNode[node])))
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
	appendMeshLinksForRoots(msg, roots, nodeIndex, &linkIndex)
}

func normalizedMeshRoots(root *meshNode) []*meshNode {
	if root == nil {
		return nil
	}
	if isSyntheticMeshRoot(root) {
		return dedupeMeshChildren(root.children)
	}
	return []*meshNode{root}
}

func isSyntheticMeshRoot(node *meshNode) bool {
	if node == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(node.name), "Mesh Topology") &&
		strings.TrimSpace(firstNonEmpty(node.id, node.mac, node.ip)) == ""
}

func flattenMeshForest(roots []*meshNode) []*meshNode {
	nodes := make([]*meshNode, 0)
	seen := make(map[*meshNode]struct{})
	for _, root := range roots {
		nodes = append(nodes, flattenMeshNodes(root, seen)...)
	}
	return nodes
}

func flattenMeshNodes(root *meshNode, seen map[*meshNode]struct{}) []*meshNode {
	if root == nil {
		return nil
	}
	if _, ok := seen[root]; ok {
		return nil
	}
	seen[root] = struct{}{}
	nodes := []*meshNode{root}
	for _, child := range root.children {
		nodes = append(nodes, flattenMeshNodes(child, seen)...)
	}
	return nodes
}

func countMeshLinksForRoots(roots []*meshNode) int {
	total := 0
	seen := make(map[*meshNode]struct{})
	for _, root := range roots {
		total += countMeshLinks(root, seen)
	}
	return total
}

func countMeshLinks(node *meshNode, seen map[*meshNode]struct{}) int {
	if node == nil {
		return 0
	}
	if _, ok := seen[node]; ok {
		return 0
	}
	seen[node] = struct{}{}
	count := len(node.children)
	for _, child := range node.children {
		count += countMeshLinks(child, seen)
	}
	return count
}

func appendMeshLinksForRoots(msg *wusp.Message, roots []*meshNode, nodeIndex map[*meshNode]int, linkIndex *int) {
	seen := make(map[*meshNode]struct{})
	for _, root := range roots {
		appendMeshLinks(msg, root, nodeIndex, linkIndex, seen)
	}
}

func appendMeshLinks(msg *wusp.Message, node *meshNode, nodeIndex map[*meshNode]int, linkIndex *int, seen map[*meshNode]struct{}) {
	if node == nil {
		return
	}
	if _, ok := seen[node]; ok {
		return
	}
	seen[node] = struct{}{}
	source := nodeIndex[node]
	for _, child := range node.children {
		target := nodeIndex[child]
		if source > 0 && target > 0 {
			*linkIndex = *linkIndex + 1
			prefix := fmt.Sprintf("Device.WUSP_MeshTelemetry.Link.%d.", *linkIndex)
			msg.Set(prefix+"Alias", wusp.String(fmt.Sprintf("link-%d", *linkIndex)))
			msg.Set(prefix+"SourceNode", wusp.String(meshNodePath(source)))
			msg.Set(prefix+"TargetNode", wusp.String(meshNodePath(target)))
			if mac, ok := parseMeshMAC(node.mac); ok {
				msg.Set(prefix+"SourceMACAddress", wusp.MAC(mac))
			}
			if mac, ok := parseMeshMAC(child.mac); ok {
				msg.Set(prefix+"TargetMACAddress", wusp.MAC(mac))
			}
			msg.Set(prefix+"Status", wusp.String("Up"))
			if child.signal != 0 {
				quality := signalDBMToQuality(child.signal)
				msg.Set(prefix+"SignalQuality", wusp.Uint(uint64(quality)))
				msg.Set(prefix+"Metric", wusp.Uint(uint64(100-quality)))
			}
		}
		appendMeshLinks(msg, child, nodeIndex, linkIndex, seen)
	}
}

func indexMeshTree(roots []*meshNode, parent *meshNode, depth int, parents map[*meshNode]*meshNode, depths map[*meshNode]int, seen map[*meshNode]struct{}) {
	for _, node := range roots {
		if node == nil {
			continue
		}
		if _, ok := seen[node]; ok {
			continue
		}
		seen[node] = struct{}{}
		if parent != nil {
			parents[node] = parent
		}
		depths[node] = depth
		indexMeshTree(node.children, node, depth+1, parents, depths, seen)
	}
}

func attachMeshParentHints(roots []*meshNode) []*meshNode {
	roots = dedupeMeshChildren(roots)
	nodes := flattenMeshForest(roots)
	if len(nodes) < 2 {
		return roots
	}
	byKey := make(map[string]*meshNode, len(nodes)*3)
	for _, node := range nodes {
		for _, key := range meshIdentityKeys(node) {
			if _, exists := byKey[key]; !exists {
				byKey[key] = node
			}
		}
	}

	parentByNode := make(map[*meshNode]*meshNode, len(nodes))
	indexMeshTree(roots, nil, 0, parentByNode, make(map[*meshNode]int, len(nodes)), make(map[*meshNode]struct{}, len(nodes)))
	for _, node := range nodes {
		parent := lookupMeshParent(node, byKey)
		if parent == nil || parent == node {
			continue
		}
		if parentByNode[node] == parent {
			continue
		}
		if wouldCreateMeshCycle(parent, node, parentByNode) {
			continue
		}
		if oldParent := parentByNode[node]; oldParent != nil {
			oldParent.children = removeMeshChild(oldParent.children, node)
		} else {
			roots = removeMeshChild(roots, node)
		}
		if !hasMeshChild(parent, node) {
			parent.children = append(parent.children, node)
		}
		parentByNode[node] = parent
	}
	return dedupeMeshChildren(roots)
}

func ensureMeshTreeRoot(roots []*meshNode) []*meshNode {
	roots = dedupeMeshChildren(roots)
	if len(roots) < 2 || meshHasAnyChild(roots) {
		return roots
	}
	rootIndex := chooseMeshRootIndex(roots)
	root := roots[rootIndex]
	if root == nil {
		return roots
	}
	if strings.TrimSpace(root.role) == "" {
		root.role = "controller"
	}
	children := make([]*meshNode, 0, len(roots)-1)
	for index, node := range roots {
		if index == rootIndex || node == nil {
			continue
		}
		if strings.TrimSpace(node.role) == "" {
			node.role = "agent"
		}
		if node.parentID == "" {
			node.parentID = meshNodeID(root, 1)
		}
		if node.parentMAC == "" {
			node.parentMAC = root.mac
		}
		children = append(children, node)
	}
	root.children = append(root.children, children...)
	return []*meshNode{root}
}

func meshHasAnyChild(roots []*meshNode) bool {
	for _, root := range roots {
		if root != nil && len(root.children) > 0 {
			return true
		}
	}
	return false
}

func chooseMeshRootIndex(roots []*meshNode) int {
	bestIndex := 0
	bestScore := -1
	for index, node := range roots {
		score := meshRootScore(node, index)
		if score > bestScore {
			bestScore = score
			bestIndex = index
		}
	}
	return bestIndex
}

func meshRootScore(node *meshNode, index int) int {
	if node == nil {
		return -1
	}
	score := 100 - index
	normalizedRole := strings.ToLower(strings.TrimSpace(node.role))
	normalizedName := strings.ToLower(strings.TrimSpace(firstNonEmpty(node.name, node.id)))
	if strings.Contains(normalizedRole, "controller") || strings.Contains(normalizedRole, "gateway") || normalizedRole == "root" {
		score += 1000
	}
	if strings.Contains(normalizedName, "controller") || strings.Contains(normalizedName, "gateway") || strings.Contains(normalizedName, "root") {
		score += 500
	}
	if strings.HasSuffix(strings.TrimSpace(node.ip), ".1") {
		score += 400
	}
	if strings.HasSuffix(strings.TrimSpace(node.ip), ".254") {
		score += 200
	}
	return score
}

func lookupMeshParent(node *meshNode, byKey map[string]*meshNode) *meshNode {
	if node == nil {
		return nil
	}
	for _, value := range []string{node.parentMAC, node.parentID} {
		for _, key := range meshIdentityKeys(&meshNode{id: value, mac: value, name: value, ip: value}) {
			if parent := byKey[key]; parent != nil {
				return parent
			}
		}
	}
	return nil
}

func meshIdentityKeys(node *meshNode) []string {
	if node == nil {
		return nil
	}
	keys := make([]string, 0, 5)
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return
		}
		keys = append(keys, value)
		if mac, ok := parseMeshMAC(value); ok {
			keys = append(keys, mac.String())
		}
	}
	add(node.id)
	add(node.mac)
	add(node.name)
	add(node.ip)
	if len(keys) < 2 {
		return keys
	}
	deduped := keys[:0]
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, key)
	}
	return deduped
}

func hasMeshChild(parent, child *meshNode) bool {
	if parent == nil || child == nil {
		return false
	}
	for _, item := range parent.children {
		if item == child {
			return true
		}
	}
	return false
}

func wouldCreateMeshCycle(parent, child *meshNode, parentByNode map[*meshNode]*meshNode) bool {
	for node := parent; node != nil; node = parentByNode[node] {
		if node == child {
			return true
		}
	}
	return false
}

func removeMeshChild(children []*meshNode, child *meshNode) []*meshNode {
	if child == nil {
		return children
	}
	result := children[:0]
	for _, item := range children {
		if item == child {
			continue
		}
		result = append(result, item)
	}
	return result
}

func meshNodePath(index int) string {
	return fmt.Sprintf("Device.WUSP_MeshTelemetry.Node.%d.", index)
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
