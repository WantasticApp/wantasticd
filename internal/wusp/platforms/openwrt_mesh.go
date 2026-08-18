package platforms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"wantastic-agent/internal/linkdiscovery"
	"wantastic-agent/internal/wusp"
)

type openWrtRealTopo struct {
	protocol string
	root     *meshNode
}

type openWrtMeshLinkHint struct {
	source string
	target string
}

func (b *OpenWrtBackend) appendOpenWrtMeshTopology(ctx context.Context, msg *wusp.Message) {
	data, err := b.readOpenWrtRealTopo(ctx)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return
	}
	topo, ok := parseOpenWrtRealTopo(data)
	if !ok {
		return
	}
	if topo.protocol == "" && topo.root != nil {
		topo.protocol = "EasyMesh"
	}
	b.enrichOpenWrtMeshEvidence(topo.root, linkdiscovery.DefaultSnapshot())
	appendMeshSnapshot(msg, meshSnapshot{
		protocol:       topo.protocol,
		implementation: "OpenWrt",
		topology:       topo.root,
		sampleTime:     b.now().UTC(),
	})
}

func (b *OpenWrtBackend) enrichOpenWrtMeshEvidence(root *meshNode, discovery linkdiscovery.Snapshot) {
	if root == nil {
		return
	}
	nodes := flattenMeshForest(normalizedMeshRoots(root))
	byMAC := make(map[string]*meshNode)
	for _, node := range nodes {
		if mac, ok := parseMeshMAC(firstNonEmpty(node.mac, node.id)); ok {
			byMAC[strings.ToLower(mac.String())] = node
		}
	}
	local := localMeshNode(nodes, b.readTextFile(b.hostnamePath))
	if local == nil {
		return
	}

	// A station-mode nl80211 dump returns the associated upstream AP/BSSID.
	// This is direct kernel evidence for the local node's backhaul and fills the
	// common CN -> T2 gap without treating ordinary AP clients as mesh nodes.
	for _, radio := range b.openWrtWirelessRadios() {
		for _, iface := range radio.Interfaces {
			mode := strings.ToLower(configString(iface.Config, "mode"))
			if mode != "sta" && mode != "station" && mode != "client" {
				continue
			}
			ifName := strings.TrimSpace(iface.IfName)
			if ifName == "" || b.wifiAssocList == nil {
				continue
			}
			associations, err := b.wifiAssocList(ifName)
			if err != nil {
				continue
			}
			for _, association := range associations {
				parent := byMAC[strings.ToLower(association.MAC.String())]
				if parent == nil || parent == local {
					continue
				}
				local.parentMAC = parent.mac
				local.parentID = firstNonEmpty(parent.id, parent.mac)
				local.linkType = "Wi-Fi"
				local.linkIface = ifName
				local.discovery = "nl80211"
				break
			}
		}
	}

	// LLDP confirms the physical medium on a relationship already present in
	// the vendor or station topology. It does not invent direction from a
	// symmetric LLDP adjacency.
	wifiInterfaces := b.openWrtWiFiInterfaceSet()
	for _, neighbor := range discovery.LLDP {
		remote := meshNodeForLLDPNeighbor(byMAC, neighbor)
		if remote == nil || remote == local {
			continue
		}
		linkType := "Ethernet"
		if openWrtWiFiInterfaceMatch(neighbor.LocalInterface, wifiInterfaces) {
			linkType = "Wi-Fi"
		}
		if meshNodeReferencesParent(local, remote) {
			local.linkType, local.linkIface, local.discovery = linkType, neighbor.LocalInterface, "LLDP"
		} else if meshNodeReferencesParent(remote, local) {
			remote.linkType, remote.linkIface, remote.discovery = linkType, neighbor.LocalInterface, "LLDP"
		}
	}
	for _, neighbor := range discovery.MNDP {
		node := byMAC[strings.ToLower(neighbor.MAC.String())]
		if node == nil {
			continue
		}
		if node.name == "" {
			node.name = strings.TrimSpace(neighbor.Identity)
		}
		if node.ip == "" && len(neighbor.IPv4) > 0 {
			node.ip = neighbor.IPv4[0].String()
		}
	}
}

func localMeshNode(nodes []*meshNode, hostname string) *meshNode {
	hostname = strings.TrimSpace(hostname)
	localMACs := make(map[string]bool)
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) == 6 {
			localMACs[strings.ToLower(iface.HardwareAddr.String())] = true
		}
	}
	for _, node := range nodes {
		if mac, ok := parseMeshMAC(firstNonEmpty(node.mac, node.id)); ok && localMACs[strings.ToLower(mac.String())] {
			return node
		}
	}
	for _, node := range nodes {
		if hostname != "" && strings.EqualFold(strings.TrimSpace(node.name), hostname) {
			return node
		}
	}
	return nil
}

func meshNodeForLLDPNeighbor(byMAC map[string]*meshNode, neighbor linkdiscovery.LLDPNeighbor) *meshNode {
	for _, value := range []string{neighbor.ChassisID, neighbor.SourceMAC.String()} {
		if mac, err := net.ParseMAC(value); err == nil {
			if node := byMAC[strings.ToLower(mac.String())]; node != nil {
				return node
			}
		}
	}
	return nil
}

func meshNodeReferencesParent(child, parent *meshNode) bool {
	if child == nil || parent == nil {
		return false
	}
	for _, childParent := range []string{child.parentMAC, child.parentID} {
		for _, parentIdentity := range []string{parent.mac, parent.id} {
			if meshIdentityValueEqual(childParent, parentIdentity) {
				return true
			}
		}
	}
	return false
}

func meshIdentityValueEqual(left, right string) bool {
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)
	if left == "" || right == "" {
		return false
	}
	leftMAC, leftOK := parseMeshMAC(left)
	rightMAC, rightOK := parseMeshMAC(right)
	if leftOK && rightOK {
		return strings.EqualFold(leftMAC.String(), rightMAC.String())
	}
	return strings.EqualFold(left, right)
}

func (b *OpenWrtBackend) appendOpenWrtMeshConfig(ctx context.Context, msg *wusp.Message) {
	if msg == nil {
		return
	}
	wireless, _ := b.readUCIConfig("wireless")
	network, _ := b.readUCIConfig("network")
	protocolIndex := nextMeshProtocolIndex(msg)
	ieeeIndex := 0
	batIndex := 0

	for _, section := range wireless.Sections {
		if section.Type != "wifi-iface" || !strings.EqualFold(strings.TrimSpace(section.Options["mode"]), "mesh") {
			continue
		}
		ieeeIndex++
		protocolPath := fmt.Sprintf("Device.WUSP_MeshTelemetry.Protocol.%d.", protocolIndex)
		ieeePath := fmt.Sprintf("Device.WUSP_MeshTelemetry.IEEE80211s.%d.", ieeeIndex)
		msg.Set(protocolPath+"Alias", wusp.String(fmt.Sprintf("protocol-%d", protocolIndex)))
		msg.Set(protocolPath+"Name", wusp.String("IEEE80211s"))
		msg.Set(protocolPath+"Implementation", wusp.String("OpenWrt"))
		msg.Set(protocolPath+"Status", wusp.String(statusFromDisabledOption(section.Options["disabled"])))
		msg.Set(protocolPath+"Writable", wusp.Bool(true))
		msg.Set(protocolPath+"PrimaryObject", wusp.String(ieeePath))
		msg.Set(ieeePath+"Alias", wusp.String(firstNonEmpty(section.Name, fmt.Sprintf("ieee80211s-%d", ieeeIndex))))
		msg.Set(ieeePath+"Enable", wusp.Bool(!parseOpenWrtBool(section.Options["disabled"], false)))
		msg.Set(ieeePath+"Status", wusp.String(upDownFromDisabledOption(section.Options["disabled"])))
		msg.Set(ieeePath+"ProtocolReference", wusp.String(protocolPath))
		if radioIndex := b.radioIndexForDevice(section.Options["device"]); radioIndex > 0 {
			msg.Set(ieeePath+"RadioReference", wusp.String(fmt.Sprintf("Device.WiFi.Radio.%d.", radioIndex)))
		}
		if ifName := firstNonEmpty(section.Options["ifname"], section.Name); ifName != "" {
			msg.Set(ieeePath+"InterfaceName", wusp.String(ifName))
		}
		setStringOption(msg, ieeePath+"Network", section.Options["network"])
		setStringOption(msg, ieeePath+"MeshID", firstNonEmpty(section.Options["mesh_id"], section.Options["ssid"]))
		setStringOption(msg, ieeePath+"Encryption", normalizeOpenWrtMeshEncryption(section.Options["encryption"]))
		setUintOption(msg, ieeePath+"Channel", b.readUCIValue(ctx, "wireless", section.Options["device"], "channel"))
		setBoolOption(msg, ieeePath+"MeshForwarding", section.Options["mesh_fwding"])
		setBoolOption(msg, ieeePath+"MeshNoLearn", section.Options["mesh_nolearn"])
		setIntOption(msg, ieeePath+"MeshRSSIThreshold", section.Options["mesh_rssi_threshold"])
		setUintOption(msg, ieeePath+"MeshMaxPeerLinks", section.Options["mesh_max_peer_links"])
		setUintOption(msg, ieeePath+"MeshMaxRetries", section.Options["mesh_max_retries"])
		setUintOption(msg, ieeePath+"MeshHWMPRootMode", section.Options["mesh_hwmp_rootmode"])
		setBoolOption(msg, ieeePath+"MeshGateAnnouncements", section.Options["mesh_gate_announcements"])
		setBoolOption(msg, ieeePath+"MeshConnectedToGate", section.Options["mesh_connected_to_gate"])
		setBoolOption(msg, ieeePath+"MeshConnectedToAS", section.Options["mesh_connected_to_as"])
		setUintOption(msg, ieeePath+"MeshTTL", section.Options["mesh_ttl"])
		msg.Set(ieeePath+"PeerNumberOfEntries", wusp.Uint(0))
		protocolIndex++
	}

	for _, section := range network.Sections {
		if section.Type != "interface" || !strings.EqualFold(strings.TrimSpace(section.Options["proto"]), "batadv") {
			continue
		}
		batIndex++
		protocolPath := fmt.Sprintf("Device.WUSP_MeshTelemetry.Protocol.%d.", protocolIndex)
		batPath := fmt.Sprintf("Device.WUSP_MeshTelemetry.BATMANAdv.%d.", batIndex)
		msg.Set(protocolPath+"Alias", wusp.String(fmt.Sprintf("protocol-%d", protocolIndex)))
		msg.Set(protocolPath+"Name", wusp.String("BATMANAdv"))
		msg.Set(protocolPath+"Implementation", wusp.String("batman-adv"))
		msg.Set(protocolPath+"Status", wusp.String(statusFromDisabledOption(section.Options["disabled"])))
		msg.Set(protocolPath+"Writable", wusp.Bool(true))
		msg.Set(protocolPath+"PrimaryObject", wusp.String(batPath))
		msg.Set(batPath+"Alias", wusp.String(firstNonEmpty(section.Name, fmt.Sprintf("batman-adv-%d", batIndex))))
		msg.Set(batPath+"Enable", wusp.Bool(!parseOpenWrtBool(section.Options["disabled"], false)))
		msg.Set(batPath+"Status", wusp.String(upDownFromDisabledOption(section.Options["disabled"])))
		msg.Set(batPath+"ProtocolReference", wusp.String(protocolPath))
		msg.Set(batPath+"InterfaceName", wusp.String(firstNonEmpty(section.Name, section.Options["ifname"], fmt.Sprintf("bat%d", batIndex-1))))
		setStringOption(msg, batPath+"RoutingAlgorithm", section.Options["routing_algo"])
		setBoolOption(msg, batPath+"AggregatedOGMs", section.Options["aggregated_ogms"])
		setBoolOption(msg, batPath+"Fragmentation", section.Options["fragmentation"])
		setStringOption(msg, batPath+"GatewayMode", section.Options["gw_mode"])
		setStringOption(msg, batPath+"GatewayBandwidth", section.Options["gw_bandwidth"])
		setUintOption(msg, batPath+"GatewaySelectionClass", section.Options["gw_sel_class"])
		setUintOption(msg, batPath+"OrigInterval", section.Options["orig_interval"])
		setBoolOption(msg, batPath+"BridgeLoopAvoidance", section.Options["bridge_loop_avoidance"])
		setBoolOption(msg, batPath+"DistributedARPTable", section.Options["distributed_arp_table"])
		setBoolOption(msg, batPath+"MulticastMode", section.Options["multicast_mode"])
		setUintOption(msg, batPath+"MulticastFanout", section.Options["multicast_fanout"])
		setUintOption(msg, batPath+"HopPenalty", section.Options["hop_penalty"])
		setBoolOption(msg, batPath+"APIsolation", section.Options["ap_isolation"])
		setStringOption(msg, batPath+"IsolationMark", section.Options["isolation_mark"])
		msg.Set(batPath+"OriginatorNumberOfEntries", wusp.Uint(0))
		msg.Set(batPath+"NeighborNumberOfEntries", wusp.Uint(0))
		msg.Set(batPath+"TranslationTableNumberOfEntries", wusp.Uint(0))
		msg.Set(batPath+"GatewayNumberOfEntries", wusp.Uint(0))
		protocolIndex++
	}

	if ieeeIndex > 0 || batIndex > 0 {
		msg.Set("Device.WUSP_MeshTelemetry.Enable", wusp.Bool(true))
		if _, ok := msg.Get("Device.WUSP_MeshTelemetry.Status"); !ok {
			msg.Set("Device.WUSP_MeshTelemetry.Status", wusp.String("Collecting"))
		}
		msg.Set("Device.WUSP_MeshTelemetry.IEEE80211sNumberOfEntries", wusp.Uint(uint64(ieeeIndex)))
		msg.Set("Device.WUSP_MeshTelemetry.BATMANAdvNumberOfEntries", wusp.Uint(uint64(batIndex)))
		msg.Set("Device.WUSP_MeshTelemetry.ProtocolNumberOfEntries", wusp.Uint(uint64(protocolIndex-1)))
		if _, ok := msg.Get("Device.WUSP_MeshTelemetry.LastSampleTime"); !ok {
			msg.Set("Device.WUSP_MeshTelemetry.LastSampleTime", wusp.Time(b.now().UTC()))
		}
	}
}

func (b *OpenWrtBackend) setOpenWrtMeshParam(ctx context.Context, path string, value wusp.Value) error {
	if strings.HasPrefix(path, "Device.WUSP_MeshTelemetry.IEEE80211s.") {
		return b.setOpenWrtIEEE80211sParam(ctx, path, value)
	}
	if strings.HasPrefix(path, "Device.WUSP_MeshTelemetry.BATMANAdv.") {
		return b.setOpenWrtBATMANAdvParam(ctx, path, value)
	}
	return wusp.ErrUSPPathUnsupported
}

func (b *OpenWrtBackend) setOpenWrtIEEE80211sParam(ctx context.Context, path string, value wusp.Value) error {
	index, leaf, ok := parseIndexedMeshPath(path, "Device.WUSP_MeshTelemetry.IEEE80211s.")
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}
	if leaf == "Channel" {
		channel, err := boundedUintString("Channel", value, 1, 233)
		if err != nil {
			return err
		}
		radioSection := b.openWrtMeshRadioSection(index)
		if radioSection == "" {
			return wusp.ErrUSPPathUnsupported
		}
		return b.setUCIOption(ctx, "wireless", radioSection, "channel", channel, true, wirelessReloadScript)
	}
	section := b.openWrtMeshIfaceSection(index)
	if section == "" {
		return wusp.ErrUSPPathUnsupported
	}
	option, converted, err := openWrtIEEE80211sOptionValue(leaf, value)
	if err != nil {
		return err
	}
	return b.setUCIOption(ctx, "wireless", section, option, converted, true, wirelessReloadScript)
}

func (b *OpenWrtBackend) setOpenWrtBATMANAdvParam(ctx context.Context, path string, value wusp.Value) error {
	index, leaf, ok := parseIndexedMeshPath(path, "Device.WUSP_MeshTelemetry.BATMANAdv.")
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}
	section := b.openWrtBatmanSection(index)
	if section == "" {
		return wusp.ErrUSPPathUnsupported
	}
	option, converted, err := openWrtBatmanOptionValue(leaf, value)
	if err != nil {
		return err
	}
	return b.setUCIOption(ctx, "network", section, option, converted, true, networkReloadScript)
}

func (b *OpenWrtBackend) readOpenWrtRealTopo(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	data, err := b.callUbus(ctx, "device", "getRealTopo", nil)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("openwrt mesh topology: empty getRealTopo response")
	}
	return data, nil
}

func parseOpenWrtRealTopo(data []byte) (openWrtRealTopo, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw any
	if err := decoder.Decode(&raw); err != nil {
		return openWrtRealTopo{}, false
	}
	raw = unwrapOpenWrtRealTopo(raw)
	protocol := findOpenWrtMeshProtocol(raw)
	root := meshNodeFromAny(raw, "", 0)
	applyOpenWrtLinkHints(root, raw)
	if root == nil && protocol == "" {
		return openWrtRealTopo{}, false
	}
	return openWrtRealTopo{protocol: protocol, root: root}, true
}

func unwrapOpenWrtRealTopo(raw any) any {
	obj, ok := raw.(map[string]any)
	if !ok {
		return raw
	}
	if result, ok := lookupAnyCI(obj, "result"); ok {
		if list, ok := result.([]any); ok && len(list) >= 2 {
			return list[1]
		}
	}
	for _, key := range []string{"response", "data", "topology", "topo"} {
		if value, ok := lookupAnyCI(obj, key); ok {
			if node := meshNodeFromAny(value, key, 0); node != nil {
				return value
			}
		}
	}
	return raw
}

func findOpenWrtMeshProtocol(raw any) string {
	switch value := raw.(type) {
	case map[string]any:
		for _, key := range []string{"protocol", "mesh_protocol", "meshProtocol", "mesh_type", "meshType", "standard"} {
			if candidate := normalizeMeshProtocol(stringFromAny(lookupAnyCIValue(value, key))); candidate != "" && candidate != "Unknown" {
				return candidate
			}
		}
		for _, item := range value {
			if protocol := findOpenWrtMeshProtocol(item); protocol != "" {
				return protocol
			}
		}
	case []any:
		for _, item := range value {
			if protocol := findOpenWrtMeshProtocol(item); protocol != "" {
				return protocol
			}
		}
	}
	return ""
}

func meshNodeFromAny(raw any, hint string, depth int) *meshNode {
	if depth > 16 {
		return nil
	}
	switch value := raw.(type) {
	case map[string]any:
		return meshNodeFromMap(value, hint, depth)
	case []any:
		children := make([]*meshNode, 0, len(value))
		for _, item := range value {
			if child := meshNodeFromAny(item, "", depth+1); child != nil {
				children = append(children, child)
			}
		}
		return collapseMeshContainer(children)
	default:
		return nil
	}
}

func meshNodeFromMap(payload map[string]any, hint string, depth int) *meshNode {
	node := &meshNode{}
	if id := strings.TrimSpace(hint); id != "" && !isOpenWrtMeshContainerKey(id) {
		if mac, ok := parseMeshMAC(id); ok {
			node.id = mac.String()
			node.mac = mac.String()
		} else if role := roleFromOpenWrtMeshHint(id); role != "" {
			node.role = role
		} else {
			node.id = id
		}
	}

	node.id = firstNonEmpty(node.id, firstStringCI(payload, "id", "node_id", "nodeId", "device_id", "deviceId", "al_id", "alId", "alid", "ieee1905id", "ieee1905_id"))
	node.mac = firstNonEmpty(node.mac, firstStringCI(payload, "mac", "macaddr", "mac_address", "macAddress", "bssid", "al_mac", "alMac", "almac", "backhaul_mac", "backhaulMac", "backhaulMAC"))
	if node.mac == "" {
		if mac, ok := parseMeshMAC(node.id); ok {
			node.mac = mac.String()
		}
	}
	node.name = firstStringCI(payload, "hostname", "host", "name", "alias", "device_name", "deviceName", "friendly_name", "friendlyName", "label")
	node.ip = firstStringCI(payload, "ip", "ipaddr", "ip_address", "ipAddress", "ipv4", "address", "lan_ip", "lanIP")
	node.role = firstNonEmpty(node.role, firstStringCI(payload, "role", "type", "device_role", "deviceRole", "mode", "node_type", "nodeType"))
	node.signal = firstIntCI(payload, "rssi", "signal", "signal_strength", "signalStrength", "backhaul_signal", "backhaulSignal", "rx_signal", "rxSignal")
	node.parentID = firstStringCI(payload,
		"parent", "parent_id", "parentId", "parent_node", "parentNode",
		"parent_al_id", "parentAlId", "parentAlID", "parent_ieee1905_id", "parentIEEE1905ID",
		"uplink", "uplink_id", "uplinkId", "upstream", "upstream_id", "upstreamId",
		"backhaul_parent", "backhaulParent",
	)
	node.parentMAC = firstStringCI(payload,
		"pMac", "pmac",
		"parent_mac", "parentMac", "parent_mac_address", "parentMacAddress",
		"parent_al_mac", "parentAlMac", "parentALMAC",
		"uplink_mac", "uplinkMac", "upstream_mac", "upstreamMac",
		"backhaul_parent_mac", "backhaulParentMAC",
	)
	node.sourceHop, node.hasHop = firstPresentIntCI(payload, "hops", "hop", "hop_count", "hopCount")
	node.backhaul = firstStringCI(payload, "backhaul", "backhaul_type", "backhaulType", "backhaul_media", "backhaulMedia")
	if node.role == "" && node.hasHop {
		if node.sourceHop == 0 {
			node.role = "controller"
		} else {
			node.role = "agent"
		}
	}
	if node.parentMAC == "" {
		if mac, ok := parseMeshMAC(node.parentID); ok {
			node.parentMAC = mac.String()
		}
	}

	children := make([]*meshNode, 0)
	for _, key := range openWrtMeshContainerKeys() {
		value, ok := lookupAnyCI(payload, key)
		if !ok {
			continue
		}
		children = append(children, meshChildrenFromAny(value, key, depth+1)...)
	}
	for _, key := range sortedMapKeys(payload) {
		value := payload[key]
		if isOpenWrtMeshScalarKey(key) || isOpenWrtMeshContainerKey(key) {
			continue
		}
		if !looksLikeOpenWrtMeshNodeKey(key) {
			continue
		}
		children = append(children, meshChildrenFromAny(value, key, depth+1)...)
	}
	node.children = dedupeMeshChildren(children)

	if !meshNodeHasIdentity(node) {
		return collapseMeshContainer(node.children)
	}
	if node.id == "" && node.mac != "" {
		node.id = node.mac
	}
	return node
}

func applyOpenWrtLinkHints(root *meshNode, raw any) {
	if root == nil {
		return
	}
	links := extractOpenWrtMeshLinkHints(raw)
	if len(links) == 0 {
		return
	}
	nodes := flattenMeshForest(normalizedMeshRoots(root))
	byKey := make(map[string]*meshNode, len(nodes)*4)
	for _, node := range nodes {
		for _, key := range meshIdentityKeys(node) {
			if _, exists := byKey[key]; !exists {
				byKey[key] = node
			}
		}
	}
	for _, link := range links {
		source := lookupOpenWrtMeshHintNode(link.source, byKey)
		target := lookupOpenWrtMeshHintNode(link.target, byKey)
		if source == nil || target == nil || source == target {
			continue
		}
		if target.parentMAC == "" {
			target.parentMAC = source.mac
		}
		if target.parentID == "" {
			target.parentID = meshNodeID(source, 1)
		}
	}
}

func lookupOpenWrtMeshHintNode(value string, byKey map[string]*meshNode) *meshNode {
	for _, key := range meshIdentityKeys(&meshNode{id: value, mac: value, name: value, ip: value}) {
		if node := byKey[key]; node != nil {
			return node
		}
	}
	return nil
}

func extractOpenWrtMeshLinkHints(raw any) []openWrtMeshLinkHint {
	switch value := raw.(type) {
	case map[string]any:
		hints := make([]openWrtMeshLinkHint, 0)
		if hint, ok := openWrtMeshLinkHintFromMap(value); ok {
			hints = append(hints, hint)
		}
		for key, item := range value {
			if isOpenWrtMeshLinkCollectionKey(key) {
				hints = append(hints, extractOpenWrtMeshLinkHints(item)...)
				continue
			}
			switch item.(type) {
			case map[string]any, []any:
				hints = append(hints, extractOpenWrtMeshLinkHints(item)...)
			}
		}
		return hints
	case []any:
		hints := make([]openWrtMeshLinkHint, 0, len(value))
		for _, item := range value {
			hints = append(hints, extractOpenWrtMeshLinkHints(item)...)
		}
		return hints
	default:
		return nil
	}
}

func openWrtMeshLinkHintFromMap(payload map[string]any) (openWrtMeshLinkHint, bool) {
	parent := firstMeshIdentityCI(payload,
		"parent", "parent_id", "parentId", "parent_node", "parentNode",
		"parent_mac", "parentMac", "parent_mac_address", "parentMacAddress",
		"parent_al_mac", "parentAlMac", "uplink", "uplink_id", "uplinkId",
		"uplink_mac", "uplinkMac", "upstream", "upstream_id", "upstreamId",
		"upstream_mac", "upstreamMac", "backhaul_parent", "backhaulParent",
		"backhaul_parent_mac", "backhaulParentMAC",
	)
	if parent != "" {
		child := firstMeshIdentityCI(payload,
			"id", "node_id", "nodeId", "device_id", "deviceId", "al_id", "alId", "ieee1905_id",
			"mac", "macaddr", "mac_address", "macAddress", "al_mac", "alMac", "backhaul_mac", "backhaulMac",
			"child", "child_id", "childId", "child_mac", "childMac", "slave", "slave_mac", "agent", "agent_mac",
		)
		if child != "" && child != parent {
			return openWrtMeshLinkHint{source: parent, target: child}, true
		}
	}

	source := firstMeshIdentityCI(payload,
		"source", "source_id", "sourceId", "source_mac", "sourceMac",
		"src", "src_id", "srcId", "src_mac", "srcMac",
		"from", "from_id", "fromId", "from_mac", "fromMac",
		"local", "local_id", "localId", "local_mac", "localMac",
	)
	target := firstMeshIdentityCI(payload,
		"target", "target_id", "targetId", "target_mac", "targetMac",
		"dst", "dst_id", "dstId", "dst_mac", "dstMac",
		"to", "to_id", "toId", "to_mac", "toMac",
		"remote", "remote_id", "remoteId", "remote_mac", "remoteMac",
		"neighbor", "neighbor_id", "neighborId", "neighbor_mac", "neighborMac",
		"neighbour", "neighbour_id", "neighbourId", "neighbour_mac", "neighbourMac",
		"child", "child_id", "childId", "child_mac", "childMac",
	)
	if source == "" || target == "" || source == target {
		return openWrtMeshLinkHint{}, false
	}
	return openWrtMeshLinkHint{source: source, target: target}, true
}

func firstMeshIdentityCI(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := lookupAnyCI(payload, key)
		if !ok {
			continue
		}
		if text := strings.TrimSpace(stringFromAny(value)); text != "" {
			return text
		}
		if nested, ok := value.(map[string]any); ok {
			if text := firstStringCI(nested,
				"id", "node_id", "nodeId", "device_id", "deviceId", "al_id", "alId", "ieee1905_id",
				"mac", "macaddr", "mac_address", "macAddress", "al_mac", "alMac", "backhaul_mac", "backhaulMac",
				"hostname", "name", "ip", "ipaddr", "ip_address", "ipAddress",
			); text != "" {
				return text
			}
		}
	}
	return ""
}

func meshChildrenFromAny(raw any, hint string, depth int) []*meshNode {
	switch value := raw.(type) {
	case map[string]any:
		if !isOpenWrtMeshCollectionKey(hint) {
			if child := meshNodeFromMap(value, hint, depth); child != nil {
				return []*meshNode{child}
			}
		}
		children := make([]*meshNode, 0, len(value))
		for _, key := range sortedMapKeys(value) {
			item := value[key]
			if child := meshNodeFromAny(item, key, depth+1); child != nil {
				children = append(children, child)
			}
		}
		return children
	case []any:
		children := make([]*meshNode, 0, len(value))
		for _, item := range value {
			if child := meshNodeFromAny(item, "", depth+1); child != nil {
				children = append(children, child)
			}
		}
		return children
	default:
		return nil
	}
}

func collapseMeshContainer(children []*meshNode) *meshNode {
	children = dedupeMeshChildren(children)
	switch len(children) {
	case 0:
		return nil
	case 1:
		return children[0]
	default:
		return &meshNode{name: "Mesh Topology", role: "controller", children: children}
	}
}

func meshNodeHasIdentity(node *meshNode) bool {
	if node == nil {
		return false
	}
	return strings.TrimSpace(firstNonEmpty(node.id, node.name, node.mac, node.ip, node.role)) != "" || node.signal != 0
}

func dedupeMeshChildren(children []*meshNode) []*meshNode {
	if len(children) < 2 {
		return children
	}
	seen := make(map[string]struct{}, len(children))
	result := children[:0]
	for _, child := range children {
		if child == nil {
			continue
		}
		key := strings.ToLower(meshNodeID(child, len(result)+1))
		if key == "" {
			result = append(result, child)
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, child)
	}
	return result
}

func firstStringCI(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := lookupAnyCI(payload, key); ok {
			if text := strings.TrimSpace(stringFromAny(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstIntCI(payload map[string]any, keys ...string) int {
	for _, key := range keys {
		if value, ok := lookupAnyCI(payload, key); ok {
			if parsed, ok := intFromAny(value); ok {
				return parsed
			}
		}
	}
	return 0
}

func firstPresentIntCI(payload map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		value, ok := lookupAnyCI(payload, key)
		if !ok {
			continue
		}
		if parsed, valid := intFromAny(value); valid {
			return parsed, true
		}
	}
	return 0, false
}

func lookupAnyCIValue(payload map[string]any, key string) any {
	value, _ := lookupAnyCI(payload, key)
	return value
}

func lookupAnyCI(payload map[string]any, key string) (any, bool) {
	if value, ok := payload[key]; ok {
		return value, true
	}
	target := strings.ToLower(key)
	for candidate, value := range payload {
		if strings.ToLower(candidate) == target {
			return value, true
		}
	}
	return nil, false
}

func sortedMapKeys(payload map[string]any) []string {
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

func intFromAny(value any) (int, bool) {
	switch typed := value.(type) {
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return int(parsed), true
		}
		if parsed, err := strconv.ParseFloat(typed.String(), 64); err == nil {
			return int(parsed), true
		}
	case float64:
		return int(typed), true
	case string:
		fields := strings.FieldsFunc(typed, func(r rune) bool {
			return !(r == '-' || r == '+' || (r >= '0' && r <= '9'))
		})
		for _, field := range fields {
			if parsed, err := strconv.Atoi(field); err == nil {
				return parsed, true
			}
		}
	}
	return 0, false
}

func openWrtMeshContainerKeys() []string {
	return []string{
		"topology",
		"topo",
		"data",
		"root",
		"controller",
		"gateway",
		"device",
		"devices",
		"node",
		"nodes",
		"children",
		"child",
		"childs",
		"agents",
		"ap_devices",
		"apDevices",
		"mesh_nodes",
		"meshNodes",
		"downlink_devices",
		"downlinkDevices",
		"connected_devices",
		"connectedDevices",
	}
}

func isOpenWrtMeshContainerKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, candidate := range openWrtMeshContainerKeys() {
		if normalized == strings.ToLower(candidate) {
			return true
		}
	}
	return false
}

func isOpenWrtMeshCollectionKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "devices", "nodes", "children", "child", "childs", "agents", "ap_devices", "apdevices",
		"mesh_nodes", "meshnodes", "downlink_devices", "downlinkdevices", "connected_devices", "connecteddevices":
		return true
	default:
		return false
	}
}

func isOpenWrtMeshLinkCollectionKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "links", "link", "edges", "edge", "connections", "connection",
		"topology_links", "topologylinks", "topo_links", "topolinks",
		"backhaul_links", "backhaullinks", "uplinks", "uplink_links", "upstream_links",
		"neighbor_links", "neighborlinks", "neighbour_links", "neighbourlinks":
		return true
	default:
		return false
	}
}

func isOpenWrtMeshScalarKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "id", "node_id", "nodeid", "device_id", "deviceid", "al_id", "alid", "ieee1905id", "ieee1905_id",
		"mac", "macaddr", "mac_address", "macaddress", "bssid", "al_mac", "almac", "backhaul_mac", "backhaulmac",
		"hostname", "host", "name", "alias", "device_name", "devicename", "friendly_name", "friendlyname", "label",
		"ip", "ipaddr", "ip_address", "ipaddress", "ipv4", "address", "lan_ip", "lanip",
		"role", "type", "device_role", "devicerole", "mode", "node_type", "nodetype",
		"parent", "parent_id", "parentid", "parent_node", "parentnode", "parent_al_id", "parentalid", "parent_ieee1905_id", "parentieee1905id",
		"parent_mac", "parentmac", "parent_mac_address", "parentmacaddress", "parent_al_mac", "parentalmac",
		"pmac", "hops", "hop", "hop_count", "hopcount", "backhaul", "backhaul_type", "backhaultype",
		"uplink", "uplink_id", "uplinkid", "uplink_mac", "uplinkmac",
		"upstream", "upstream_id", "upstreamid", "upstream_mac", "upstreammac",
		"backhaul_parent", "backhaulparent", "backhaul_parent_mac", "backhaulparentmac",
		"rssi", "signal", "signal_strength", "signalstrength", "backhaul_signal", "backhaulsignal", "rx_signal", "rxsignal",
		"protocol", "mesh_protocol", "meshprotocol", "mesh_type", "meshtype", "standard", "status", "state":
		return true
	default:
		return false
	}
}

func looksLikeOpenWrtMeshNodeKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if _, ok := parseMeshMAC(normalized); ok {
		return true
	}
	for _, needle := range []string{"node", "device", "agent", "ap", "mesh", "controller", "gateway", "client"} {
		if strings.Contains(normalized, needle) {
			return true
		}
	}
	return false
}

func roleFromOpenWrtMeshHint(hint string) string {
	normalized := strings.ToLower(strings.TrimSpace(hint))
	switch {
	case strings.Contains(normalized, "controller") || strings.Contains(normalized, "gateway") || normalized == "root":
		return "controller"
	case strings.Contains(normalized, "client"):
		return "client"
	case strings.Contains(normalized, "agent") || strings.Contains(normalized, "node") || strings.Contains(normalized, "ap"):
		return "agent"
	default:
		return ""
	}
}

func nextMeshProtocolIndex(msg *wusp.Message) int {
	maxIndex := 0
	for _, field := range msg.Fields {
		rest, ok := strings.CutPrefix(field.Path, "Device.WUSP_MeshTelemetry.Protocol.")
		if !ok {
			continue
		}
		parts := strings.SplitN(rest, ".", 2)
		if len(parts) != 2 {
			continue
		}
		if index, err := strconv.Atoi(parts[0]); err == nil && index > maxIndex {
			maxIndex = index
		}
	}
	return maxIndex + 1
}

func (b *OpenWrtBackend) radioIndexForDevice(device string) int {
	device = strings.TrimSpace(device)
	if device == "" {
		return 0
	}
	radios := b.readWirelessRadioStatus()
	if len(radios) == 0 {
		radios = b.readWirelessRadioStatusFromUCI()
	}
	keys := make([]string, 0, len(radios))
	for key := range radios {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for i, key := range keys {
		if key == device {
			return i + 1
		}
	}
	return 0
}

func parseIndexedMeshPath(path, prefix string) (int, string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(path), prefix)
	if !ok {
		return 0, "", false
	}
	parts := strings.SplitN(rest, ".", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	index, err := strconv.Atoi(parts[0])
	if err != nil || index <= 0 {
		return 0, "", false
	}
	leaf := strings.TrimSpace(parts[1])
	if leaf == "" || strings.Contains(leaf, ".") {
		return 0, "", false
	}
	return index, leaf, true
}

func (b *OpenWrtBackend) openWrtMeshIfaceSection(index int) string {
	parsed, err := b.readUCIConfig("wireless")
	if err != nil {
		return ""
	}
	count := 0
	ifaceIndex := 0
	for _, section := range parsed.Sections {
		if section.Type != "wifi-iface" {
			continue
		}
		ifaceIndex++
		if !strings.EqualFold(strings.TrimSpace(section.Options["mode"]), "mesh") {
			continue
		}
		count++
		if count == index {
			if section.Name != "" {
				return section.Name
			}
			return fmt.Sprintf("@wifi-iface[%d]", ifaceIndex-1)
		}
	}
	return ""
}

func (b *OpenWrtBackend) openWrtMeshRadioSection(index int) string {
	parsed, err := b.readUCIConfig("wireless")
	if err != nil {
		return ""
	}
	count := 0
	for _, section := range parsed.Sections {
		if section.Type != "wifi-iface" || !strings.EqualFold(strings.TrimSpace(section.Options["mode"]), "mesh") {
			continue
		}
		count++
		if count == index {
			return strings.TrimSpace(section.Options["device"])
		}
	}
	return ""
}

func (b *OpenWrtBackend) openWrtBatmanSection(index int) string {
	parsed, err := b.readUCIConfig("network")
	if err != nil {
		return ""
	}
	count := 0
	ifaceIndex := 0
	for _, section := range parsed.Sections {
		if section.Type != "interface" {
			continue
		}
		ifaceIndex++
		if !strings.EqualFold(strings.TrimSpace(section.Options["proto"]), "batadv") {
			continue
		}
		count++
		if count == index {
			if section.Name != "" {
				return section.Name
			}
			return fmt.Sprintf("@interface[%d]", ifaceIndex-1)
		}
	}
	return ""
}

func openWrtIEEE80211sOptionValue(leaf string, value wusp.Value) (string, string, error) {
	switch leaf {
	case "Enable":
		enabled, err := boolValue("Enable", value)
		if err != nil {
			return "", "", err
		}
		if enabled {
			return "disabled", "0", nil
		}
		return "disabled", "1", nil
	case "Network":
		network, err := boundedNonEmptyString("Network", value, 64)
		return "network", network, err
	case "MeshID":
		meshID, err := boundedNonEmptyString("MeshID", value, 32)
		return "mesh_id", meshID, err
	case "Encryption":
		encryption, err := enumString("Encryption", value, "none", "sae", "psk2", "psk-mixed")
		return "encryption", encryption, err
	case "Key":
		key := value.AsString()
		if len(key) < 8 || len(key) > 64 {
			return "", "", fmt.Errorf("wusp openwrt mesh Key length must be 8..64")
		}
		return "key", key, nil
	case "MeshForwarding":
		enabled, err := boolValue("MeshForwarding", value)
		return "mesh_fwding", boolToOpenWrtOption(enabled), err
	case "MeshNoLearn":
		enabled, err := boolValue("MeshNoLearn", value)
		return "mesh_nolearn", boolToOpenWrtOption(enabled), err
	case "MeshRSSIThreshold":
		threshold, err := boundedIntString("MeshRSSIThreshold", value, -255, 0)
		return "mesh_rssi_threshold", threshold, err
	case "MeshMaxPeerLinks":
		links, err := boundedUintString("MeshMaxPeerLinks", value, 0, 0)
		return "mesh_max_peer_links", links, err
	case "MeshMaxRetries":
		retries, err := boundedUintString("MeshMaxRetries", value, 0, 0)
		return "mesh_max_retries", retries, err
	case "MeshHWMPRootMode":
		mode, err := boundedUintString("MeshHWMPRootMode", value, 0, 4)
		return "mesh_hwmp_rootmode", mode, err
	case "MeshGateAnnouncements":
		enabled, err := boolValue("MeshGateAnnouncements", value)
		return "mesh_gate_announcements", boolToOpenWrtOption(enabled), err
	case "MeshConnectedToGate":
		enabled, err := boolValue("MeshConnectedToGate", value)
		return "mesh_connected_to_gate", boolToOpenWrtOption(enabled), err
	case "MeshConnectedToAS":
		enabled, err := boolValue("MeshConnectedToAS", value)
		return "mesh_connected_to_as", boolToOpenWrtOption(enabled), err
	case "MeshTTL":
		ttl, err := boundedUintString("MeshTTL", value, 1, 255)
		return "mesh_ttl", ttl, err
	default:
		return "", "", wusp.ErrUSPPathUnsupported
	}
}

func openWrtBatmanOptionValue(leaf string, value wusp.Value) (string, string, error) {
	switch leaf {
	case "Enable":
		enabled, err := boolValue("Enable", value)
		if err != nil {
			return "", "", err
		}
		if enabled {
			return "disabled", "0", nil
		}
		return "disabled", "1", nil
	case "RoutingAlgorithm":
		algorithm, err := enumString("RoutingAlgorithm", value, "BATMAN_IV", "BATMAN_V")
		return "routing_algo", algorithm, err
	case "AggregatedOGMs":
		enabled, err := boolValue("AggregatedOGMs", value)
		return "aggregated_ogms", boolToOpenWrtOption(enabled), err
	case "Fragmentation":
		enabled, err := boolValue("Fragmentation", value)
		return "fragmentation", boolToOpenWrtOption(enabled), err
	case "GatewayMode":
		mode, err := enumString("GatewayMode", value, "off", "client", "server")
		return "gw_mode", mode, err
	case "GatewayBandwidth":
		bandwidth, err := boundedNonEmptyString("GatewayBandwidth", value, 64)
		return "gw_bandwidth", bandwidth, err
	case "GatewaySelectionClass":
		class, err := boundedUintString("GatewaySelectionClass", value, 0, 256)
		return "gw_sel_class", class, err
	case "OrigInterval":
		interval, err := boundedUintString("OrigInterval", value, 1, 0)
		return "orig_interval", interval, err
	case "BridgeLoopAvoidance":
		enabled, err := boolValue("BridgeLoopAvoidance", value)
		return "bridge_loop_avoidance", boolToOpenWrtOption(enabled), err
	case "DistributedARPTable":
		enabled, err := boolValue("DistributedARPTable", value)
		return "distributed_arp_table", boolToOpenWrtOption(enabled), err
	case "MulticastMode":
		enabled, err := boolValue("MulticastMode", value)
		return "multicast_mode", boolToOpenWrtOption(enabled), err
	case "MulticastFanout":
		fanout, err := boundedUintString("MulticastFanout", value, 0, 0)
		return "multicast_fanout", fanout, err
	case "HopPenalty":
		penalty, err := boundedUintString("HopPenalty", value, 0, 255)
		return "hop_penalty", penalty, err
	case "APIsolation":
		enabled, err := boolValue("APIsolation", value)
		return "ap_isolation", boolToOpenWrtOption(enabled), err
	case "IsolationMark":
		mark := value.AsString()
		if !validIsolationMark(mark) {
			return "", "", fmt.Errorf("wusp openwrt mesh IsolationMark must be 0x<value>/0x<mask>")
		}
		return "isolation_mark", mark, nil
	default:
		return "", "", wusp.ErrUSPPathUnsupported
	}
}

func boundedNonEmptyString(name string, value wusp.Value, maxLen int) (string, error) {
	text := strings.TrimSpace(value.AsString())
	if text == "" {
		return "", fmt.Errorf("wusp openwrt mesh %s must not be empty", name)
	}
	if maxLen > 0 && len(text) > maxLen {
		return "", fmt.Errorf("wusp openwrt mesh %s length must be <= %d", name, maxLen)
	}
	return text, nil
}

func boolValue(name string, value wusp.Value) (bool, error) {
	switch value.Tag {
	case wusp.TagTrue:
		return true, nil
	case wusp.TagFalse:
		return false, nil
	default:
		return false, fmt.Errorf("wusp openwrt mesh %s must be boolean", name)
	}
}

func enumString(name string, value wusp.Value, allowed ...string) (string, error) {
	text := strings.TrimSpace(value.AsString())
	for _, candidate := range allowed {
		if text == candidate {
			return text, nil
		}
	}
	return "", fmt.Errorf("wusp openwrt mesh %s=%q is unsupported", name, text)
}

func boundedUintString(name string, value wusp.Value, min, max uint64) (string, error) {
	text := strings.TrimSpace(wusp.ValueToString(value))
	parsed, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return "", fmt.Errorf("wusp openwrt mesh %s must be an unsigned integer", name)
	}
	if parsed < min || (max > 0 && parsed > max) {
		if max > 0 {
			return "", fmt.Errorf("wusp openwrt mesh %s must be between %d and %d", name, min, max)
		}
		return "", fmt.Errorf("wusp openwrt mesh %s must be >= %d", name, min)
	}
	return strconv.FormatUint(parsed, 10), nil
}

func boundedIntString(name string, value wusp.Value, min, max int64) (string, error) {
	text := strings.TrimSpace(wusp.ValueToString(value))
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return "", fmt.Errorf("wusp openwrt mesh %s must be an integer", name)
	}
	if parsed < min || parsed > max {
		return "", fmt.Errorf("wusp openwrt mesh %s must be between %d and %d", name, min, max)
	}
	return strconv.FormatInt(parsed, 10), nil
}

func validIsolationMark(value string) bool {
	left, right, ok := strings.Cut(strings.TrimSpace(value), "/")
	if !ok {
		return false
	}
	if !strings.HasPrefix(left, "0x") || !strings.HasPrefix(right, "0x") {
		return false
	}
	if len(left) < 3 || len(left) > 10 || len(right) < 3 || len(right) > 10 {
		return false
	}
	if _, err := strconv.ParseUint(left[2:], 16, 32); err != nil {
		return false
	}
	if _, err := strconv.ParseUint(right[2:], 16, 32); err != nil {
		return false
	}
	return true
}

func boolToOpenWrtOption(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func statusFromDisabledOption(value string) string {
	if parseOpenWrtBool(value, false) {
		return "Disabled"
	}
	return "Running"
}

func upDownFromDisabledOption(value string) string {
	if parseOpenWrtBool(value, false) {
		return "Down"
	}
	return "Up"
}

func normalizeOpenWrtMeshEncryption(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case value == "":
		return "unknown"
	case value == "none" || value == "sae" || value == "psk2" || value == "psk-mixed":
		return value
	case strings.Contains(value, "sae"):
		return "sae"
	case strings.Contains(value, "psk2"):
		return "psk2"
	case strings.Contains(value, "psk"):
		return "psk-mixed"
	default:
		return "unknown"
	}
}

func setStringOption(msg *wusp.Message, path, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		msg.Set(path, wusp.String(value))
	}
}

func setBoolOption(msg *wusp.Message, path, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		msg.Set(path, wusp.Bool(parseOpenWrtBool(value, false)))
	}
}

func setUintOption(msg *wusp.Message, path, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err == nil {
		msg.Set(path, wusp.Uint(parsed))
	}
}

func setIntOption(msg *wusp.Message, path, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err == nil {
		msg.Set(path, wusp.Int(parsed))
	}
}
