//go:build linux

package platforms

import (
	"fmt"
	"strings"

	"wantastic-agent/internal/wusp"
)

// collectMeshStatic detects mesh topology (EasyMesh, batman-adv, 802.11s)
// and populates TR-181 Device.WiFi.MultiAP.* and Device.WiFi.DataElements.* params.
//
// This uses the mesh detection from internal/stats (already pure Go — sysfs,
// ubus, netlink). The stats package remains the source of truth for mesh
// collection; this function maps the results to TR-181 paths.
func collectMeshStatic(msg *wusp.Message) {
	// Detect mesh type from sysfs/procfs
	protocol, role, topology := detectMeshTopology()
	if protocol == "" {
		return
	}

	// Device.WiFi.MultiAP
	msg.Set("Device.WiFi.MultiAP.Enable", wusp.Bool(true))
	msg.Set("Device.WiFi.MultiAP.Status", wusp.String("Enabled"))

	// Map protocol name to TR-181 MultiAP version hint
	switch {
	case strings.Contains(protocol, "easymesh"):
		msg.Set("Device.WiFi.MultiAP.X_WANTASTIC_Protocol", wusp.String("EasyMesh"))
	case strings.Contains(protocol, "batman"):
		msg.Set("Device.WiFi.MultiAP.X_WANTASTIC_Protocol", wusp.String("BATMAN-adv"))
	case strings.Contains(protocol, "802.11s"):
		msg.Set("Device.WiFi.MultiAP.X_WANTASTIC_Protocol", wusp.String("802.11s"))
	default:
		msg.Set("Device.WiFi.MultiAP.X_WANTASTIC_Protocol", wusp.String(protocol))
	}

	if role != "" {
		isController := role == "controller" || role == "center"
		msg.Set("Device.WiFi.MultiAP.APDeviceIsController", wusp.Bool(isController))
		msg.Set("Device.WiFi.MultiAP.X_WANTASTIC_Role", wusp.String(role))
	}

	// Flatten topology into Device.WiFi.DataElements.Network.Device.{n}
	if topology != nil {
		flattenMeshTopology(msg, topology, 0)
	}
}

// meshNode is a simplified mesh topology node.
type meshNode struct {
	name     string
	mac      string
	ip       string
	signal   int
	role     string
	children []*meshNode
}

// flattenMeshTopology writes mesh nodes as TR-181 DataElements devices.
func flattenMeshTopology(msg *wusp.Message, node *meshNode, index int) int {
	if node == nil {
		return index
	}
	index++
	prefix := fmt.Sprintf("Device.WiFi.DataElements.Network.Device.%d.", index)

	if node.mac != "" {
		msg.Set(prefix+"ID", wusp.String(node.mac))
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

// detectMeshTopology checks sysfs/procfs for mesh indicators.
// Returns protocol name, role, and root topology node.
func detectMeshTopology() (protocol, role string, root *meshNode) {
	// 1. EasyMesh — check for map-agent/controller presence
	for _, p := range []string{
		"/usr/sbin/map-agent",
		"/usr/sbin/map-controller",
		"/etc/config/multiap",
		"/var/run/ezmesh-agent-cmd.fifo",
		"/var/run/wsplcd.lock",
	} {
		if fileExists(p) {
			protocol = "easymesh"
			if strings.Contains(p, "controller") {
				role = "controller"
			} else {
				role = "agent"
			}
			return
		}
	}

	// 2. batman-adv — check sysfs
	if fileExists("/sys/class/net/bat0/mesh") {
		protocol = "batman-adv"
		root = collectBatmanTopologyFromSysfs()
		return
	}

	// 3. 802.11s — check for mesh point interfaces
	if ifaces := find80211sMeshInterfaces(); len(ifaces) > 0 {
		protocol = "802.11s"
		return
	}

	return "", "", nil
}

// collectBatmanTopologyFromSysfs reads batman-adv originators from debugfs.
func collectBatmanTopologyFromSysfs() *meshNode {
	root := &meshNode{name: "bat0", role: "gateway"}

	// Read originators from /sys/kernel/debug/batman_adv/bat0/originators
	data, err := readFileQuiet("/sys/kernel/debug/batman_adv/bat0/originators")
	if err != nil {
		return root
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "Originator") {
			continue
		}
		// Format: "mac TQ via_mac [iface]: ... "
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mac := strings.TrimRight(fields[0], "*")
		child := &meshNode{mac: mac}

		// Parse TQ (transmission quality) — batman's metric
		if len(fields) >= 2 {
			if strings.HasSuffix(fields[1], ")") {
				// "( 252)" format
				tqStr := strings.Trim(fields[1], "()")
				if tqStr == "" && len(fields) >= 3 {
					tqStr = strings.Trim(fields[2], "()")
				}
				var tq int
				fmt.Sscanf(tqStr, "%d", &tq)
				if tq > 0 {
					// Convert TQ (0-255) to approximate signal dBm
					child.signal = tqToSignal(tq)
				}
			}
		}
		root.children = append(root.children, child)
	}
	return root
}

func find80211sMeshInterfaces() []string {
	var ifaces []string
	entries, _ := readDirQuiet("/sys/class/net")
	for _, e := range entries {
		meshDir := "/sys/class/net/" + e.Name() + "/mesh"
		if fileExists(meshDir) {
			ifaces = append(ifaces, e.Name())
		}
	}
	return ifaces
}

func tqToSignal(tq int) int {
	// batman-adv TQ: 0-255 (255=perfect link)
	// Rough mapping: 255→-30dBm, 128→-65dBm, 0→-100dBm
	if tq <= 0 {
		return -100
	}
	return -100 + (tq * 70 / 255)
}

// fileExists is defined in platforms.go
