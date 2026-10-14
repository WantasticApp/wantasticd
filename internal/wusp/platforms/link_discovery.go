package platforms

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/linkdiscovery"
	"wantastic-agent/internal/wusp"
)

type lldpDeviceObservation struct {
	chassisSubtype uint8
	chassisID      string
	ports          []linkdiscovery.LLDPNeighbor
	organizations  []linkdiscovery.OrganizationTLV
}

// appendLinkDiscoveryFields publishes only after the passive listener has
// become authoritative. Before then no count is emitted, so the controller
// retains a previously successful LLDP snapshot.
func appendLinkDiscoveryFields(msg *wusp.Message, snapshot linkdiscovery.Snapshot, wifiInterfaces map[string]bool) {
	if msg == nil || !snapshot.LLDPReady {
		return
	}
	byChassis := make(map[string]*lldpDeviceObservation)
	keys := make([]string, 0)
	for _, neighbor := range snapshot.LLDP {
		key := fmt.Sprintf("%d\x00%s", neighbor.ChassisIDSubtype, strings.ToLower(strings.TrimSpace(neighbor.ChassisID)))
		if strings.Trim(key, "0\x00 ") == "" {
			continue
		}
		device := byChassis[key]
		if device == nil {
			device = &lldpDeviceObservation{chassisSubtype: neighbor.ChassisIDSubtype, chassisID: neighbor.ChassisID}
			byChassis[key] = device
			keys = append(keys, key)
		}
		device.ports = append(device.ports, neighbor)
		for _, organization := range neighbor.Organizations {
			if !containsOrganization(device.organizations, organization) {
				device.organizations = append(device.organizations, organization)
			}
		}
	}
	sort.Strings(keys)
	hostByIdentity := lldpHostReferences(msg)
	interfacePaths := ipInterfacePathByName()
	appendField(msg, "Device.LLDP.Discovery.DeviceNumberOfEntries", wusp.Uint(uint64(len(keys))))
	for devicePosition, key := range keys {
		device := byChassis[key]
		prefix := fmt.Sprintf("Device.LLDP.Discovery.Device.%d.", devicePosition+1)
		appendField(msg, prefix+"ChassisIDSubtype", wusp.Uint(uint64(device.chassisSubtype)))
		appendField(msg, prefix+"ChassisID", wusp.String(truncateUTF8Bytes(device.chassisID, 255)))
		if len(device.ports) > 0 {
			if path := interfacePaths[device.ports[0].LocalInterface]; path != "" {
				appendField(msg, prefix+"Interface", wusp.String(path))
			}
		}
		if hosts := lldpMatchingHostRefs(device, hostByIdentity); len(hosts) > 0 {
			items := make([]wusp.Value, 0, len(hosts))
			for _, host := range hosts {
				items = append(items, wusp.String(host))
			}
			appendField(msg, prefix+"Host", wusp.List(items...))
		}
		sort.Slice(device.ports, func(i, j int) bool {
			left := device.ports[i].LocalInterface + "\x00" + device.ports[i].PortID
			right := device.ports[j].LocalInterface + "\x00" + device.ports[j].PortID
			return left < right
		})
		appendField(msg, prefix+"PortNumberOfEntries", wusp.Uint(uint64(len(device.ports))))
		for portPosition, port := range device.ports {
			portPrefix := fmt.Sprintf("%sPort.%d.", prefix, portPosition+1)
			appendField(msg, portPrefix+"PortIDSubtype", wusp.Uint(uint64(port.PortIDSubtype)))
			appendField(msg, portPrefix+"PortID", wusp.String(truncateUTF8Bytes(port.PortID, 255)))
			ttl := port.TTL / time.Second
			if ttl < 0 {
				ttl = 0
			} else if ttl > 65535 {
				ttl = 65535
			}
			appendField(msg, portPrefix+"TTL", wusp.Uint(uint64(ttl)))
			if port.PortDescription != "" {
				appendField(msg, portPrefix+"PortDescription", wusp.String(truncateUTF8Bytes(port.PortDescription, 255)))
			}
			if len(port.SourceMAC) == 6 {
				appendField(msg, portPrefix+"MACAddressList", wusp.List(wusp.String(port.SourceMAC.String())))
			}
			appendField(msg, portPrefix+"LastUpdate", wusp.Time(port.LastUpdate.UTC()))
			if interfaceType := lldpInterfaceType(port.LocalInterface, wifiInterfaces); interfaceType != 0 {
				appendField(msg, portPrefix+"LinkInformation.InterfaceType", wusp.Uint(uint64(interfaceType)))
			}
		}
		appendField(msg, prefix+"DeviceInformation.VendorSpecificNumberOfEntries", wusp.Uint(uint64(len(device.organizations))))
		for organizationPosition, organization := range device.organizations {
			orgPrefix := fmt.Sprintf("%sDeviceInformation.VendorSpecific.%d.", prefix, organizationPosition+1)
			appendField(msg, orgPrefix+"OrganizationCode", wusp.String(strings.ToUpper(organization.OUI)))
			appendField(msg, orgPrefix+"InformationType", wusp.Uint(uint64(organization.Subtype)))
			data := organization.Data
			if len(data) > 124 {
				data = data[:124]
			}
			appendField(msg, orgPrefix+"Information", wusp.String(hex.EncodeToString(data)))
		}
	}
}

func truncateUTF8Bytes(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	if len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func containsOrganization(values []linkdiscovery.OrganizationTLV, candidate linkdiscovery.OrganizationTLV) bool {
	for _, value := range values {
		if strings.EqualFold(value.OUI, candidate.OUI) && value.Subtype == candidate.Subtype && hex.EncodeToString(value.Data) == hex.EncodeToString(candidate.Data) {
			return true
		}
	}
	return false
}

func lldpInterfaceType(ifName string, wifiInterfaces map[string]bool) uint32 {
	if openWrtWiFiInterfaceMatch(ifName, wifiInterfaces) {
		return 71
	}
	lower := strings.ToLower(strings.TrimSpace(ifName))
	if strings.HasPrefix(lower, "eth") || strings.HasPrefix(lower, "en") || strings.HasPrefix(lower, "lan") {
		return 6
	}
	return 0
}

func openWrtWiFiInterfaceMatch(ifName string, wifiInterfaces map[string]bool) bool {
	ifName = strings.TrimSpace(ifName)
	if wifiInterfaces[ifName] {
		return true
	}
	for known := range wifiInterfaces {
		if known != "" && strings.HasPrefix(ifName, known+".") {
			return true
		}
	}
	return false
}

func lldpHostReferences(msg *wusp.Message) map[string]string {
	refs := make(map[string]string)
	for _, field := range msg.Fields {
		path := strings.TrimSpace(field.Path)
		if !strings.HasPrefix(path, "Device.Hosts.Host.") {
			continue
		}
		parts := strings.Split(path, ".")
		if len(parts) < 5 {
			continue
		}
		hostPath := strings.Join(parts[:4], ".") + "."
		leaf := strings.ToLower(parts[len(parts)-1])
		if leaf == "physaddress" || leaf == "ipaddress" {
			value := strings.ToLower(strings.TrimSpace(field.Val.AsString()))
			if value != "" {
				refs[value] = hostPath
			}
		}
	}
	return refs
}

func lldpMatchingHostRefs(device *lldpDeviceObservation, hostByIdentity map[string]string) []string {
	seen := make(map[string]bool)
	add := func(value string) {
		if ref := hostByIdentity[strings.ToLower(strings.TrimSpace(value))]; ref != "" {
			seen[ref] = true
		}
	}
	add(device.chassisID)
	for _, port := range device.ports {
		add(port.SourceMAC.String())
		for _, ip := range port.ManagementAddresses {
			add(ip.String())
		}
	}
	refs := make([]string, 0, len(seen))
	for ref := range seen {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

func runtimeWiFiInterfaceSet() map[string]bool {
	set := make(map[string]bool)
	ifaces, _ := iwinfo.RuntimeInterfaces()
	for _, iface := range ifaces {
		set[iface.Name] = true
	}
	return set
}

func (b *OpenWrtBackend) openWrtWiFiInterfaceSet() map[string]bool {
	set := make(map[string]bool)
	for device, radio := range b.openWrtWirelessRadios() {
		if b.existingWiFiIfName(device) != "" {
			set[device] = true
		}
		for _, iface := range radio.Interfaces {
			if iface.IfName != "" {
				set[iface.IfName] = true
			}
		}
	}
	return set
}

func mergeMNDPHosts(hosts map[string]*openWrtLANHost, snapshot linkdiscovery.Snapshot) {
	if !snapshot.MNDPReady {
		return
	}
	for _, neighbor := range snapshot.MNDP {
		if len(neighbor.MAC) != 6 {
			continue
		}
		key := strings.ToLower(neighbor.MAC.String())
		host := hosts[key]
		if host == nil {
			host = &openWrtLANHost{mac: append(net.HardwareAddr(nil), neighbor.MAC...)}
			hosts[key] = host
		}
		if host.hostname == "" {
			host.hostname = strings.TrimSpace(neighbor.Identity)
		}
		if host.interfaceName == "" {
			host.interfaceName = strings.TrimSpace(neighbor.LocalInterface)
		}
		for _, ip := range neighbor.IPv4 {
			addHostIP(host, ip.String())
		}
		for _, ip := range neighbor.IPv6 {
			addHostIP(host, ip.String())
		}
		if neighbor.SourceAddress != nil {
			addHostIP(host, neighbor.SourceAddress.String())
		}
		host.active = true
	}
}
