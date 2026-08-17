package platforms

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wusp"
)

// appendLinuxWiFiFields is shared by the generic Linux backend and Linux CPE
// images which expose standard nl80211/hostapd facilities but no OpenWrt
// release marker. An inventory failure is non-authoritative: it emits no WiFi
// counts, allowing the controller to retain the prior successful section.
func appendLinuxWiFiFields(ctx context.Context, msg *wusp.Message, commandRunner CommandRunner, now time.Time) error {
	interfaces, inventoryErr := iwinfo.RuntimeInterfaces()
	if inventoryErr != nil {
		appendGenericLinuxHosts(msg, nil, commandRunner, now)
		return inventoryErr
	}
	stationByInterface := make(map[string]linuxStationCollection)
	for _, iface := range interfaces {
		if iface.Mode != "ap" && iface.Mode != "ap-vlan" {
			continue
		}
		stationByInterface[iface.Name] = collectLinuxStations(ctx, iface.Name, commandRunner)
	}
	wifiHosts := appendLinuxWiFiInventory(msg, interfaces, stationByInterface, now)
	appendGenericLinuxHosts(msg, wifiHosts, commandRunner, now)
	return nil
}

func appendLinuxWiFiInventory(msg *wusp.Message, interfaces []iwinfo.WirelessInterface, stationByInterface map[string]linuxStationCollection, now time.Time) map[string]string {
	sort.Slice(interfaces, func(i, j int) bool {
		if interfaces[i].PHY == interfaces[j].PHY {
			return interfaces[i].Name < interfaces[j].Name
		}
		return interfaces[i].PHY < interfaces[j].PHY
	})

	byPHY := make(map[int][]iwinfo.WirelessInterface)
	phyOrder := make([]int, 0)
	for _, iface := range interfaces {
		if _, exists := byPHY[iface.PHY]; !exists {
			phyOrder = append(phyOrder, iface.PHY)
		}
		byPHY[iface.PHY] = append(byPHY[iface.PHY], iface)
	}
	sort.Ints(phyOrder)

	ssidCount, apCount, endpointCount := 0, 0, 0
	wifiHosts := make(map[string]string)
	for radioPosition, phy := range phyOrder {
		radioIndex := radioPosition + 1
		phyInterfaces := byPHY[phy]
		radioPath := fmt.Sprintf("Device.WiFi.Radio.%d.", radioIndex)
		radioUp := false
		frequency, width := 0, ""
		for _, iface := range phyInterfaces {
			radioUp = radioUp || iface.Up
			if frequency == 0 && iface.Frequency > 0 {
				frequency = iface.Frequency
			}
			if width == "" {
				width = iface.ChannelWidth
			}
		}
		appendField(msg, radioPath+"Enable", wusp.Bool(radioUp))
		appendField(msg, radioPath+"Status", wusp.String(wifiStatusValue(radioUp, radioUp)))
		appendField(msg, radioPath+"Name", wusp.String(fmt.Sprintf("phy%d", phy)))
		if band := wifiBandTR181FromFrequency(frequency); band != "" {
			appendField(msg, radioPath+"OperatingFrequencyBand", wusp.String(band))
		}
		if channel := wifiChannelFromFrequency(frequency); channel > 0 {
			appendField(msg, radioPath+"Channel", wusp.Uint(uint64(channel)))
		}
		if width != "" {
			appendField(msg, radioPath+"OperatingChannelBandwidth", wusp.String(width+"MHz"))
			appendField(msg, radioPath+"CurrentOperatingChannelBandwidth", wusp.String(width+"MHz"))
		}

		primaryAP := ""
		for _, iface := range phyInterfaces {
			if iface.Mode == "ap" {
				primaryAP = iface.Name
				break
			}
		}
		if primaryAP == "" {
			for _, iface := range phyInterfaces {
				if iface.Mode == "ap-vlan" {
					primaryAP = iface.Name
					break
				}
			}
		}

		for _, iface := range phyInterfaces {
			// AP-VLAN links represent dynamically assigned stations for a parent
			// BSS, not independent SSIDs. Their station dumps are merged below.
			if iface.Mode == "ap-vlan" && primaryAP != iface.Name {
				continue
			}
			ssidCount++
			ssidPath := fmt.Sprintf("Device.WiFi.SSID.%d.", ssidCount)
			appendField(msg, ssidPath+"Enable", wusp.Bool(iface.Up))
			appendField(msg, ssidPath+"Status", wusp.String(wifiStatusValue(iface.Up, iface.Up)))
			appendField(msg, ssidPath+"Name", wusp.String(iface.Name))
			appendField(msg, ssidPath+"LowerLayers", wusp.List(wusp.String(radioPath)))
			if len(iface.HardwareAddr) == 6 {
				appendField(msg, ssidPath+"BSSID", wusp.MAC(iface.HardwareAddr))
			}
			if info, err := iwinfo.GetInfo(iface.Name); err == nil && info != nil && strings.TrimSpace(info.SSID) != "" {
				appendField(msg, ssidPath+"SSID", wusp.String(strings.TrimSpace(info.SSID)))
			}

			switch iface.Mode {
			case "ap", "ap-vlan":
				apCount++
				apPath := fmt.Sprintf("Device.WiFi.AccessPoint.%d.", apCount)
				appendField(msg, apPath+"Enable", wusp.Bool(iface.Up))
				appendField(msg, apPath+"Status", wusp.String(wifiAccessPointStatusValue(iface.Up, iface.Up)))
				appendField(msg, apPath+"SSIDReference", wusp.String(ssidPath))
				collection := stationByInterface[iface.Name]
				for _, vlan := range phyInterfaces {
					if vlan.Mode == "ap-vlan" && vlan.Name != iface.Name {
						vlanCollection := stationByInterface[vlan.Name]
						collection.Stations = mergeWiFiAssociations(collection.Stations, vlanCollection.Stations)
						collection.Succeeded = collection.Succeeded || vlanCollection.Succeeded
						collection.Attempted = append(collection.Attempted, vlanCollection.Attempted...)
						collection.Errors = append(collection.Errors, vlanCollection.Errors...)
					}
				}
				if collection.Succeeded {
					appendField(msg, apPath+"AssociatedDeviceNumberOfEntries", wusp.Uint(uint64(len(collection.Stations))))
					for stationIndex, station := range collection.Stations {
						stationPath := fmt.Sprintf("%sAssociatedDevice.%d.", apPath, stationIndex+1)
						appendWiFiAssociatedDeviceFields(msg, stationPath, station, now)
						wifiHosts[strings.ToLower(station.MAC.String())] = stationPath
					}
				}
			case "station":
				endpointCount++
			}
		}
	}

	appendField(msg, "Device.WiFi.RadioNumberOfEntries", wusp.Uint(uint64(len(phyOrder))))
	appendField(msg, "Device.WiFi.SSIDNumberOfEntries", wusp.Uint(uint64(ssidCount)))
	appendField(msg, "Device.WiFi.AccessPointNumberOfEntries", wusp.Uint(uint64(apCount)))
	appendField(msg, "Device.WiFi.EndPointNumberOfEntries", wusp.Uint(uint64(endpointCount)))
	return wifiHosts
}

type linuxStationCollection struct {
	Stations  []iwinfo.AssocEntry
	Attempted []string
	Succeeded bool
	Errors    []string
}

func collectLinuxStations(ctx context.Context, ifName string, commandRunner CommandRunner) linuxStationCollection {
	collection := linuxStationCollection{}
	mergeSuccess := func(source string, stations []iwinfo.AssocEntry, err error) {
		collection.Attempted = append(collection.Attempted, source)
		if err != nil {
			collection.Errors = append(collection.Errors, source+": "+err.Error())
			return
		}
		collection.Succeeded = true
		collection.Stations = mergeWiFiAssociations(collection.Stations, stations)
	}

	if commandRunner != nil {
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		data, err := commandRunner(callCtx, "ubus", "call", "hostapd."+ifName, "get_clients")
		cancel()
		if err == nil {
			var payload openWrtHostapdClients
			if decodeErr := json.Unmarshal(data, &payload); decodeErr != nil {
				err = decodeErr
			} else if payload.Clients == nil {
				err = fmt.Errorf("missing clients object")
			}
			mergeSuccess("hostapd-ubus", associationsFromHostapdPayload(payload), err)
		} else {
			mergeSuccess("hostapd-ubus", nil, err)
		}

		callCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		data, err = commandRunner(callCtx, "hostapd_cli", "-i", ifName, "all_sta")
		cancel()
		if err == nil && strings.EqualFold(strings.TrimSpace(string(data)), "FAIL") {
			err = fmt.Errorf("hostapd_cli returned FAIL")
		}
		if err == nil {
			mergeSuccess("hostapd-cli", parseHostapdCLIStations(string(data)), nil)
		} else {
			mergeSuccess("hostapd-cli", nil, err)
		}

		callCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		data, err = commandRunner(callCtx, "iw", "dev", ifName, "station", "dump")
		cancel()
		if err == nil {
			mergeSuccess("iw", parseIWStationDump(string(data)), nil)
		} else {
			mergeSuccess("iw", nil, err)
		}

		callCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		data, err = commandRunner(callCtx, "iwinfo", ifName, "assoclist")
		cancel()
		if err == nil {
			mergeSuccess("iwinfo-cli", parseIWInfoCLIStations(string(data)), nil)
		} else {
			mergeSuccess("iwinfo-cli", nil, err)
		}
	}
	stations, err := iwinfo.GetAssocList(ifName)
	mergeSuccess("nl80211", stations, err)

	log.Printf("[USP] wifi_collection_summary interface=%q sources_attempted=%q successful=%t selected_station_count=%d errors=%q",
		ifName, strings.Join(collection.Attempted, ","), collection.Succeeded, len(collection.Stations), strings.Join(collection.Errors, "; "))
	return collection
}

func parseHostapdCLIStations(output string) []iwinfo.AssocEntry {
	var entries []iwinfo.AssocEntry
	var current *iwinfo.AssocEntry
	flush := func() {
		if current != nil && validClientMAC(current.MAC.String()) != nil {
			entries = append(entries, *current)
		}
		current = nil
	}
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if mac := validClientMAC(line); mac != nil {
			flush()
			current = &iwinfo.AssocEntry{MAC: mac}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "flags":
			current.AuthenticationKnown = true
			current.Authenticated = strings.Contains(value, "[AUTHORIZED]") || strings.Contains(value, "[AUTH]")
		case "signal":
			if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
				current.Signal, current.SignalKnown = boundedWiFiDBM(parsed), true
			}
		case "connected_time":
			current.ConnectedTime, current.ConnectedTimeKnown = parseCLIUint32(value)
		case "inactive_msec":
			current.Inactive, current.InactiveKnown = parseCLIUint32(value)
		case "rx_bytes":
			current.RxBytes, current.RxBytesKnown = parseCLIUint64(value)
		case "tx_bytes":
			current.TxBytes, current.TxBytesKnown = parseCLIUint64(value)
		case "rx_packets":
			current.RxPackets, current.RxPacketsKnown = parseCLIUint32(value)
		case "tx_packets":
			current.TxPackets, current.TxPacketsKnown = parseCLIUint32(value)
		case "tx_retries":
			current.TxRetries, current.TxRetriesKnown = parseCLIUint32(value)
		case "tx_failed":
			current.TxFailed, current.TxFailedKnown = parseCLIUint32(value)
		}
	}
	flush()
	return entries
}

func parseIWStationDump(output string) []iwinfo.AssocEntry {
	var entries []iwinfo.AssocEntry
	var current *iwinfo.AssocEntry
	flush := func() {
		if current != nil && validClientMAC(current.MAC.String()) != nil {
			entries = append(entries, *current)
		}
		current = nil
	}
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "Station ") {
			flush()
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if mac := validClientMAC(fields[1]); mac != nil {
					current = &iwinfo.AssocEntry{MAC: mac}
				}
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "signal", "signal avg":
			fields := strings.Fields(value)
			if len(fields) > 0 {
				if parsed, err := strconv.Atoi(fields[0]); err == nil {
					if strings.TrimSpace(key) == "signal avg" {
						current.SignalAvg, current.SignalAvgKnown = boundedWiFiDBM(parsed), true
					} else {
						current.Signal, current.SignalKnown = boundedWiFiDBM(parsed), true
					}
				}
			}
		case "inactive time":
			current.Inactive, current.InactiveKnown = parseCLIUint32(value)
		case "connected time":
			current.ConnectedTime, current.ConnectedTimeKnown = parseCLIUint32(value)
		case "rx bytes":
			current.RxBytes, current.RxBytesKnown = parseCLIUint64(value)
		case "tx bytes":
			current.TxBytes, current.TxBytesKnown = parseCLIUint64(value)
		case "rx packets":
			current.RxPackets, current.RxPacketsKnown = parseCLIUint32(value)
		case "tx packets":
			current.TxPackets, current.TxPacketsKnown = parseCLIUint32(value)
		case "tx retries":
			current.TxRetries, current.TxRetriesKnown = parseCLIUint32(value)
		case "tx failed":
			current.TxFailed, current.TxFailedKnown = parseCLIUint32(value)
		case "rx bitrate":
			current.RxRate, current.RxRateKnown = parseIWRateKbit(value)
		case "tx bitrate":
			current.TxRate, current.TxRateKnown = parseIWRateKbit(value)
		}
	}
	flush()
	return entries
}

func parseIWInfoCLIStations(output string) []iwinfo.AssocEntry {
	var entries []iwinfo.AssocEntry
	var current *iwinfo.AssocEntry
	flush := func() {
		if current != nil && validClientMAC(current.MAC.String()) != nil {
			entries = append(entries, *current)
		}
		current = nil
	}
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if mac := validClientMAC(fields[0]); mac != nil {
			flush()
			current = &iwinfo.AssocEntry{MAC: mac}
			dbmValues := make([]int, 0, 2)
			for index := 1; index+1 < len(fields); index++ {
				if strings.EqualFold(strings.Trim(fields[index+1], ","), "dBm") {
					if parsed, err := strconv.Atoi(strings.Trim(fields[index], ",")); err == nil {
						dbmValues = append(dbmValues, parsed)
					}
				}
			}
			if len(dbmValues) > 0 {
				current.Signal, current.SignalKnown = boundedWiFiDBM(dbmValues[0]), true
			}
			if len(dbmValues) > 1 {
				current.Noise, current.NoiseKnown = boundedWiFiDBM(dbmValues[1]), true
			}
			continue
		}
		if current == nil || len(fields) < 3 {
			continue
		}
		switch strings.TrimSuffix(strings.ToUpper(fields[0]), ":") {
		case "RX":
			current.RxRate, current.RxRateKnown = parseIWRateKbit(strings.Join(fields[1:3], " "))
		case "TX":
			current.TxRate, current.TxRateKnown = parseIWRateKbit(strings.Join(fields[1:3], " "))
		}
	}
	flush()
	return entries
}

func parseIWRateKbit(value string) (uint32, bool) {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return 0, false
	}
	rate, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || rate < 0 {
		return 0, false
	}
	switch strings.ToLower(strings.Trim(fields[1], ",;")) {
	case "mbit/s", "mbps":
		rate *= 1000
	case "gbit/s", "gbps":
		rate *= 1000000
	case "kbit/s", "kbps":
	default:
		return 0, false
	}
	if rate > float64(^uint32(0)) {
		return ^uint32(0), true
	}
	return uint32(rate), true
}

func parseCLIUint64(value string) (uint64, bool) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 {
		return 0, false
	}
	parsed, err := strconv.ParseUint(fields[0], 10, 64)
	return parsed, err == nil
}

func parseCLIUint32(value string) (uint32, bool) {
	parsed, ok := parseCLIUint64(value)
	if !ok {
		return 0, false
	}
	if parsed > uint64(^uint32(0)) {
		return ^uint32(0), true
	}
	return uint32(parsed), true
}

func appendGenericLinuxHosts(msg *wusp.Message, wifiHosts map[string]string, commandRunner CommandRunner, now time.Time) {
	hosts := make(map[string]*openWrtLANHost)
	ensure := func(macText string) *openWrtLANHost {
		mac := validClientMAC(macText)
		if mac == nil {
			return nil
		}
		key := strings.ToLower(mac.String())
		if hosts[key] == nil {
			hosts[key] = &openWrtLANHost{mac: mac}
		}
		return hosts[key]
	}
	for macText, stationPath := range wifiHosts {
		if host := ensure(macText); host != nil {
			host.associatedDevice = stationPath
			host.interfaceType = "Wi-Fi"
			host.active = true
		}
	}
	interfacePaths := ipInterfacePathByName()
	if neighbors, err := readRouteNeighbors(); err == nil {
		for _, neighbor := range neighbors {
			if host := ensure(neighbor.MAC.String()); host != nil {
				addHostIP(host, neighbor.IP.String())
				host.interfaceName = neighbor.InterfaceName
				host.layer3Interface = interfacePaths[neighbor.InterfaceName]
				if host.interfaceType == "" {
					host.interfaceType = hostInterfaceType(neighbor.InterfaceName)
				}
				host.active = host.active || neighbor.Active
			}
		}
	} else {
		logCollectorError("linux.hosts.rtnetlink", err)
	}
	if data, err := os.ReadFile("/proc/net/arp"); err == nil {
		for lineIndex, line := range strings.Split(string(data), "\n") {
			if lineIndex == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			host := ensure(fields[3])
			if host == nil {
				continue
			}
			addHostIP(host, fields[0])
			host.interfaceName = fields[5]
			host.layer3Interface = interfacePaths[fields[5]]
			if host.interfaceType == "" {
				host.interfaceType = hostInterfaceType(fields[5])
			}
			flags, _ := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(fields[2]), "0x"), 16, 32)
			host.active = host.active || flags&0x2 != 0
		}
	}
	if commandRunner != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		data, err := commandRunner(ctx, "ip", "neigh", "show")
		cancel()
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 5 {
					continue
				}
				devIndex, lladdrIndex := -1, -1
				for index, field := range fields {
					switch field {
					case "dev":
						devIndex = index
					case "lladdr":
						lladdrIndex = index
					}
				}
				if lladdrIndex < 0 || lladdrIndex+1 >= len(fields) {
					continue
				}
				host := ensure(fields[lladdrIndex+1])
				if host == nil {
					continue
				}
				addHostIP(host, fields[0])
				if devIndex >= 0 && devIndex+1 < len(fields) {
					host.interfaceName = fields[devIndex+1]
					host.layer3Interface = interfacePaths[host.interfaceName]
					if host.interfaceType == "" {
						host.interfaceType = hostInterfaceType(host.interfaceName)
					}
				}
				state := strings.ToUpper(fields[len(fields)-1])
				host.active = host.active || (state != "FAILED" && state != "INCOMPLETE")
			}
		}
	}
	for _, leasePath := range []string{"/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases", "/var/lib/dnsmasq/dnsmasq.leases"} {
		data, err := os.ReadFile(filepath.Clean(leasePath))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			host := ensure(fields[1])
			if host == nil {
				continue
			}
			addHostIP(host, fields[2])
			if fields[3] != "*" {
				host.hostname = fields[3]
			}
			host.addressSource = "DHCP"
			host.active = true
			expiry, err := strconv.ParseInt(fields[0], 10, 64)
			switch {
			case err != nil:
				host.leaseTimeRemaining = 0
			case expiry == 0:
				host.leaseTimeRemaining = -1
			case expiry > now.Unix():
				host.leaseTimeRemaining = expiry - now.Unix()
			}
		}
		break
	}

	out := make([]*openWrtLANHost, 0, len(hosts))
	for _, host := range hosts {
		sort.Slice(host.ipv4, func(i, j int) bool { return bytesCompareIP(host.ipv4[i], host.ipv4[j]) < 0 })
		sort.Slice(host.ipv6, func(i, j int) bool { return bytesCompareIP(host.ipv6[i], host.ipv6[j]) < 0 })
		out = append(out, host)
	}
	sort.Slice(out, func(i, j int) bool { return strings.Compare(out[i].mac.String(), out[j].mac.String()) < 0 })
	appendLANHostFields(msg, out)
}

func wifiChannelFromFrequency(frequency int) int {
	switch {
	case frequency == 2484:
		return 14
	case frequency >= 2412 && frequency <= 2472:
		return (frequency - 2407) / 5
	case frequency >= 5000 && frequency <= 5895:
		return (frequency - 5000) / 5
	case frequency >= 5955 && frequency <= 7115:
		return (frequency - 5950) / 5
	default:
		return 0
	}
}

func wifiBandTR181FromFrequency(frequency int) string {
	switch {
	case frequency >= 5925:
		return "6GHz"
	case frequency >= 4900:
		return "5GHz"
	case frequency >= 2300:
		return "2.4GHz"
	default:
		return ""
	}
}

func operatingClassForFrequency(frequency int) int {
	channel := wifiChannelFromFrequency(frequency)
	switch {
	case frequency >= 5955:
		return 131
	case frequency >= 5745:
		return 124
	case frequency >= 5500:
		return 121
	case frequency >= 5180:
		return 115
	case channel == 14:
		return 82
	case channel > 0:
		return 81
	default:
		return 0
	}
}

func validRuntimeMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 && validClientMAC(mac.String()) != nil
}
