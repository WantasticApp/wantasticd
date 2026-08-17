package platforms

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/iwinfo"
	"wantastic-agent/internal/wusp"
)

const (
	wifiScanInterval   = 5 * time.Minute
	wifiScanDeadline   = 8 * time.Second
	wifiScanMaxBackoff = 30 * time.Minute
	wifiScanMaxBSS     = 64
)

type wifiPHYScanSnapshot struct {
	PHY         int
	Interface   string
	RadioMAC    net.HardwareAddr
	Width       string
	Entries     []iwinfo.ScanEntry
	Survey      map[int]iwinfo.SurveyEntry
	Timestamp   time.Time
	Duration    time.Duration
	LastAttempt time.Time
	LastError   string
}

type wifiScanState struct {
	interfaceName string
	radioMAC      net.HardwareAddr
	width         string
	entries       []iwinfo.ScanEntry
	survey        map[int]iwinfo.SurveyEntry
	timestamp     time.Time
	duration      time.Duration
	lastAttempt   time.Time
	nextAttempt   time.Time
	lastError     string
	failures      int
	scanning      bool
}

type wifiScanCoordinator struct {
	mu     sync.Mutex
	states map[int]*wifiScanState
	now    func() time.Time
	active func(context.Context, string) ([]iwinfo.ScanEntry, error)
	cached func(string) ([]iwinfo.ScanEntry, error)
}

var defaultWiFiScanCoordinator = &wifiScanCoordinator{
	states: make(map[int]*wifiScanState),
	now:    time.Now,
	active: iwinfo.ActiveScan,
	cached: iwinfo.CachedScan,
}

func (c *wifiScanCoordinator) snapshotsAndTrigger(interfaces []iwinfo.WirelessInterface) []wifiPHYScanSnapshot {
	if c == nil {
		return nil
	}
	now := c.now().UTC()
	byPHY := make(map[int][]iwinfo.WirelessInterface)
	phys := make([]int, 0)
	for _, iface := range interfaces {
		if strings.TrimSpace(iface.Name) == "" || iface.Mode == "ap-vlan" || iface.Mode == "monitor" {
			continue
		}
		if _, ok := byPHY[iface.PHY]; !ok {
			phys = append(phys, iface.PHY)
		}
		byPHY[iface.PHY] = append(byPHY[iface.PHY], iface)
	}
	sort.Ints(phys)

	c.mu.Lock()
	if c.states == nil {
		c.states = make(map[int]*wifiScanState)
	}
	for _, phy := range phys {
		candidates := byPHY[phy]
		selected := candidates[0]
		for _, candidate := range candidates {
			if candidate.Mode == "station" {
				selected = candidate
				break
			}
		}
		state := c.states[phy]
		if state == nil {
			state = &wifiScanState{}
			c.states[phy] = state
		}
		state.interfaceName = selected.Name
		state.radioMAC = append(net.HardwareAddr(nil), selected.HardwareAddr...)
		state.width = selected.ChannelWidth
		if !state.scanning && (state.nextAttempt.IsZero() || !now.Before(state.nextAttempt)) {
			state.scanning = true
			state.lastAttempt = now
			state.nextAttempt = now.Add(wifiScanInterval)
			go c.scanPHY(phy, selected.Name, ownBSSIDs(candidates))
		}
	}
	snapshots := make([]wifiPHYScanSnapshot, 0, len(phys))
	for _, phy := range phys {
		state := c.states[phy]
		if state == nil {
			continue
		}
		snapshots = append(snapshots, wifiPHYScanSnapshot{
			PHY:         phy,
			Interface:   state.interfaceName,
			RadioMAC:    append(net.HardwareAddr(nil), state.radioMAC...),
			Width:       state.width,
			Entries:     append([]iwinfo.ScanEntry(nil), state.entries...),
			Survey:      cloneSurveyByFrequency(state.survey),
			Timestamp:   state.timestamp,
			Duration:    state.duration,
			LastAttempt: state.lastAttempt,
			LastError:   state.lastError,
		})
	}
	c.mu.Unlock()
	return snapshots
}

func (c *wifiScanCoordinator) scanPHY(phy int, ifName string, own map[string]bool) {
	started := c.now().UTC()
	// Seed the process cache from the kernel cache once. This path still runs
	// asynchronously, so a USP Get never waits on netlink or RF work.
	if c.cached != nil {
		if entries, err := c.cached(ifName); err == nil && len(entries) > 0 {
			observed := started
			for _, entry := range entries {
				if entry.LastSeen > 0 && started.Add(-entry.LastSeen).Before(observed) {
					observed = started.Add(-entry.LastSeen)
				}
			}
			c.mu.Lock()
			if state := c.states[phy]; state != nil && state.timestamp.IsZero() {
				state.entries = normalizeScanEntries(entries, own)
				state.timestamp = observed
			}
			c.mu.Unlock()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), wifiScanDeadline)
	entries, err := c.active(ctx, ifName)
	cancel()
	var surveyByFrequency map[int]iwinfo.SurveyEntry
	if err == nil {
		if survey, surveyErr := iwinfo.GetSurvey(ifName); surveyErr == nil {
			surveyByFrequency = make(map[int]iwinfo.SurveyEntry, len(survey))
			for _, entry := range survey {
				if entry.Frequency > 0 {
					surveyByFrequency[int(entry.Frequency)] = entry
				}
			}
		}
	}
	completed := c.now().UTC()

	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.states[phy]
	if state == nil {
		return
	}
	state.scanning = false
	if err == nil {
		state.entries = normalizeScanEntries(entries, own)
		state.survey = surveyByFrequency
		state.timestamp = completed
		state.duration = completed.Sub(started)
		state.lastError = ""
		state.failures = 0
		state.nextAttempt = completed.Add(wifiScanInterval)
		return
	}
	state.lastError = err.Error()
	state.failures++
	backoff := wifiScanInterval
	for step := 1; step < state.failures && backoff < wifiScanMaxBackoff; step++ {
		backoff *= 2
	}
	if backoff > wifiScanMaxBackoff {
		backoff = wifiScanMaxBackoff
	}
	state.nextAttempt = completed.Add(backoff)
}

func cloneSurveyByFrequency(source map[int]iwinfo.SurveyEntry) map[int]iwinfo.SurveyEntry {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[int]iwinfo.SurveyEntry, len(source))
	for frequency, entry := range source {
		cloned[frequency] = entry
	}
	return cloned
}

func normalizeScanEntries(entries []iwinfo.ScanEntry, own map[string]bool) []iwinfo.ScanEntry {
	byBSSID := make(map[string]iwinfo.ScanEntry, len(entries))
	for _, entry := range entries {
		if !validRuntimeMAC(entry.BSSID) {
			continue
		}
		key := strings.ToLower(entry.BSSID.String())
		if own[key] {
			continue
		}
		if existing, ok := byBSSID[key]; !ok || entry.SignalDBM > existing.SignalDBM {
			entry.BSSID = append(net.HardwareAddr(nil), entry.BSSID...)
			byBSSID[key] = entry
		}
	}
	out := make([]iwinfo.ScanEntry, 0, len(byBSSID))
	for _, entry := range byBSSID {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SignalDBM == out[j].SignalDBM {
			return out[i].BSSID.String() < out[j].BSSID.String()
		}
		return out[i].SignalDBM > out[j].SignalDBM
	})
	if len(out) > wifiScanMaxBSS {
		out = out[:wifiScanMaxBSS]
	}
	return out
}

func ownBSSIDs(interfaces []iwinfo.WirelessInterface) map[string]bool {
	own := make(map[string]bool)
	for _, iface := range interfaces {
		if validRuntimeMAC(iface.HardwareAddr) {
			own[strings.ToLower(iface.HardwareAddr.String())] = true
		}
	}
	return own
}

// appendWiFiScanFields returns immediately with the last successful scan and
// schedules due RF work in the background. It must run after mesh topology so
// the local DataElements device can be resolved/appended without collisions.
func appendWiFiScanFields(msg *wusp.Message) error {
	interfaces, err := iwinfo.RuntimeInterfaces()
	if err != nil {
		return err
	}
	snapshots := defaultWiFiScanCoordinator.snapshotsAndTrigger(interfaces)
	available := snapshots[:0]
	for _, snapshot := range snapshots {
		age := time.Duration(0)
		if !snapshot.Timestamp.IsZero() {
			age = time.Since(snapshot.Timestamp)
			available = append(available, snapshot)
		}
		log.Printf("[USP] wifi_scan_summary phy=%d interface=%q successful=%t neighbor_count=%d scan_age=%q last_error=%q",
			snapshot.PHY, snapshot.Interface, !snapshot.Timestamp.IsZero(), len(snapshot.Entries), age.Round(time.Second), snapshot.LastError)
	}
	if len(available) == 0 {
		return nil
	}
	deviceIndex, localMAC, ok := resolveLocalDataElementsDevice(msg, interfaces)
	if !ok {
		return fmt.Errorf("no valid local WiFi MAC for DataElements scan device")
	}
	devicePath := fmt.Sprintf("Device.WiFi.DataElements.Network.Device.%d.", deviceIndex)
	appendField(msg, devicePath+"ID", wusp.MAC(localMAC))
	appendField(msg, devicePath+"RadioNumberOfEntries", wusp.Uint(uint64(len(available))))
	for radioPosition, snapshot := range available {
		radioPath := fmt.Sprintf("%sRadio.%d.", devicePath, radioPosition+1)
		radioMAC := snapshot.RadioMAC
		if !validRuntimeMAC(radioMAC) {
			radioMAC = localMAC
		}
		appendField(msg, radioPath+"ID", wusp.MAC(radioMAC))
		appendField(msg, radioPath+"ScanResultNumberOfEntries", wusp.Uint(1))
		appendScanResultFields(msg, radioPath+"ScanResult.1.", snapshot)
	}
	return nil
}

func resolveLocalDataElementsDevice(msg *wusp.Message, interfaces []iwinfo.WirelessInterface) (int, net.HardwareAddr, bool) {
	local := ownBSSIDs(interfaces)
	var selected net.HardwareAddr
	for _, iface := range interfaces {
		if validRuntimeMAC(iface.HardwareAddr) {
			selected = append(net.HardwareAddr(nil), iface.HardwareAddr...)
			break
		}
	}
	if selected == nil {
		return 0, nil, false
	}
	count := 0
	if value, found := msg.Get("Device.WiFi.DataElements.Network.DeviceNumberOfEntries"); found {
		count = int(value.AsUint())
	}
	for index := 1; index <= count; index++ {
		value, found := msg.Get(fmt.Sprintf("Device.WiFi.DataElements.Network.Device.%d.ID", index))
		if !found {
			continue
		}
		mac := net.HardwareAddr(value.AsBytes())
		if local[strings.ToLower(mac.String())] {
			return index, append(net.HardwareAddr(nil), mac...), true
		}
	}
	count++
	appendField(msg, "Device.WiFi.DataElements.Network.DeviceNumberOfEntries", wusp.Uint(uint64(count)))
	return count, selected, true
}

type scanOpClassGroup struct {
	OperatingClass int
	Channels       map[int][]iwinfo.ScanEntry
}

func appendScanResultFields(msg *wusp.Message, path string, snapshot wifiPHYScanSnapshot) {
	appendField(msg, path+"TimeStamp", wusp.Time(snapshot.Timestamp.UTC()))
	appendField(msg, path+"AggregateScanDuration", wusp.Uint(uint64(max(snapshot.Duration.Milliseconds(), 0))))
	appendField(msg, path+"ScanType", wusp.Bool(true))
	groupsByClass := make(map[int]*scanOpClassGroup)
	for _, entry := range snapshot.Entries {
		opClass := operatingClassForFrequency(entry.Frequency)
		channel := wifiChannelFromFrequency(entry.Frequency)
		if opClass == 0 || channel == 0 {
			continue
		}
		group := groupsByClass[opClass]
		if group == nil {
			group = &scanOpClassGroup{OperatingClass: opClass, Channels: make(map[int][]iwinfo.ScanEntry)}
			groupsByClass[opClass] = group
		}
		group.Channels[channel] = append(group.Channels[channel], entry)
	}
	groups := make([]*scanOpClassGroup, 0, len(groupsByClass))
	for _, group := range groupsByClass {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].OperatingClass < groups[j].OperatingClass })
	appendField(msg, path+"OpClassScanNumberOfEntries", wusp.Uint(uint64(len(groups))))
	for groupIndex, group := range groups {
		opPath := fmt.Sprintf("%sOpClassScan.%d.", path, groupIndex+1)
		appendField(msg, opPath+"OperatingClass", wusp.Uint(uint64(group.OperatingClass)))
		channels := make([]int, 0, len(group.Channels))
		for channel := range group.Channels {
			channels = append(channels, channel)
		}
		sort.Ints(channels)
		appendField(msg, opPath+"ChannelScanNumberOfEntries", wusp.Uint(uint64(len(channels))))
		for channelIndex, channel := range channels {
			entries := group.Channels[channel]
			channelPath := fmt.Sprintf("%sChannelScan.%d.", opPath, channelIndex+1)
			appendField(msg, channelPath+"Channel", wusp.Uint(uint64(channel)))
			appendField(msg, channelPath+"TimeStamp", wusp.Time(snapshot.Timestamp.UTC()))
			appendField(msg, channelPath+"ScanStatus", wusp.String("0"))
			if len(entries) > 0 {
				if survey, ok := snapshot.Survey[entries[0].Frequency]; ok {
					if survey.Noise < 0 {
						appendField(msg, channelPath+"Noise", wusp.Uint(uint64(noiseDBMToANPI(int(survey.Noise)))))
					}
					if survey.ActiveTime > 0 {
						utilization := survey.BusyTime * 255 / survey.ActiveTime
						if utilization > 255 {
							utilization = 255
						}
						appendField(msg, channelPath+"Utilization", wusp.Uint(utilization))
					}
				}
			}
			appendField(msg, channelPath+"NeighborBSSNumberOfEntries", wusp.Uint(uint64(len(entries))))
			for neighborIndex, entry := range entries {
				neighborPath := fmt.Sprintf("%sNeighborBSS.%d.", channelPath, neighborIndex+1)
				appendField(msg, neighborPath+"BSSID", wusp.MAC(entry.BSSID))
				appendField(msg, neighborPath+"SSID", wusp.String(entry.SSID))
				appendField(msg, neighborPath+"SignalStrength", wusp.Uint(uint64(signalDBMToRCPI(entry.SignalDBM))))
				bandwidth := strings.TrimSpace(entry.ChannelBandwidth)
				if bandwidth == "" {
					bandwidth = strings.TrimSuffix(snapshot.Width, "MHz")
				}
				if bandwidth != "" {
					appendField(msg, neighborPath+"ChannelBandwidth", wusp.String(bandwidth))
				}
				if entry.BSSLoadKnown {
					appendField(msg, neighborPath+"BSSLoadElementPresent", wusp.Bool(true))
					appendField(msg, neighborPath+"StationCount", wusp.Uint(uint64(entry.StationCount)))
					if entry.ChannelUtilizationKnown {
						appendField(msg, neighborPath+"ChannelUtilization", wusp.Uint(uint64(entry.ChannelUtilization)))
					}
				}
			}
		}
	}
}

func noiseDBMToANPI(noise int) int {
	anpi := noise + 110
	if anpi < 0 {
		return 0
	}
	if anpi > 255 {
		return 255
	}
	return anpi
}
