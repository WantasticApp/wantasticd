package platforms

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	easyMeshBackhaulSteeringTimeout = 15 * time.Second
	easyMeshNativeDatabaseMaxBytes  = 1 << 20
	easyMeshCommandPath             = "/usr/sbin/ezcmd"
)

var easyMeshNativeDevicePattern = regexp.MustCompile(
	`QCA IEEE 1905\.1 device:\s*([0-9A-Fa-f:]{17})`,
)

type easyMeshNativeDatabase struct {
	devices map[string]*easyMeshNativeDevice
}

type easyMeshNativeDevice struct {
	interfaces []easyMeshNativeInterface
}

type easyMeshNativeInterface struct {
	mac        string
	medium     string
	role       string
	bssid      string
	channel    int
	mapBSSRole uint64
	hasSSID    bool
}

type easyMeshBackhaulSteer struct {
	childALID   string
	parentALID  string
	staMAC      string
	targetBSSID string
	opClass     int
	channel     int
}

func (b *OpenWrtBackend) prepareEasyMeshBackhaulSteer(
	ctx context.Context,
	topology easyMeshTopology,
	liveRoot *meshNode,
) (*easyMeshBackhaulSteer, *easyMeshBackhaulSteer, error) {
	child, parent, previousParent, changed, err := easyMeshParentChange(topology, liveRoot)
	if err != nil || !changed {
		return nil, nil, err
	}

	commandCtx, cancel := context.WithTimeout(ctx, easyMeshConsoleTimeout)
	defer cancel()
	output, err := b.commandRunner(commandCtx, easyMeshCommandPath, "td", "s2")
	if err != nil {
		return nil, nil, fmt.Errorf("read Qualcomm EasyMesh topology database: %w", err)
	}
	if len(output) > easyMeshNativeDatabaseMaxBytes {
		return nil, nil, fmt.Errorf(
			"Qualcomm EasyMesh topology database exceeds %d bytes",
			easyMeshNativeDatabaseMaxBytes,
		)
	}
	database, err := parseEasyMeshNativeDatabase(string(output))
	if err != nil {
		return nil, nil, err
	}
	steer, err := database.backhaulSteer(child, parent)
	if err != nil {
		return nil, nil, err
	}
	rollback, err := database.backhaulSteer(child, previousParent)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare safe EasyMesh rollback: %w", err)
	}
	return &steer, &rollback, nil
}

func easyMeshParentChange(
	topology easyMeshTopology,
	liveRoot *meshNode,
) (string, string, string, bool, error) {
	liveParents := make(map[string]string, len(topology.DeviceArray))
	for _, node := range flattenMeshForest(normalizedMeshRoots(liveRoot)) {
		mac, err := normalizeEasyMeshMAC(firstNonEmpty(node.mac, node.id))
		if err != nil {
			continue
		}
		parent := "NULL"
		if rawParent := firstNonEmpty(node.parentMAC, node.parentID); strings.TrimSpace(rawParent) != "" {
			parent, err = normalizeEasyMeshMAC(rawParent)
			if err != nil {
				return "", "", "", false, err
			}
		}
		liveParents[mac] = parent
	}

	changes := make([]easyMeshTopologyNode, 0, 1)
	for _, node := range topology.DeviceArray {
		if liveParents[node.ALID] != node.ParentALID {
			changes = append(changes, node)
		}
	}
	if len(changes) == 0 {
		return "", "", "", false, nil
	}
	if len(changes) != 1 {
		return "", "", "", false, fmt.Errorf(
			"apply EasyMesh topology: change one node parent per operation",
		)
	}
	change := changes[0]
	if change.ParentALID == "NULL" {
		return "", "", "", false, fmt.Errorf("apply EasyMesh topology: the controller root cannot be changed")
	}
	previousParent := liveParents[change.ALID]
	if previousParent == "" || previousParent == "NULL" {
		return "", "", "", false, fmt.Errorf("apply EasyMesh topology: current parent is unavailable")
	}
	return change.ALID, change.ParentALID, previousParent, true, nil
}

func parseEasyMeshNativeDatabase(output string) (easyMeshNativeDatabase, error) {
	database := easyMeshNativeDatabase{devices: map[string]*easyMeshNativeDevice{}}
	var current *easyMeshNativeDevice
	lastInterface := -1
	inRadioList := false

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 4096), easyMeshConsoleMaxOutput)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if matches := easyMeshNativeDevicePattern.FindStringSubmatch(line); len(matches) == 2 {
			alID, err := normalizeEasyMeshMAC(matches[1])
			if err != nil {
				continue
			}
			current = database.devices[alID]
			if current == nil {
				current = &easyMeshNativeDevice{interfaces: []easyMeshNativeInterface{}}
				database.devices[alID] = current
			}
			lastInterface = -1
			inRadioList = false
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasSuffix(line, "Radios:") {
			inRadioList = true
			lastInterface = -1
			continue
		}
		if inRadioList {
			if mac, medium, channel, ok := parseEasyMeshRadioLine(line); ok {
				current.setRadio(mac, medium, channel)
				continue
			}
			if line == "" || strings.HasPrefix(line, "#") {
				inRadioList = false
			}
		}
		if iface, ok := parseEasyMeshInterfaceLine(line); ok {
			current.interfaces = append(current.interfaces, iface)
			lastInterface = len(current.interfaces) - 1
			inRadioList = false
			continue
		}
		if lastInterface < 0 {
			continue
		}
		iface := &current.interfaces[lastInterface]
		switch {
		case strings.HasPrefix(line, "BSSID:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "BSSID:"))
			if bssid, err := normalizeEasyMeshMAC(value); err == nil {
				iface.bssid = bssid
			}
		case strings.HasPrefix(line, "SSID:"):
			iface.hasSSID = strings.TrimSpace(strings.TrimPrefix(line, "SSID:")) != ""
		case strings.HasPrefix(line, "Map BSS Type :"):
			fields := strings.Fields(line)
			for _, field := range fields {
				field = strings.TrimRight(field, ",;")
				if !strings.HasPrefix(field, "0x") {
					continue
				}
				if role, err := strconv.ParseUint(field, 0, 64); err == nil {
					iface.mapBSSRole = role
				}
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return easyMeshNativeDatabase{}, fmt.Errorf("parse Qualcomm EasyMesh topology database: %w", err)
	}
	if len(database.devices) == 0 {
		return easyMeshNativeDatabase{}, fmt.Errorf("Qualcomm EasyMesh topology database contains no devices")
	}
	return database, nil
}

func parseEasyMeshInterfaceLine(line string) (easyMeshNativeInterface, bool) {
	fields := strings.Fields(line)
	macIndex := -1
	mac := ""
	for index, field := range fields {
		normalized, err := normalizeEasyMeshMAC(field)
		if err == nil {
			macIndex = index
			mac = normalized
			break
		}
	}
	if macIndex <= 0 {
		return easyMeshNativeInterface{}, false
	}
	medium := strings.ToUpper(fields[macIndex-1])
	if !strings.HasPrefix(medium, "WLAN") {
		return easyMeshNativeInterface{}, false
	}
	role := ""
	for _, field := range fields[macIndex+1:] {
		if field == "AP" || field == "STA" {
			role = field
			break
		}
	}
	if role == "" {
		return easyMeshNativeInterface{}, false
	}
	channel := 0
	if role == "AP" && macIndex+1 < len(fields) {
		channel, _ = strconv.Atoi(fields[macIndex+1])
	}
	return easyMeshNativeInterface{
		mac:     mac,
		medium:  medium,
		role:    role,
		channel: channel,
	}, true
}

func parseEasyMeshRadioLine(line string) (string, string, int, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", "", 0, false
	}
	mac, err := normalizeEasyMeshMAC(fields[0])
	if err != nil {
		return "", "", 0, false
	}
	medium := strings.ToUpper(fields[1])
	if !strings.HasPrefix(medium, "WLAN") {
		return "", "", 0, false
	}
	channel, err := strconv.Atoi(fields[2])
	if err != nil {
		return "", "", 0, false
	}
	return mac, medium, channel, true
}

func (device *easyMeshNativeDevice) setRadio(mac, medium string, channel int) {
	for index := range device.interfaces {
		iface := &device.interfaces[index]
		if iface.mac != mac {
			continue
		}
		iface.medium = medium
		iface.channel = channel
	}
}

func (database easyMeshNativeDatabase) backhaulSteer(
	childALID string,
	parentALID string,
) (easyMeshBackhaulSteer, error) {
	child := database.devices[childALID]
	if child == nil {
		return easyMeshBackhaulSteer{}, fmt.Errorf("EasyMesh node %s is absent from the controller database", childALID)
	}
	parent := database.devices[parentALID]
	if parent == nil {
		return easyMeshBackhaulSteer{}, fmt.Errorf("EasyMesh parent %s is absent from the controller database", parentALID)
	}

	stations := make([]easyMeshNativeInterface, 0, len(child.interfaces))
	for _, iface := range child.interfaces {
		if iface.role == "STA" && iface.bssid != "" {
			stations = append(stations, iface)
		}
	}
	targets := make([]easyMeshNativeInterface, 0, len(parent.interfaces))
	for _, iface := range parent.interfaces {
		isBackhaulBSS := iface.role == "AP" && iface.hasSSID && iface.mapBSSRole&0x40 != 0
		if isBackhaulBSS {
			targets = append(targets, iface)
		}
	}
	if len(stations) == 0 {
		return easyMeshBackhaulSteer{}, fmt.Errorf("EasyMesh node %s has no active backhaul STA", childALID)
	}
	if len(targets) == 0 {
		return easyMeshBackhaulSteer{}, fmt.Errorf(
			"EasyMesh parent %s is not advertising an operational backhaul BSS",
			parentALID,
		)
	}

	sort.SliceStable(targets, func(left, right int) bool {
		return targets[left].channel < targets[right].channel
	})
	for _, station := range stations {
		for _, target := range targets {
			if station.medium != target.medium {
				continue
			}
			opClass, err := easyMeshOperatingClass(target.medium, target.channel)
			if err != nil {
				continue
			}
			return easyMeshBackhaulSteer{
				childALID:   childALID,
				parentALID:  parentALID,
				staMAC:      station.mac,
				targetBSSID: target.mac,
				opClass:     opClass,
				channel:     target.channel,
			}, nil
		}
	}
	return easyMeshBackhaulSteer{}, fmt.Errorf(
		"EasyMesh parent %s has no backhaul BSS compatible with node %s",
		parentALID,
		childALID,
	)
}

func easyMeshOperatingClass(medium string, channel int) (int, error) {
	switch strings.ToUpper(strings.TrimSpace(medium)) {
	case "WLAN6G":
		if channel >= 1 && channel <= 233 {
			return 131, nil
		}
	case "WLAN2G", "WLAN2.4G":
		if channel >= 1 && channel <= 13 {
			return 81, nil
		}
	case "WLAN5G":
		switch {
		case channel >= 36 && channel <= 48:
			return 115, nil
		case channel >= 52 && channel <= 64:
			return 118, nil
		case channel >= 100 && channel <= 144:
			return 121, nil
		case channel >= 149 && channel <= 161:
			return 124, nil
		case channel == 165:
			return 125, nil
		}
	}
	return 0, fmt.Errorf("cannot derive EasyMesh operating class for %s channel %d", medium, channel)
}

func (b *OpenWrtBackend) executeEasyMeshBackhaulSteer(
	ctx context.Context,
	steer easyMeshBackhaulSteer,
) error {
	commandCtx, cancel := context.WithTimeout(ctx, easyMeshConsoleTimeout)
	defer cancel()
	_, err := b.commandRunner(
		commandCtx,
		easyMeshCommandPath,
		"map",
		"bhs",
		steer.childALID,
		steer.staMAC,
		steer.targetBSSID,
		strconv.Itoa(steer.opClass),
		strconv.Itoa(steer.channel),
	)
	if err != nil {
		return fmt.Errorf("send EasyMesh backhaul steering request: %w", err)
	}
	return b.waitForEasyMeshParent(
		ctx,
		steer.childALID,
		steer.parentALID,
		easyMeshBackhaulSteeringTimeout,
	)
}

func (b *OpenWrtBackend) waitForEasyMeshParent(
	ctx context.Context,
	childALID string,
	parentALID string,
	timeout time.Duration,
) error {
	verifyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	interval := b.easyMeshVerifyInterval
	if interval <= 0 || interval > time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if data, err := b.readOpenWrtRealTopo(verifyCtx); err == nil {
			if live, ok := parseOpenWrtRealTopo(data); ok {
				for _, node := range flattenMeshForest(normalizedMeshRoots(live.root)) {
					mac, macErr := normalizeEasyMeshMAC(firstNonEmpty(node.mac, node.id))
					if macErr != nil || mac != childALID {
						continue
					}
					parent := firstNonEmpty(node.parentMAC, node.parentID)
					if normalized, parentErr := normalizeEasyMeshMAC(parent); parentErr == nil && normalized == parentALID {
						b.notifyEasyMeshLiveTopology(live.root)
						return nil
					}
				}
			}
		}
		select {
		case <-verifyCtx.Done():
			return fmt.Errorf(
				"EasyMesh node %s did not associate with parent %s within %d seconds; the agent kept or restored its previous link",
				childALID,
				parentALID,
				int(timeout.Seconds()),
			)
		case <-ticker.C:
		}
	}
}
