package platforms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	easyMeshConsoleAddress   = "127.0.0.1:7777"
	easyMeshConsoleTimeout   = 4 * time.Second
	easyMeshConsoleMaxOutput = 128 << 10
)

type easyMeshConsoleCommand uint8

const (
	easyMeshConsoleEnableTopologyRequests easyMeshConsoleCommand = iota + 1
	easyMeshConsoleDisableTopologyRequests
	easyMeshConsoleDetailedStatus
	easyMeshConsoleDiscovery
	easyMeshConsoleNotification
	easyMeshConsoleRadioCapabilities
)

func (command easyMeshConsoleCommand) text() (string, error) {
	switch command {
	case easyMeshConsoleEnableTopologyRequests:
		return "td test on", nil
	case easyMeshConsoleDisableTopologyRequests:
		return "td test off", nil
	case easyMeshConsoleDetailedStatus:
		return "td s1", nil
	case easyMeshConsoleDiscovery:
		return "td discovery", nil
	case easyMeshConsoleNotification:
		return "td notify", nil
	case easyMeshConsoleRadioCapabilities:
		return "td radiocap", nil
	default:
		return "", fmt.Errorf("unsupported EasyMesh console command %d", command)
	}
}

type easyMeshConsoleInterface struct {
	Name    string `json:"name"`
	Medium  string `json:"medium"`
	MAC     string `json:"mac,omitempty"`
	Role    string `json:"role,omitempty"`
	PHY     string `json:"phy,omitempty"`
	Network string `json:"network,omitempty"`
	SSID    string `json:"ssid,omitempty"`
	BSSID   string `json:"bssid,omitempty"`
	BSSRole string `json:"bssRole,omitempty"`
}

type easyMeshConsoleSnapshot struct {
	Role            string
	MAPAgentVersion string
	PackageVersion  string
	CountryCode     string
	LocalMAC        string
	LocalIP         string
	UpstreamMAC     string
	Interfaces      []easyMeshConsoleInterface
	Topology        *meshNode
}

var easyMeshConsoleDeviceLine = regexp.MustCompile(
	`(?i)QCA IEEE 1905\.1 device:\s*([0-9a-f:]{17}),\s*IPv4 address:\s*([^\s(]+)`,
)

// parseEasyMeshConsoleStatus maps the vendor's td s1 output into the same
// neutral topology shape used by device.getRealTopo. Relay devices expose
// their local node, upstream controller, peer relays, radio interfaces and
// BSS details here even when the controller-only ubus topology is empty.
func parseEasyMeshConsoleStatus(raw string, hostname string) (easyMeshConsoleSnapshot, bool) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	snapshot := easyMeshConsoleSnapshot{}
	nodes := make([]*meshNode, 0, 8)
	var local *meshNode
	var current *meshNode
	var currentInterface *easyMeshConsoleInterface
	inLocalInterfaces := false
	inDatabase := false

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Mode of operation:"):
			mode := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Mode of operation:")))
			if strings.Contains(mode, "controller") || strings.Contains(mode, "central") {
				snapshot.Role = "Controller"
			} else if strings.Contains(mode, "agent") || strings.Contains(mode, "relay") {
				snapshot.Role = "Agent"
			}
			continue
		case strings.HasPrefix(line, "Map-Agent Version"):
			snapshot.MAPAgentVersion = valueAfterColon(line)
			continue
		case strings.HasPrefix(line, "Local interfaces:"):
			inLocalInterfaces = true
			inDatabase = false
			currentInterface = nil
			continue
		case strings.HasPrefix(line, "Legacy Devices:"):
			inLocalInterfaces = false
			currentInterface = nil
			continue
		case strings.HasPrefix(line, "-- DB ("):
			inDatabase = true
			inLocalInterfaces = false
			currentInterface = nil
			continue
		}

		if match := easyMeshConsoleDeviceLine.FindStringSubmatch(line); len(match) == 3 {
			mac, err := normalizeEasyMeshMAC(match[1])
			if err != nil {
				continue
			}
			node := &meshNode{
				id:   mac,
				mac:  mac,
				ip:   strings.TrimSpace(match[2]),
				role: easyMeshConsoleRole(line),
			}
			if !inDatabase && local == nil {
				local = node
				local.name = strings.TrimSpace(hostname)
				snapshot.LocalMAC = mac
				snapshot.LocalIP = node.ip
				if node.role == "" {
					node.role = snapshot.Role
				}
			} else {
				current = node
			}
			nodes = append(nodes, node)
			continue
		}

		if inLocalInterfaces {
			if details, ok := parseEasyMeshConsoleInterface(line); ok {
				snapshot.Interfaces = append(snapshot.Interfaces, details)
				currentInterface = &snapshot.Interfaces[len(snapshot.Interfaces)-1]
				continue
			}
			if currentInterface != nil {
				applyEasyMeshConsoleInterfaceDetail(currentInterface, line)
			}
			continue
		}

		if strings.HasPrefix(line, "Package Version:") {
			version := valueAfterColon(line)
			if current == nil && snapshot.PackageVersion == "" {
				snapshot.PackageVersion = version
			}
			continue
		}
		if strings.HasPrefix(line, "Country Code:") {
			value := valueAfterColon(line)
			if before, after, found := strings.Cut(value, "Upstream Device:"); found {
				snapshot.CountryCode = strings.TrimSpace(before)
				snapshot.UpstreamMAC = normalizedEasyMeshConsoleMAC(after)
				if local != nil {
					local.parentMAC = snapshot.UpstreamMAC
				}
			} else {
				snapshot.CountryCode = strings.TrimSpace(value)
			}
			continue
		}
		if strings.HasPrefix(line, "Upstream Device:") {
			upstream := normalizedEasyMeshConsoleMAC(valueAfterColon(line))
			if current != nil {
				current.parentMAC = upstream
			} else if local != nil {
				snapshot.UpstreamMAC = upstream
				local.parentMAC = upstream
			}
			continue
		}
		if current != nil && strings.HasPrefix(line, "Relation:") {
			current.discovery = "EasyMesh " + valueAfterColon(line)
			continue
		}
		if current != nil && strings.Contains(line, "Number of hops to the device:") {
			if hops, err := strconv.Atoi(strings.TrimSpace(line[strings.LastIndex(line, ":")+1:])); err == nil {
				current.sourceHop = hops
				current.hasHop = true
			}
		}
	}

	if local == nil {
		return easyMeshConsoleSnapshot{}, false
	}
	if snapshot.Role == "" {
		snapshot.Role = firstNonEmpty(local.role, "Agent")
	}
	local.role = snapshot.Role
	if snapshot.Role == "Controller" {
		local.sourceHop = 0
		local.hasHop = true
		local.parentMAC = ""
	}
	if local.parentMAC != "" {
		local.linkType = "Wi-Fi"
	}
	for _, node := range nodes {
		if node == nil || node == local {
			continue
		}
		if node.role == "" {
			node.role = "Relay"
		}
		if node.parentMAC != "" {
			node.linkType = "Wi-Fi"
		}
	}
	snapshot.Topology = collapseMeshContainer(nodes)
	return snapshot, true
}

func easyMeshConsoleRole(line string) string {
	normalized := strings.ToLower(line)
	if strings.Contains(normalized, "map controller") {
		return "Controller"
	}
	if strings.Contains(normalized, "map agent") || strings.Contains(normalized, "relaying") {
		return "Relay"
	}
	return ""
}

func valueAfterColon(value string) string {
	_, result, found := strings.Cut(value, ":")
	if !found {
		return ""
	}
	return strings.TrimSpace(result)
}

func normalizedEasyMeshConsoleMAC(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "none") || value == "" {
		return ""
	}
	mac, err := normalizeEasyMeshMAC(strings.Fields(value)[0])
	if err != nil {
		return ""
	}
	return mac
}

func parseEasyMeshConsoleInterface(line string) (easyMeshConsoleInterface, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 || strings.EqualFold(fields[0], "Interface") || strings.EqualFold(fields[0], "Index") {
		return easyMeshConsoleInterface{}, false
	}
	mediumIndex := 1
	if strings.HasPrefix(fields[1], "(R=") {
		mediumIndex = 2
	}
	if len(fields) <= mediumIndex+1 {
		return easyMeshConsoleInterface{}, false
	}
	medium := strings.ToUpper(fields[mediumIndex])
	if !strings.HasPrefix(medium, "WLAN") && medium != "ETHER" {
		return easyMeshConsoleInterface{}, false
	}
	details := easyMeshConsoleInterface{
		Name:   fields[0],
		Medium: medium,
		MAC:    normalizedEasyMeshConsoleMAC(fields[mediumIndex+1]),
	}
	for _, field := range fields[mediumIndex+2:] {
		if field == "AP" || field == "STA" {
			details.Role = field
		}
		if strings.Contains(field, "MHz") {
			details.PHY = field
		}
		if strings.Contains(field, "(V=") || strings.HasPrefix(field, "br-") {
			details.Network = strings.TrimSpace(strings.Join(fields[len(fields)-2:], " "))
		}
	}
	return details, true
}

func applyEasyMeshConsoleInterfaceDetail(details *easyMeshConsoleInterface, line string) {
	if details == nil {
		return
	}
	if index := strings.Index(line, "SSID:"); index >= 0 {
		value := strings.TrimSpace(line[index+len("SSID:"):])
		if before, _, found := strings.Cut(value, ","); found {
			value = before
		}
		details.SSID = strings.TrimSpace(value)
	}
	if index := strings.Index(line, "BSSID:"); index >= 0 {
		details.BSSID = normalizedEasyMeshConsoleMAC(line[index+len("BSSID:"):])
	}
	if index := strings.Index(line, "Role:"); index >= 0 {
		details.BSSRole = strings.Trim(strings.TrimSpace(line[index+len("Role:"):]), "|")
	}
}

func encodeEasyMeshConsoleInterfaces(interfaces []easyMeshConsoleInterface) string {
	if len(interfaces) == 0 {
		return ""
	}
	encoded, err := json.Marshal(interfaces)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func easyMeshConsoleActionCommand(action string) (easyMeshConsoleCommand, bool) {
	switch strings.TrimSpace(action) {
	case "RefreshTopology":
		return easyMeshConsoleDetailedStatus, true
	case "DiscoverNeighbors":
		return easyMeshConsoleDiscovery, true
	case "AnnounceTopology":
		return easyMeshConsoleNotification, true
	case "RefreshRadioCapabilities":
		return easyMeshConsoleRadioCapabilities, true
	default:
		return 0, false
	}
}

// RunEasyMeshConsoleAction executes a small, explicit allowlist of vendor
// actions. Database mutation, debug, message-ID and SSH commands from the
// interactive console are deliberately not reachable through USP.
func (b *OpenWrtBackend) RunEasyMeshConsoleAction(ctx context.Context, action string) (string, error) {
	if b == nil || b.easyMeshConsole == nil {
		return "", fmt.Errorf("local EasyMesh console is unavailable")
	}
	command, ok := easyMeshConsoleActionCommand(action)
	if !ok {
		return "", fmt.Errorf("unsupported EasyMesh console action %q", action)
	}
	output, err := b.easyMeshConsole.Run(ctx, command)
	if err != nil {
		return "", fmt.Errorf("run EasyMesh %s: %w", action, err)
	}

	// Every action returns a fresh structured snapshot. This keeps the UI on
	// the controller's WUSP channel instead of introducing a second poller.
	statusOutput := output
	if command != easyMeshConsoleDetailedStatus {
		statusOutput, err = b.easyMeshConsole.Run(ctx, easyMeshConsoleDetailedStatus)
		if err != nil {
			return "", fmt.Errorf("refresh EasyMesh topology after %s: %w", action, err)
		}
	}
	snapshot, parsed := parseEasyMeshConsoleStatus(statusOutput, b.readTextFile(b.hostnamePath))
	if !parsed {
		return "", fmt.Errorf("EasyMesh %s returned an unreadable topology", action)
	}
	b.notifyEasyMeshConsoleSnapshot(snapshot)

	switch action {
	case "RefreshTopology":
		return "EasyMesh topology refreshed", nil
	case "DiscoverNeighbors":
		return "Neighbor discovery sent", nil
	case "AnnounceTopology":
		return "Topology notification sent", nil
	case "RefreshRadioCapabilities":
		return "Radio capabilities refreshed", nil
	default:
		return strings.TrimSpace(output), nil
	}
}

type easyMeshConsole interface {
	Run(context.Context, easyMeshConsoleCommand) (string, error)
}

type easyMeshConsoleFunc func(context.Context, easyMeshConsoleCommand) (string, error)

func (run easyMeshConsoleFunc) Run(ctx context.Context, command easyMeshConsoleCommand) (string, error) {
	return run(ctx, command)
}

type easyMeshConsoleClient struct {
	address string
	timeout time.Duration
	dialer  net.Dialer
}

func newEasyMeshConsoleClient() *easyMeshConsoleClient {
	return &easyMeshConsoleClient{
		address: easyMeshConsoleAddress,
		timeout: easyMeshConsoleTimeout,
	}
}

func (client *easyMeshConsoleClient) Run(
	ctx context.Context,
	command easyMeshConsoleCommand,
) (string, error) {
	if client == nil {
		return "", fmt.Errorf("EasyMesh console is unavailable")
	}
	commandText, err := command.text()
	if err != nil {
		return "", err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := client.timeout
	if timeout <= 0 {
		timeout = easyMeshConsoleTimeout
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	connection, err := client.dialer.DialContext(commandCtx, "tcp", client.address)
	if err != nil {
		return "", fmt.Errorf("connect to local EasyMesh console: %w", err)
	}
	defer connection.Close()
	if deadline, ok := commandCtx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return "", fmt.Errorf("set EasyMesh console deadline: %w", err)
		}
	}

	decoder := telnetDecoder{}
	if _, err := readEasyMeshConsolePrompt(commandCtx, connection, &decoder); err != nil {
		return "", fmt.Errorf("read EasyMesh console greeting: %w", err)
	}
	if _, err := io.WriteString(connection, commandText+"\n"); err != nil {
		return "", fmt.Errorf("send EasyMesh console command: %w", err)
	}
	response, err := readEasyMeshConsolePrompt(commandCtx, connection, &decoder)
	if err != nil {
		return "", fmt.Errorf("read EasyMesh console response: %w", err)
	}
	return trimEasyMeshConsolePrompt(response), nil
}

func readEasyMeshConsolePrompt(
	ctx context.Context,
	connection net.Conn,
	decoder *telnetDecoder,
) (string, error) {
	buffer := make([]byte, 4096)
	var output bytes.Buffer
	for {
		count, err := connection.Read(buffer)
		if count > 0 {
			plain, reply := decoder.Decode(buffer[:count])
			if len(reply) > 0 {
				if _, writeErr := connection.Write(reply); writeErr != nil {
					return "", fmt.Errorf("reply to Telnet negotiation: %w", writeErr)
				}
			}
			if output.Len()+len(plain) > easyMeshConsoleMaxOutput {
				return "", fmt.Errorf("response exceeds %d bytes", easyMeshConsoleMaxOutput)
			}
			_, _ = output.Write(plain)
			if hasEasyMeshConsolePrompt(output.String()) {
				return output.String(), nil
			}
		}
		if err == nil {
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if deadline, hasDeadline := ctx.Deadline(); hasDeadline && !time.Now().Before(deadline) {
				return "", context.DeadlineExceeded
			}
			return "", fmt.Errorf("timed out waiting for prompt")
		}
		return "", err
	}
}

func hasEasyMeshConsolePrompt(output string) bool {
	trimmed := strings.TrimRight(output, " \t\r\n")
	lineStart := strings.LastIndexByte(trimmed, '\n') + 1
	return strings.TrimSpace(trimmed[lineStart:]) == "@"
}

func trimEasyMeshConsolePrompt(output string) string {
	normalized := strings.ReplaceAll(output, "\r\n", "\n")
	trimmed := strings.TrimRight(normalized, " \t\r\n")
	lineStart := strings.LastIndexByte(trimmed, '\n') + 1
	if strings.TrimSpace(trimmed[lineStart:]) == "@" {
		trimmed = trimmed[:lineStart]
	}
	return strings.TrimSpace(trimmed)
}

const (
	telnetSE   = 240
	telnetSB   = 250
	telnetWILL = 251
	telnetWONT = 252
	telnetDO   = 253
	telnetDONT = 254
	telnetIAC  = 255
)

type telnetDecoder struct {
	state byte
	verb  byte
}

const (
	telnetStateData byte = iota
	telnetStateCommand
	telnetStateOption
	telnetStateSubnegotiation
	telnetStateSubnegotiationCommand
)

func (decoder *telnetDecoder) Decode(input []byte) ([]byte, []byte) {
	plain := make([]byte, 0, len(input))
	reply := make([]byte, 0, 6)
	for _, value := range input {
		switch decoder.state {
		case telnetStateData:
			if value == telnetIAC {
				decoder.state = telnetStateCommand
				continue
			}
			plain = append(plain, value)
		case telnetStateCommand:
			switch value {
			case telnetIAC:
				plain = append(plain, value)
				decoder.state = telnetStateData
			case telnetWILL, telnetWONT, telnetDO, telnetDONT:
				decoder.verb = value
				decoder.state = telnetStateOption
			case telnetSB:
				decoder.state = telnetStateSubnegotiation
			default:
				decoder.state = telnetStateData
			}
		case telnetStateOption:
			switch decoder.verb {
			case telnetWILL:
				reply = append(reply, telnetIAC, telnetDONT, value)
			case telnetDO:
				reply = append(reply, telnetIAC, telnetWONT, value)
			}
			decoder.state = telnetStateData
		case telnetStateSubnegotiation:
			if value == telnetIAC {
				decoder.state = telnetStateSubnegotiationCommand
			}
		case telnetStateSubnegotiationCommand:
			if value == telnetSE {
				decoder.state = telnetStateData
			} else {
				decoder.state = telnetStateSubnegotiation
			}
		}
	}
	return plain, reply
}
