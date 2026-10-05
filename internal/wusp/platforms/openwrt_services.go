package platforms

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

const (
	dnsmasqReloadScript = "/etc/init.d/dnsmasq"
	ntpReloadScript     = "/etc/init.d/sysntpd"
)

// appendOpenWrtServiceFields projects the operator-facing OpenWrt network,
// DHCP, DNS and time configuration into their canonical TR-181 objects. Raw
// UCI implementation details stay on the device; the portal receives only
// stable service objects that it can explain and render safely.
func (b *OpenWrtBackend) appendOpenWrtServiceFields(msg *wusp.Message) {
	if b == nil || msg == nil {
		return
	}

	network, networkErr := b.readUCIConfig("network")
	if networkErr != nil {
		network = openWrtUCIConfig{}
	}
	interfaceRefs := messageInterfaceRefs(msg)
	networkByName := make(map[string]openWrtUCISection)
	for _, section := range network.Sections {
		if section.Type != "interface" {
			continue
		}
		name := firstNonEmpty(section.Name, section.Options["device"], section.Options["ifname"])
		if name != "" {
			networkByName[name] = section
		}
		for _, candidate := range []string{section.Name, section.Options["device"], section.Options["ifname"]} {
			if ref := interfaceRefs[strings.TrimSpace(candidate)]; ref != "" {
				addressing := "Static"
				if proto := strings.ToLower(strings.TrimSpace(section.Options["proto"])); proto != "" && proto != "static" {
					addressing = "DHCP"
				}
				for _, field := range msg.Fields {
					if strings.HasPrefix(field.Path, ref+"IPv4Address.") && strings.HasSuffix(field.Path, ".AddressingType") {
						msg.Set(field.Path, wusp.String(addressing))
					}
				}
				break
			}
		}
	}

	b.appendOpenWrtDNSFields(msg, network, interfaceRefs)
	b.appendOpenWrtDHCPFields(msg, networkByName, interfaceRefs)
	b.appendOpenWrtTimeClientFields(msg)
}

func messageInterfaceRefs(msg *wusp.Message) map[string]string {
	refs := make(map[string]string)
	for _, field := range msg.Fields {
		if !strings.HasPrefix(field.Path, "Device.IP.Interface.") || !strings.HasSuffix(field.Path, ".Name") {
			continue
		}
		name := strings.TrimSpace(wusp.ValueToString(field.Val))
		if name == "" {
			continue
		}
		refs[name] = strings.TrimSuffix(field.Path, "Name")
	}
	return refs
}

type openWrtDNSBinding struct {
	sectionRef   string
	interfaceRef string
	servers      []string
}

func openWrtDNSBindings(network openWrtUCIConfig, interfaceRefs map[string]string) []openWrtDNSBinding {
	bindings := make([]openWrtDNSBinding, 0)
	typeIndex := make(map[string]int)
	for _, section := range network.Sections {
		index := typeIndex[section.Type]
		typeIndex[section.Type] = index + 1
		if section.Type != "interface" {
			continue
		}
		servers := append([]string(nil), section.Lists["dns"]...)
		if len(servers) == 0 {
			servers = strings.Fields(section.Options["dns"])
		}
		clean := make([]string, 0, len(servers))
		for _, server := range servers {
			server = strings.TrimSpace(server)
			if net.ParseIP(server) != nil {
				clean = append(clean, server)
			}
		}
		if len(clean) == 0 {
			continue
		}
		ref := section.Name
		if ref == "" {
			ref = fmt.Sprintf("@%s[%d]", section.Type, index)
		}
		interfaceRef := ""
		for _, candidate := range []string{section.Options["device"], section.Options["ifname"], section.Name} {
			if interfaceRef = interfaceRefs[strings.TrimSpace(candidate)]; interfaceRef != "" {
				break
			}
		}
		bindings = append(bindings, openWrtDNSBinding{sectionRef: ref, interfaceRef: interfaceRef, servers: clean})
	}
	return bindings
}

func (b *OpenWrtBackend) appendOpenWrtDNSFields(msg *wusp.Message, network openWrtUCIConfig, interfaceRefs map[string]string) {
	bindings := openWrtDNSBindings(network, interfaceRefs)
	count := 0
	for _, binding := range bindings {
		for _, server := range binding.servers {
			count++
			prefix := fmt.Sprintf("Device.DNS.Client.Server.%d.", count)
			appendField(msg, prefix+"Enable", wusp.Bool(true))
			appendField(msg, prefix+"Status", wusp.String("Enabled"))
			appendField(msg, prefix+"Alias", wusp.String(fmt.Sprintf("dns-%d", count)))
			appendField(msg, prefix+"DNSServer", wusp.String(server))
			if binding.interfaceRef != "" {
				appendField(msg, prefix+"Interface", wusp.String(binding.interfaceRef))
			}
			appendField(msg, prefix+"Type", wusp.String("Static"))
		}
	}
	appendField(msg, "Device.DNS.Client.Enable", wusp.Bool(count > 0))
	appendField(msg, "Device.DNS.Client.Status", wusp.String(map[bool]string{true: "Enabled", false: "Disabled"}[count > 0]))
	appendField(msg, "Device.DNS.Client.ServerNumberOfEntries", wusp.Uint(uint64(count)))
}

func (b *OpenWrtBackend) appendOpenWrtDHCPFields(msg *wusp.Message, networkByName map[string]openWrtUCISection, interfaceRefs map[string]string) {
	dhcp, err := b.readUCIConfig("dhcp")
	if err != nil {
		return
	}
	pools := make([]openWrtUCISection, 0)
	for _, section := range dhcp.Sections {
		if section.Type == "dhcp" {
			pools = append(pools, section)
		}
	}
	appendField(msg, "Device.DHCPv4.Server.PoolNumberOfEntries", wusp.Uint(uint64(len(pools))))
	serverEnabled := false
	for index, pool := range pools {
		prefix := fmt.Sprintf("Device.DHCPv4.Server.Pool.%d.", index+1)
		enabled := !parseOpenWrtBool(pool.Options["ignore"], false)
		serverEnabled = serverEnabled || enabled
		appendField(msg, prefix+"Enable", wusp.Bool(enabled))
		appendField(msg, prefix+"Status", wusp.String(map[bool]string{true: "Enabled", false: "Disabled"}[enabled]))
		appendField(msg, prefix+"Alias", wusp.String(firstNonEmpty(pool.Name, fmt.Sprintf("pool-%d", index+1))))
		appendField(msg, prefix+"Order", wusp.String(strconv.Itoa(index+1)))

		interfaceName := firstNonEmpty(pool.Options["interface"], pool.Name)
		networkSection := networkByName[interfaceName]
		interfaceRef := ""
		for _, candidate := range []string{networkSection.Options["device"], networkSection.Options["ifname"], interfaceName} {
			if interfaceRef = interfaceRefs[strings.TrimSpace(candidate)]; interfaceRef != "" {
				appendField(msg, prefix+"Interface", wusp.String(interfaceRef))
				break
			}
		}

		gateway := net.ParseIP(strings.TrimSpace(networkSection.Options["ipaddr"])).To4()
		maskIP := net.ParseIP(strings.TrimSpace(networkSection.Options["netmask"])).To4()
		if maskIP == nil {
			maskIP = net.IPv4(255, 255, 255, 0).To4()
		}
		if gateway != nil {
			appendField(msg, prefix+"SubnetMask", wusp.IP4(maskIP))
			appendField(msg, prefix+"IPRouters", wusp.List(wusp.IP4(gateway)))
			start := strings.TrimSpace(pool.Options["start"])
			limit, _ := strconv.Atoi(strings.TrimSpace(pool.Options["limit"]))
			if minAddress, maxAddress := openWrtDHCPRange(gateway, net.IPMask(maskIP), start, limit); minAddress != nil {
				appendField(msg, prefix+"MinAddress", wusp.IP4(minAddress))
				appendField(msg, prefix+"MaxAddress", wusp.IP4(maxAddress))
			}
		}
		if servers := openWrtNetworkDNSServers(networkSection); len(servers) > 0 {
			values := make([]wusp.Value, 0, len(servers))
			for _, server := range servers {
				values = append(values, wusp.String(server))
			}
			appendField(msg, prefix+"DNSServers", wusp.List(values...))
		}
		if domain := strings.TrimSpace(pool.Options["domain"]); domain != "" {
			appendField(msg, prefix+"DomainName", wusp.String(domain))
		}
		if seconds, ok := parseOpenWrtLeaseSeconds(pool.Options["leasetime"]); ok {
			appendField(msg, prefix+"LeaseTime", wusp.Int(seconds))
		}
	}
	appendField(msg, "Device.DHCPv4.Server.Enable", wusp.Bool(serverEnabled))
}

func openWrtNetworkDNSServers(section openWrtUCISection) []string {
	servers := append([]string(nil), section.Lists["dns"]...)
	if len(servers) == 0 {
		servers = strings.Fields(section.Options["dns"])
	}
	return servers
}

func openWrtDHCPRange(gateway net.IP, mask net.IPMask, start string, limit int) (net.IP, net.IP) {
	if gateway = gateway.To4(); gateway == nil || len(mask) != net.IPv4len || limit <= 0 {
		return nil, nil
	}
	if explicit := net.ParseIP(start).To4(); explicit != nil {
		return explicit, addIPv4(explicit, limit-1)
	}
	offset, err := strconv.Atoi(start)
	if err != nil || offset < 0 {
		return nil, nil
	}
	base := gateway.Mask(mask)
	return addIPv4(base, offset), addIPv4(base, offset+limit-1)
}

func addIPv4(ip net.IP, offset int) net.IP {
	ip = append(net.IP(nil), ip.To4()...)
	value := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	value += uint32(offset)
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)).To4()
}

func parseOpenWrtLeaseSeconds(value string) (int64, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return 0, false
	}
	if value == "infinite" {
		return -1, true
	}
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseInt(strings.TrimSuffix(value, "d"), 10, 64)
		return days * 24 * 60 * 60, err == nil
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return int64(duration.Seconds()), true
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	return seconds, err == nil
}

func (b *OpenWrtBackend) appendOpenWrtTimeClientFields(msg *wusp.Message) {
	servers := b.readUCIList("system", "timeserver", "server")
	enabled := parseOpenWrtBool(b.readUCIOption("system", "timeserver", "enabled"), true)
	if len(servers) == 0 && !enabled {
		appendField(msg, "Device.Time.ClientNumberOfEntries", wusp.Uint(0))
		return
	}
	appendField(msg, "Device.Time.ClientNumberOfEntries", wusp.Uint(1))
	appendField(msg, "Device.Time.Client.1.Enable", wusp.Bool(enabled))
	appendField(msg, "Device.Time.Client.1.Status", wusp.String(map[bool]string{true: "Unsynchronized", false: "Disabled"}[enabled]))
	appendField(msg, "Device.Time.Client.1.Alias", wusp.String("system-ntp"))
	appendField(msg, "Device.Time.Client.1.Mode", wusp.String("Unicast"))
	appendField(msg, "Device.Time.Client.1.Port", wusp.Uint(123))
	appendField(msg, "Device.Time.Client.1.Version", wusp.Uint(4))
	values := make([]wusp.Value, 0, len(servers))
	for _, server := range servers {
		if server = strings.TrimSpace(server); server != "" {
			values = append(values, wusp.String(server))
		}
	}
	appendField(msg, "Device.Time.Client.1.Servers", wusp.List(values...))
}

func (b *OpenWrtBackend) readUCIOption(config, section, option string) string {
	parsed, err := b.readUCIConfig(config)
	if err != nil {
		return ""
	}
	current := parsed.findSection(section)
	if current == nil {
		return ""
	}
	return current.Options[option]
}

func (b *OpenWrtBackend) setOpenWrtServiceParam(ctx context.Context, path string, value wusp.Value) error {
	switch path {
	case "Device.Time.Client.1.Enable":
		return b.setTimeEnabled(ctx, value.AsBool())
	case "Device.Time.Client.1.Servers":
		return b.setOpenWrtTimeServers(ctx, value)
	case "Device.DHCPv4.Server.Enable":
		return b.setAllOpenWrtDHCPPools(ctx, value.AsBool())
	}
	if index, ok := indexedServicePath(path, "Device.DNS.Client.Server.", ".DNSServer"); ok {
		return b.setOpenWrtDNSServer(ctx, index, strings.TrimSpace(wusp.ValueToString(value)))
	}
	if index, ok := indexedServicePath(path, "Device.DHCPv4.Server.Pool.", ".Enable"); ok {
		return b.setOpenWrtDHCPPoolOption(ctx, index, "ignore", map[bool]string{true: "0", false: "1"}[value.AsBool()])
	}
	if index, ok := indexedServicePath(path, "Device.DHCPv4.Server.Pool.", ".LeaseTime"); ok {
		seconds := value.AsInt()
		if value.Tag == wusp.TagUint {
			seconds = int64(value.AsUint())
		}
		if seconds < -1 {
			return fmt.Errorf("wusp openwrt DHCP lease time must be -1 or a non-negative number of seconds")
		}
		lease := "infinite"
		if seconds >= 0 {
			lease = strconv.FormatInt(seconds, 10) + "s"
		}
		return b.setOpenWrtDHCPPoolOption(ctx, index, "leasetime", lease)
	}
	return wusp.ErrUSPPathUnsupported
}

func indexedServicePath(path, prefix, suffix string) (int, bool) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return 0, false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	index, err := strconv.Atoi(value)
	return index, err == nil && index > 0
}

func valueStringList(value wusp.Value) []string {
	items := value.AsList()
	if value.Tag != wusp.TagList {
		items = nil
		for _, item := range strings.Split(wusp.ValueToString(value), ",") {
			items = append(items, wusp.String(item))
		}
	}
	values := make([]string, 0, len(items))
	seen := make(map[string]bool)
	for _, item := range items {
		text := strings.TrimSpace(wusp.ValueToString(item))
		if text != "" && !seen[text] {
			seen[text] = true
			values = append(values, text)
		}
	}
	return values
}

func (b *OpenWrtBackend) setOpenWrtTimeServers(ctx context.Context, value wusp.Value) error {
	servers := valueStringList(value)
	section := b.resolveUCISectionRef("system", "timeserver")
	if err := b.writeUCIListViaFile("system", section, "server", servers); err != nil {
		return fmt.Errorf("wusp openwrt set NTP servers: %w", err)
	}
	_ = b.reloadScript(ctx, ntpReloadScript)
	return nil
}

func (b *OpenWrtBackend) setOpenWrtDNSServer(ctx context.Context, index int, server string) error {
	if net.ParseIP(server) == nil {
		return fmt.Errorf("wusp openwrt invalid DNS server %q", server)
	}
	network, err := b.readUCIConfig("network")
	if err != nil {
		return err
	}
	bindings := openWrtDNSBindings(network, nil)
	current := 0
	for _, binding := range bindings {
		for serverIndex := range binding.servers {
			current++
			if current != index {
				continue
			}
			binding.servers[serverIndex] = server
			if err := b.writeUCIListViaFile("network", binding.sectionRef, "dns", binding.servers); err != nil {
				return err
			}
			_ = b.reloadScript(ctx, networkReloadScript)
			return nil
		}
	}
	return wusp.ErrUSPPathNotFound
}

func (b *OpenWrtBackend) setAllOpenWrtDHCPPools(ctx context.Context, enabled bool) error {
	dhcp, err := b.readUCIConfig("dhcp")
	if err != nil {
		return err
	}
	pool := 0
	for _, section := range dhcp.Sections {
		if section.Type != "dhcp" {
			continue
		}
		pool++
		if err := b.setOpenWrtDHCPPoolOption(ctx, pool, "ignore", map[bool]string{true: "0", false: "1"}[enabled]); err != nil {
			return err
		}
	}
	return nil
}

func (b *OpenWrtBackend) setOpenWrtDHCPPoolOption(ctx context.Context, index int, option, value string) error {
	dhcp, err := b.readUCIConfig("dhcp")
	if err != nil {
		return err
	}
	current := 0
	typeIndex := 0
	for _, section := range dhcp.Sections {
		if section.Type != "dhcp" {
			continue
		}
		current++
		ref := section.Name
		if ref == "" {
			ref = fmt.Sprintf("@dhcp[%d]", typeIndex)
		}
		typeIndex++
		if current != index {
			continue
		}
		if err := b.writeUCIOptionViaFile("dhcp", ref, option, value); err != nil {
			return err
		}
		_ = b.reloadScript(ctx, dnsmasqReloadScript)
		return nil
	}
	return wusp.ErrUSPPathNotFound
}

func (b *OpenWrtBackend) writeUCIListViaFile(config, sectionRef, option string, values []string) error {
	path := filepath.Join(b.uciConfigDir, config)
	original, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	updated, err := uciRewriteList(original, sectionRef, option, values)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, updated, 0o644)
}

func uciRewriteList(original []byte, sectionRef, option string, values []string) ([]byte, error) {
	option = strings.TrimSpace(option)
	if option == "" {
		return nil, errors.New("uci: empty list option name")
	}
	lines := splitLinesPreserving(string(original))
	header, end, err := findUCISection(lines, sectionRef)
	if err != nil {
		return nil, err
	}
	if header < 0 {
		wantType, wantName, _, indexed := parseUCISectionRef(sectionRef)
		if wantType == "" {
			return nil, fmt.Errorf("uci: cannot create section %q", sectionRef)
		}
		if len(lines) > 0 && !strings.HasSuffix(lines[len(lines)-1], "\n") {
			lines[len(lines)-1] += "\n"
		}
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "\n")
		}
		headerLine := "config " + wantType
		if !indexed && wantName != "" && wantName != wantType {
			headerLine += " " + uciQuote(wantName)
		}
		lines = append(lines, headerLine+"\n")
		header, end = len(lines)-1, len(lines)
	}

	indent := detectSectionIndent(lines, header, end)
	body := make([]string, 0, end-header-1)
	for _, line := range lines[header+1 : end] {
		trimmed := strings.TrimSpace(line)
		name := ""
		if parsedName, _, ok := parseUCIAssignment(trimmed, "list"); ok {
			name = parsedName
		} else if parsedName, _, ok := parseUCIAssignment(trimmed, "option"); ok {
			name = parsedName
		}
		if name != option {
			body = append(body, line)
		}
	}
	insert := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			insert = append(insert, indent+"list "+option+" "+uciQuote(value)+"\n")
		}
	}
	result := make([]string, 0, len(lines)-((end-header-1)-len(body))+len(insert))
	result = append(result, lines[:header+1]...)
	result = append(result, body...)
	result = append(result, insert...)
	result = append(result, lines[end:]...)
	return []byte(strings.Join(result, "")), nil
}
