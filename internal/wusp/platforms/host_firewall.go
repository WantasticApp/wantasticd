package platforms

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"wantastic-agent/internal/wusp"
)

type iptablesChain struct {
	name  string
	rules []iptablesRule
}

type iptablesRule struct {
	raw, target, protocol, source, dest string
	sourcePort, sourcePortMax           int
	destPort, destPortMax               int
}

func collectHostFirewallStatic(ctx context.Context, runner CommandRunner, msg *wusp.Message) {
	if runner == nil || msg == nil {
		return
	}
	raw, err := runner(ctx, "iptables-save")
	if err != nil {
		logCollectorError("firewall.iptables-save", err)
		return
	}
	if len(raw) == 0 {
		return
	}
	chains := parseIPTablesSave(string(raw))
	msg.Set("Device.Firewall.Enable", wusp.Bool(true))
	msg.Set("Device.Firewall.Type", wusp.String("Stateful"))
	msg.Set("Device.Firewall.Config", wusp.String("Advanced"))
	msg.Set("Device.Firewall.ChainNumberOfEntries", wusp.Uint(uint64(len(chains))))
	for ci, chain := range chains {
		prefix := fmt.Sprintf("Device.Firewall.Chain.%d.", ci+1)
		msg.Set(prefix+"Enable", wusp.Bool(true))
		msg.Set(prefix+"Name", wusp.String(chain.name))
		msg.Set(prefix+"Creator", wusp.String("Other"))
		msg.Set(prefix+"RuleNumberOfEntries", wusp.Uint(uint64(len(chain.rules))))
		for ri, rule := range chain.rules {
			base := fmt.Sprintf("%sRule.%d.", prefix, ri+1)
			msg.Set(base+"Enable", wusp.Bool(true))
			msg.Set(base+"Status", wusp.String("Enabled"))
			msg.Set(base+"Order", wusp.String(strconv.Itoa(ri+1)))
			msg.Set(base+"Description", wusp.String(truncateString(rule.raw, 256)))
			msg.Set(base+"Target", wusp.String(mapFirewallTarget(rule.target)))
			msg.Set(base+"Protocol", wusp.Int(int64(mapFirewallProtocol(rule.protocol))))
			msg.Set(base+"IPVersion", wusp.Int(int64(iptablesIPVersion(rule))))
			if rule.source != "" && rule.source != "0.0.0.0/0" {
				ip, mask := splitFirewallCIDR(rule.source)
				msg.Set(base+"SourceIP", wusp.String(ip))
				if mask != "" {
					msg.Set(base+"SourceMask", wusp.String(mask))
				}
			}
			if rule.dest != "" && rule.dest != "0.0.0.0/0" {
				ip, mask := splitFirewallCIDR(rule.dest)
				msg.Set(base+"DestIP", wusp.String(ip))
				if mask != "" {
					msg.Set(base+"DestMask", wusp.String(mask))
				}
			}
			msg.Set(base+"SourcePort", wusp.Int(int64(rule.sourcePort)))
			msg.Set(base+"SourcePortRangeMax", wusp.Int(int64(rule.sourcePortMax)))
			msg.Set(base+"DestPort", wusp.Int(int64(rule.destPort)))
			msg.Set(base+"DestPortRangeMax", wusp.Int(int64(rule.destPortMax)))
			msg.Set(base+"Log", wusp.Bool(strings.EqualFold(rule.target, "LOG")))
		}
	}
}

func parseIPTablesSave(raw string) []iptablesChain {
	table := "filter"
	order := []string{}
	byName := map[string]*iptablesChain{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "-A" {
			continue
		}
		key := table + "/" + fields[1]
		chain := byName[key]
		if chain == nil {
			chain = &iptablesChain{name: key}
			byName[key] = chain
			order = append(order, key)
		}
		rule := iptablesRule{raw: line}
		for i := 2; i < len(fields); i++ {
			next := func() string {
				if i+1 < len(fields) {
					i++
					return fields[i]
				}
				return ""
			}
			switch fields[i] {
			case "-j":
				rule.target = next()
			case "-p":
				rule.protocol = next()
			case "-s":
				rule.source = next()
			case "-d":
				rule.dest = next()
			case "--sport", "--source-port":
				rule.sourcePort, rule.sourcePortMax = parseIPTablesPort(next())
			case "--dport", "--destination-port":
				rule.destPort, rule.destPortMax = parseIPTablesPort(next())
			}
		}
		chain.rules = append(chain.rules, rule)
	}
	out := make([]iptablesChain, 0, len(order))
	for _, key := range order {
		out = append(out, *byName[key])
	}
	return out
}

func parseIPTablesPort(value string) (int, int) {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ':' || r == '-' })
	if len(parts) == 0 {
		return 0, 0
	}
	low, _ := strconv.Atoi(parts[0])
	high := low
	if len(parts) > 1 {
		high, _ = strconv.Atoi(parts[1])
	}
	return low, high
}

func iptablesIPVersion(rule iptablesRule) int {
	if strings.Contains(rule.source, ":") || strings.Contains(rule.dest, ":") {
		return 6
	}
	return 4
}

func truncateString(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen]
}

func (b *hostBackend) liveIPTablesChains(ctx context.Context) ([]iptablesChain, error) {
	raw, err := b.commandRunner(ctx, "iptables-save")
	if err != nil {
		return nil, err
	}
	return parseIPTablesSave(string(raw)), nil
}

func (b *hostBackend) setHostFirewallParam(ctx context.Context, path string, value wusp.Value) error {
	chainIdx, ruleIdx, leaf, ok := parseFirewallRulePath(path)
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}
	chains, err := b.liveIPTablesChains(ctx)
	if err != nil {
		return err
	}
	if chainIdx > len(chains) || ruleIdx > len(chains[chainIdx-1].rules) {
		return wusp.ErrUSPPathNotFound
	}
	chain := chains[chainIdx-1]
	table, name, ok := strings.Cut(chain.name, "/")
	if !ok {
		return wusp.ErrUSPPathNotFound
	}
	rule := chain.rules[ruleIdx-1]
	if leaf == "Enable" {
		if value.AsBool() {
			return nil
		}
		_, err = b.commandRunner(ctx, "iptables", "-t", table, "-D", name, strconv.Itoa(ruleIdx))
		return err
	}
	args := strings.Fields(rule.raw)
	if len(args) < 3 {
		return fmt.Errorf("invalid live iptables rule")
	}
	args = append([]string{"-t", table, "-R", name, strconv.Itoa(ruleIdx)}, args[2:]...)
	flag, rendered, err := firewallLeafArgument(leaf, value)
	if err != nil {
		return err
	}
	args = replaceCLIOption(args, flag, rendered)
	_, err = b.commandRunner(ctx, "iptables", args...)
	return err
}

func (b *hostBackend) deleteHostFirewallRule(ctx context.Context, path string) error {
	chainIdx, ruleIdx, leaf, ok := parseFirewallRulePath(strings.TrimSuffix(path, "."))
	if !ok || leaf != "" {
		return wusp.ErrUSPPathUnsupported
	}
	chains, err := b.liveIPTablesChains(ctx)
	if err != nil {
		return err
	}
	if chainIdx > len(chains) || ruleIdx > len(chains[chainIdx-1].rules) {
		return wusp.ErrUSPPathNotFound
	}
	table, name, ok := strings.Cut(chains[chainIdx-1].name, "/")
	if !ok {
		return wusp.ErrUSPPathNotFound
	}
	_, err = b.commandRunner(ctx, "iptables", "-t", table, "-D", name, strconv.Itoa(ruleIdx))
	return err
}

func (b *hostBackend) addHostFirewallRule(ctx context.Context, objectPath string, initial *wusp.Message) ([]string, error) {
	const prefix = "Device.Firewall.Chain."
	if !strings.HasPrefix(objectPath, prefix) || !strings.HasSuffix(objectPath, ".Rule.") {
		return nil, wusp.ErrUSPPathUnsupported
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(objectPath, prefix), ".Rule.")
	chainIdx, err := strconv.Atoi(rest)
	if err != nil || chainIdx <= 0 {
		return nil, wusp.ErrUSPPathUnsupported
	}
	chains, err := b.liveIPTablesChains(ctx)
	if err != nil {
		return nil, err
	}
	if chainIdx > len(chains) {
		return nil, wusp.ErrUSPPathNotFound
	}
	table, name, ok := strings.Cut(chains[chainIdx-1].name, "/")
	if !ok {
		return nil, wusp.ErrUSPPathNotFound
	}
	args := []string{"-t", table, "-A", name}
	if initial != nil {
		for _, field := range initial.Fields {
			leaf := field.Path[strings.LastIndex(field.Path, ".")+1:]
			flag, rendered, convErr := firewallLeafArgument(leaf, field.Val)
			if convErr != nil {
				return nil, convErr
			}
			if flag != "" && rendered != "" {
				args = append(args, flag, rendered)
			}
		}
	}
	if !containsCLIOption(args, "-j") {
		args = append(args, "-j", "ACCEPT")
	}
	if _, err := b.commandRunner(ctx, "iptables", args...); err != nil {
		return nil, err
	}
	idx := len(chains[chainIdx-1].rules) + 1
	return []string{fmt.Sprintf("Device.Firewall.Chain.%d.Rule.%d.", chainIdx, idx)}, nil
}

func parseFirewallRulePath(path string) (int, int, string, bool) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "Device.Firewall.Chain."), "."), ".")
	if len(parts) < 3 || parts[1] != "Rule" {
		return 0, 0, "", false
	}
	ci, e1 := strconv.Atoi(parts[0])
	ri, e2 := strconv.Atoi(parts[2])
	if e1 != nil || e2 != nil || ci <= 0 || ri <= 0 {
		return 0, 0, "", false
	}
	leaf := ""
	if len(parts) > 3 {
		leaf = parts[3]
	}
	return ci, ri, leaf, true
}

func firewallLeafArgument(leaf string, value wusp.Value) (string, string, error) {
	switch leaf {
	case "Target":
		target, err := normalizeFirewallTarget(wusp.ValueToString(value))
		return "-j", target, err
	case "Protocol":
		protocol, err := normalizeFirewallProtocol(wusp.ValueToString(value))
		return "-p", protocol, err
	case "SourceIP":
		return "-s", normalizeFirewallAddress(wusp.ValueToString(value)), nil
	case "DestIP":
		return "-d", normalizeFirewallAddress(wusp.ValueToString(value)), nil
	case "SourcePort":
		port, err := normalizeFirewallPort(wusp.ValueToString(value))
		return "--sport", port, err
	case "DestPort":
		port, err := normalizeFirewallPort(wusp.ValueToString(value))
		return "--dport", port, err
	case "Enable":
		return "", "", nil
	default:
		return "", "", wusp.ErrUSPPathUnsupported
	}
}

func replaceCLIOption(args []string, flag, value string) []string {
	if flag == "" {
		return args
	}
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			if value == "" {
				end := i + 1
				if end < len(args) {
					end++
				}
				return append(args[:i], args[end:]...)
			}
			if i+1 < len(args) {
				args[i+1] = value
				return args
			}
			args = append(args, value)
			return args
		}
	}
	if value == "" {
		return args
	}
	return append(args, flag, value)
}

func containsCLIOption(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag {
			return true
		}
	}
	return false
}

func normalizeFirewallTarget(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "accept":
		return "ACCEPT", nil
	case "drop":
		return "DROP", nil
	case "reject":
		return "REJECT", nil
	case "return":
		return "RETURN", nil
	case "log":
		return "LOG", nil
	case "":
		return "", fmt.Errorf("firewall target is required")
	default:
		return "", wusp.ErrUSPPathUnsupported
	}
}

func normalizeFirewallProtocol(value string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "", "any", "all", "-1", "0":
		return "", nil
	case "1", "icmp":
		return "icmp", nil
	case "2", "igmp":
		return "igmp", nil
	case "6", "tcp":
		return "tcp", nil
	case "17", "udp":
		return "udp", nil
	case "47", "gre":
		return "gre", nil
	case "50", "esp":
		return "esp", nil
	case "51", "ah":
		return "ah", nil
	case "58", "icmpv6", "ipv6-icmp":
		return "icmpv6", nil
	case "89", "ospf":
		return "ospf", nil
	case "132", "sctp":
		return "sctp", nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 255 {
		return "", fmt.Errorf("invalid firewall protocol %q", value)
	}
	return strconv.Itoa(n), nil
}

func normalizeFirewallAddress(value string) string {
	v := strings.TrimSpace(value)
	switch strings.ToLower(v) {
	case "", "any", "all", "0.0.0.0", "0.0.0.0/0", "::", "::/0":
		return ""
	default:
		return v
	}
}

func normalizeFirewallPort(value string) (string, error) {
	v := strings.TrimSpace(value)
	switch strings.ToLower(v) {
	case "", "any", "all", "0":
		return "", nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid firewall port %q", value)
	}
	return strconv.Itoa(n), nil
}
