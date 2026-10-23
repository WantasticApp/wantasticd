package platforms

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/diaglog"
	"wantastic-agent/internal/wusp"
)

// Device.WUSP_TrafficTelemetry: per-interface throughput and per-firewall-
// rule hit rates sampled every minute in the background, each row carrying a
// rolling 30-sample history in the WiFi history block encoding.

const (
	trafficTelemetryInterval = 60 * time.Second
	trafficCommandTimeout    = 5 * time.Second
	trafficCommandMaxOutput  = 4 << 20
)

type trafficInterfaceSample struct {
	Name      string
	Status    string
	LinkSpeed int
	Duplex    string
	Counters  wifiIfaceCounters
	RxRate    uint32
	TxRate    uint32
	RxPPS     uint32
	TxPPS     uint32
	RatesOK   bool
}

type firewallRuleCounter struct {
	Key     string
	Table   string
	Chain   string
	Name    string
	Target  string
	Packets uint64
	Bytes   uint64
	PPS     uint32
	Kbps    uint32
	RatesOK bool
}

type trafficCounterState struct {
	RxBytes, TxBytes, RxPackets, TxPackets, Errors, Drops uint64
	At                                                    time.Time
}

type ruleCounterState struct {
	Packets, Bytes uint64
	At             time.Time
}

type wiredHostSample struct {
	MAC       net.HardwareAddr
	Bridge    string
	Port      string
	LinkSpeed int
	Duplex    string
	Idle      uint32
}

type trafficTelemetrySnapshot struct {
	Sampled        bool
	WiredHosts     []wiredHostSample
	LastSample     time.Time
	FirewallSource string
	Interfaces     []trafficInterfaceSample
	Rules          []firewallRuleCounter
	IfaceHistory   map[string][]wusp.WiFiHistorySample
	RuleHistory    map[string][]wusp.WiFiHistorySample
}

type trafficTelemetryDeps struct {
	netClassDir string
	listIfaces  func(netClassDir string) []string
	counters    func(netClassDir, ifname string) wifiIfaceCounters
	operstate   func(netClassDir, ifname string) string
	link        func(netClassDir, ifname string) (int, string)
	wiredHosts  func(netClassDir string) []wiredHostSample
	firewall    func(ctx context.Context) ([]firewallRuleCounter, string)
}

type trafficTelemetryCoordinator struct {
	mu        sync.Mutex
	started   bool
	interval  time.Duration
	now       func() time.Time
	deps      trafficTelemetryDeps
	current   trafficTelemetrySnapshot
	ifaceHist map[string][]wusp.WiFiHistorySample
	ruleHist  map[string][]wusp.WiFiHistorySample
	ifaceSeen map[string]time.Time
	ruleSeen  map[string]time.Time
	prevIface map[string]trafficCounterState
	prevRule  map[string]ruleCounterState
}

var defaultTrafficTelemetry = newTrafficTelemetryCoordinator(trafficTelemetryDeps{
	listIfaces: listTrafficInterfaces,
	counters:   readWiFiIfaceCounters,
	operstate:  readOperstate,
	link:       readLinkSpeed,
	wiredHosts: readBridgeHosts,
	firewall:   readFirewallRuleCounters,
})

func newTrafficTelemetryCoordinator(deps trafficTelemetryDeps) *trafficTelemetryCoordinator {
	return &trafficTelemetryCoordinator{
		interval:  trafficTelemetryInterval,
		now:       time.Now,
		deps:      deps,
		ifaceHist: make(map[string][]wusp.WiFiHistorySample),
		ruleHist:  make(map[string][]wusp.WiFiHistorySample),
		ifaceSeen: make(map[string]time.Time),
		ruleSeen:  make(map[string]time.Time),
		prevIface: make(map[string]trafficCounterState),
		prevRule:  make(map[string]ruleCounterState),
	}
}

func (c *trafficTelemetryCoordinator) snapshotAndStart(netClassDir string) trafficTelemetrySnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		c.started = true
		c.deps.netClassDir = netClassDir
		go c.loop()
	}
	out := c.current
	out.Interfaces = append([]trafficInterfaceSample(nil), c.current.Interfaces...)
	out.Rules = append([]firewallRuleCounter(nil), c.current.Rules...)
	out.WiredHosts = append([]wiredHostSample(nil), c.current.WiredHosts...)
	out.IfaceHistory = make(map[string][]wusp.WiFiHistorySample, len(c.ifaceHist))
	for k, v := range c.ifaceHist {
		out.IfaceHistory[k] = append([]wusp.WiFiHistorySample(nil), v...)
	}
	out.RuleHistory = make(map[string][]wusp.WiFiHistorySample, len(c.ruleHist))
	for k, v := range c.ruleHist {
		out.RuleHistory[k] = append([]wusp.WiFiHistorySample(nil), v...)
	}
	return out
}

func (c *trafficTelemetryCoordinator) loop() {
	for {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					diaglog.Printf("[USP] traffic_telemetry panic=%q", fmt.Sprint(recovered))
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			c.sample(ctx)
		}()
		time.Sleep(c.interval)
	}
}

func perSecond(delta uint64, seconds float64, scale float64) uint32 {
	v := float64(delta) * scale / seconds
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v + 0.5)
}

func (c *trafficTelemetryCoordinator) sample(ctx context.Context) {
	now := c.now().UTC()
	deps := c.deps
	names := deps.listIfaces(deps.netClassDir)
	interfaces := make([]trafficInterfaceSample, 0, len(names))
	for _, name := range names {
		counters := deps.counters(deps.netClassDir, name)
		if !counters.OK {
			continue
		}
		sample := trafficInterfaceSample{Name: name, Status: deps.operstate(deps.netClassDir, name), Counters: counters, Duplex: "Unknown"}
		if deps.link != nil {
			sample.LinkSpeed, sample.Duplex = deps.link(deps.netClassDir, name)
		}
		interfaces = append(interfaces, sample)
	}
	var wired []wiredHostSample
	if deps.wiredHosts != nil {
		wired = deps.wiredHosts(deps.netClassDir)
	}
	rules, source := deps.firewall(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range interfaces {
		s := &interfaces[i]
		cur := trafficCounterState{
			RxBytes: s.Counters.RxBytes, TxBytes: s.Counters.TxBytes,
			RxPackets: s.Counters.RxPackets, TxPackets: s.Counters.TxPackets,
			Errors: s.Counters.RxErrors + s.Counters.TxErrors, Drops: s.Counters.RxDropped + s.Counters.TxDropped,
			At: now,
		}
		values := map[uint8]int64{}
		if prev, ok := c.prevIface[s.Name]; ok {
			seconds := now.Sub(prev.At).Seconds()
			if seconds >= 1 && cur.RxBytes >= prev.RxBytes && cur.TxBytes >= prev.TxBytes && cur.RxPackets >= prev.RxPackets && cur.TxPackets >= prev.TxPackets {
				s.RxRate = perSecond(cur.RxBytes-prev.RxBytes, seconds, 8.0/1000)
				s.TxRate = perSecond(cur.TxBytes-prev.TxBytes, seconds, 8.0/1000)
				s.RxPPS = perSecond(cur.RxPackets-prev.RxPackets, seconds, 1)
				s.TxPPS = perSecond(cur.TxPackets-prev.TxPackets, seconds, 1)
				s.RatesOK = true
				values[wusp.TrafficMetricRxRate] = int64(s.RxRate)
				values[wusp.TrafficMetricTxRate] = int64(s.TxRate)
				values[wusp.TrafficMetricRxPacketRate] = int64(s.RxPPS)
				values[wusp.TrafficMetricTxPacketRate] = int64(s.TxPPS)
				if cur.Errors >= prev.Errors {
					values[wusp.TrafficMetricErrors] = int64(cur.Errors - prev.Errors)
				}
				if cur.Drops >= prev.Drops {
					values[wusp.TrafficMetricDrops] = int64(cur.Drops - prev.Drops)
				}
			}
		}
		c.prevIface[s.Name] = cur
		if len(values) > 0 {
			c.ifaceHist[s.Name] = appendHistory(c.ifaceHist[s.Name], wusp.WiFiHistorySample{Time: now, Values: values})
		}
		c.ifaceSeen[s.Name] = now
	}
	for i := range rules {
		r := &rules[i]
		cur := ruleCounterState{Packets: r.Packets, Bytes: r.Bytes, At: now}
		if prev, ok := c.prevRule[r.Key]; ok {
			seconds := now.Sub(prev.At).Seconds()
			if seconds >= 1 && cur.Packets >= prev.Packets && cur.Bytes >= prev.Bytes {
				r.PPS = perSecond(cur.Packets-prev.Packets, seconds, 1)
				r.Kbps = perSecond(cur.Bytes-prev.Bytes, seconds, 8.0/1000)
				r.RatesOK = true
				c.ruleHist[r.Key] = appendHistory(c.ruleHist[r.Key], wusp.WiFiHistorySample{Time: now, Values: map[uint8]int64{
					wusp.TrafficMetricRulePackets: int64(r.PPS),
					wusp.TrafficMetricRuleRate:    int64(r.Kbps),
				}})
			}
		}
		c.prevRule[r.Key] = cur
		c.ruleSeen[r.Key] = now
	}
	horizon := time.Duration(wusp.WiFiHistoryDepth) * c.interval
	for key, seen := range c.ifaceSeen {
		if now.Sub(seen) > horizon {
			delete(c.ifaceSeen, key)
			delete(c.ifaceHist, key)
			delete(c.prevIface, key)
		}
	}
	for key, seen := range c.ruleSeen {
		if now.Sub(seen) > horizon {
			delete(c.ruleSeen, key)
			delete(c.ruleHist, key)
			delete(c.prevRule, key)
		}
	}
	c.current = trafficTelemetrySnapshot{Sampled: true, LastSample: now, FirewallSource: source, Interfaces: interfaces, Rules: rules, WiredHosts: wired}
}

func appendTrafficTelemetryFields(msg *wusp.Message, netClassDir string) error {
	return appendTrafficTelemetrySnapshotFields(msg, defaultTrafficTelemetry.snapshotAndStart(netClassDir))
}

func appendTrafficTelemetrySnapshotFields(msg *wusp.Message, snap trafficTelemetrySnapshot) error {
	prefix := wusp.WUSPTrafficTelemetryPrefix
	appendField(msg, prefix+"SampleIntervalSeconds", wusp.Uint(uint64(trafficTelemetryInterval/time.Second)))
	appendField(msg, prefix+"HistoryDepth", wusp.Uint(wusp.WiFiHistoryDepth))
	if !snap.Sampled {
		appendField(msg, prefix+"Status", wusp.String("Collecting"))
		return nil
	}
	appendField(msg, prefix+"Status", wusp.String("Ready"))
	appendField(msg, prefix+"LastSampleTime", wusp.Time(snap.LastSample))
	source := snap.FirewallSource
	if source == "" {
		source = "none"
	}
	appendField(msg, prefix+"FirewallSource", wusp.String(source))
	appendField(msg, prefix+"InterfaceNumberOfEntries", wusp.Uint(uint64(len(snap.Interfaces))))
	appendField(msg, prefix+"FirewallRuleNumberOfEntries", wusp.Uint(uint64(len(snap.Rules))))
	appendField(msg, prefix+"WiredHostNumberOfEntries", wusp.Uint(uint64(len(snap.WiredHosts))))
	for i, host := range snap.WiredHosts {
		path := fmt.Sprintf("%sWiredHost.%d.", prefix, i+1)
		appendField(msg, path+"MACAddress", wusp.MAC(host.MAC))
		appendField(msg, path+"Bridge", wusp.String(host.Bridge))
		appendField(msg, path+"Port", wusp.String(host.Port))
		appendField(msg, path+"LinkSpeed", wusp.Uint(uint64(max(host.LinkSpeed, 0))))
		appendField(msg, path+"Duplex", wusp.String(host.Duplex))
		appendField(msg, path+"IdleSeconds", wusp.Uint(uint64(host.Idle)))
	}
	for i, iface := range snap.Interfaces {
		path := fmt.Sprintf("%sInterface.%d.", prefix, i+1)
		appendField(msg, path+"Alias", wusp.String("if-"+iface.Name))
		appendField(msg, path+"Name", wusp.String(iface.Name))
		appendField(msg, path+"Status", wusp.String(iface.Status))
		appendField(msg, path+"LinkSpeed", wusp.Uint(uint64(max(iface.LinkSpeed, 0))))
		duplex := iface.Duplex
		if duplex == "" {
			duplex = "Unknown"
		}
		appendField(msg, path+"Duplex", wusp.String(duplex))
		if iface.RatesOK {
			appendField(msg, path+"RxRate", wusp.Uint(uint64(iface.RxRate)))
			appendField(msg, path+"TxRate", wusp.Uint(uint64(iface.TxRate)))
			appendField(msg, path+"RxPacketRate", wusp.Uint(uint64(iface.RxPPS)))
			appendField(msg, path+"TxPacketRate", wusp.Uint(uint64(iface.TxPPS)))
		}
		appendField(msg, path+"BytesReceived", wusp.Uint(iface.Counters.RxBytes))
		appendField(msg, path+"BytesSent", wusp.Uint(iface.Counters.TxBytes))
		appendField(msg, path+"Errors", wusp.Uint(iface.Counters.RxErrors+iface.Counters.TxErrors))
		appendField(msg, path+"Drops", wusp.Uint(iface.Counters.RxDropped+iface.Counters.TxDropped))
		if err := appendHistoryField(msg, path, snap.IfaceHistory[iface.Name]); err != nil {
			return fmt.Errorf("interface %s history: %w", iface.Name, err)
		}
	}
	for i, rule := range snap.Rules {
		path := fmt.Sprintf("%sFirewallRule.%d.", prefix, i+1)
		appendField(msg, path+"Alias", wusp.String(rule.Key))
		appendField(msg, path+"Table", wusp.String(truncateUTF8Bytes(rule.Table, 32)))
		appendField(msg, path+"Chain", wusp.String(truncateUTF8Bytes(rule.Chain, 64)))
		appendField(msg, path+"Name", wusp.String(truncateUTF8Bytes(rule.Name, 128)))
		appendField(msg, path+"Target", wusp.String(truncateUTF8Bytes(rule.Target, 32)))
		appendField(msg, path+"Packets", wusp.Uint(rule.Packets))
		appendField(msg, path+"Bytes", wusp.Uint(rule.Bytes))
		if rule.RatesOK {
			appendField(msg, path+"PacketRate", wusp.Uint(uint64(rule.PPS)))
			appendField(msg, path+"ByteRate", wusp.Uint(uint64(rule.Kbps)))
		}
		if err := appendHistoryField(msg, path, snap.RuleHistory[rule.Key]); err != nil {
			return fmt.Errorf("firewall rule %s history: %w", rule.Key, err)
		}
	}
	return nil
}

func listTrafficInterfaces(netClassDir string) []string {
	if netClassDir == "" {
		netClassDir = "/sys/class/net"
	}
	entries, err := os.ReadDir(netClassDir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if name := entry.Name(); name != "lo" && !strings.HasPrefix(name, ".") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) > wusp.TrafficTelemetryMaxInterfaces {
		names = names[:wusp.TrafficTelemetryMaxInterfaces]
	}
	return names
}

func readOperstate(netClassDir, name string) string {
	if netClassDir == "" {
		netClassDir = "/sys/class/net"
	}
	data, err := os.ReadFile(filepath.Join(netClassDir, name, "operstate"))
	if err != nil {
		return "Unknown"
	}
	switch strings.TrimSpace(string(data)) {
	case "up":
		return "Up"
	case "down":
		return "Down"
	case "dormant":
		return "Dormant"
	case "lowerlayerdown":
		return "LowerLayerDown"
	case "notpresent":
		return "NotPresent"
	}
	return "Unknown"
}

// readFirewallRuleCounters reads per-rule counters from iptables-save -c
// (fw3 / legacy) or, when iptables is absent, nft -j (fw4).
func readFirewallRuleCounters(ctx context.Context) ([]firewallRuleCounter, string) {
	if out, err := runBounded(ctx, "iptables-save", "-c"); err == nil && len(out) > 0 {
		return topFirewallRules(parseIPTablesSaveCounters(string(out))), "iptables"
	}
	if out, err := runBounded(ctx, "nft", "-j", "list", "ruleset"); err == nil && len(out) > 0 {
		return topFirewallRules(parseNFTJSONCounters(out)), "nftables"
	}
	return nil, "none"
}

func runBounded(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, trafficCommandTimeout)
	defer cancel()
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = &cappedBuffer{buf: &stdout, remaining: trafficCommandMaxOutput}
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

type cappedBuffer struct {
	buf       *bytes.Buffer
	remaining int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if c.remaining > 0 {
		if len(p) > c.remaining {
			p = p[:c.remaining]
		}
		c.remaining -= len(p)
		c.buf.Write(p)
	}
	return n, nil
}

var (
	iptCounterLine = regexp.MustCompile(`^\[(\d+):(\d+)\]\s+-A\s+(\S+)\s*(.*)$`)
	iptComment     = regexp.MustCompile(`--comment\s+(?:"((?:[^"\\]|\\.)*)"|(\S+))`)
	iptTarget      = regexp.MustCompile(`(?:^|\s)-[jg]\s+(\S+)`)
)

func parseIPTablesSaveCounters(output string) []firewallRuleCounter {
	var out []firewallRuleCounter
	table := ""
	ordinal := map[string]int{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		match := iptCounterLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		packets, _ := strconv.ParseUint(match[1], 10, 64)
		byteCount, _ := strconv.ParseUint(match[2], 10, 64)
		chain, spec := match[3], match[4]
		ordinal[table+"/"+chain]++
		name := ""
		if c := iptComment.FindStringSubmatch(spec); c != nil {
			name = firstNonEmpty(c[1], c[2])
		}
		target := ""
		if t := iptTarget.FindStringSubmatch(spec); t != nil {
			target = t[1]
		}
		out = append(out, firewallRuleCounter{
			Key:     firewallRuleKey(table, chain, name, spec),
			Table:   table,
			Chain:   chain,
			Name:    cleanFirewallRuleName(name, chain, ordinal[table+"/"+chain]),
			Target:  target,
			Packets: packets,
			Bytes:   byteCount,
		})
	}
	return out
}

func parseNFTJSONCounters(data []byte) []firewallRuleCounter {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []firewallRuleCounter
	ordinal := map[string]int{}
	for _, item := range doc.Nftables {
		raw, ok := item["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Family  string                       `json:"family"`
			Table   string                       `json:"table"`
			Chain   string                       `json:"chain"`
			Handle  int                          `json:"handle"`
			Comment string                       `json:"comment"`
			Expr    []map[string]json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(raw, &rule) != nil {
			continue
		}
		var counter *struct {
			Packets uint64 `json:"packets"`
			Bytes   uint64 `json:"bytes"`
		}
		target := ""
		for _, expr := range rule.Expr {
			for key, value := range expr {
				switch key {
				case "counter":
					var c struct {
						Packets uint64 `json:"packets"`
						Bytes   uint64 `json:"bytes"`
					}
					if json.Unmarshal(value, &c) == nil {
						counter = &c
					}
				case "accept", "drop", "reject", "return", "masquerade", "snat", "dnat", "redirect":
					target = strings.ToUpper(key)
				case "jump", "goto":
					var j struct {
						Target string `json:"target"`
					}
					if json.Unmarshal(value, &j) == nil {
						target = j.Target
					}
				}
			}
		}
		if counter == nil {
			continue
		}
		table := strings.TrimSpace(rule.Family + " " + rule.Table)
		ordinal[table+"/"+rule.Chain]++
		out = append(out, firewallRuleCounter{
			Key:     firewallRuleKey(table, rule.Chain, rule.Comment, strconv.Itoa(rule.Handle)),
			Table:   table,
			Chain:   rule.Chain,
			Name:    cleanFirewallRuleName(rule.Comment, rule.Chain, ordinal[table+"/"+rule.Chain]),
			Target:  target,
			Packets: counter.Packets,
			Bytes:   counter.Bytes,
		})
	}
	return out
}

func firewallRuleKey(table, chain, name, spec string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(table + "\x00" + chain + "\x00" + name + "\x00" + spec))
	return fmt.Sprintf("fw-%08x", h.Sum32())
}

func cleanFirewallRuleName(comment, chain string, ordinal int) string {
	name := strings.TrimSpace(comment)
	for _, prefix := range []string{"!fw3: ", "!fw4: ", "!fw3:", "!fw4:"} {
		name = strings.TrimPrefix(name, prefix)
	}
	if name == "" || name == "!fw3" || name == "!fw4" {
		return fmt.Sprintf("%s #%d", chain, ordinal)
	}
	return name
}

// topFirewallRules keeps named (OpenWrt/user) rules first, then the busiest
// unnamed ones, bounded by TrafficTelemetryMaxFirewallRules.
func topFirewallRules(rules []firewallRuleCounter) []firewallRuleCounter {
	seen := make(map[string]bool, len(rules))
	unique := rules[:0]
	for _, rule := range rules {
		if seen[rule.Key] {
			continue
		}
		seen[rule.Key] = true
		unique = append(unique, rule)
	}
	named := func(r firewallRuleCounter) bool { return !strings.Contains(r.Name, " #") }
	sort.SliceStable(unique, func(i, j int) bool {
		if named(unique[i]) != named(unique[j]) {
			return named(unique[i])
		}
		return unique[i].Packets > unique[j].Packets
	})
	if len(unique) > wusp.TrafficTelemetryMaxFirewallRules {
		unique = unique[:wusp.TrafficTelemetryMaxFirewallRules]
	}
	sort.SliceStable(unique, func(i, j int) bool {
		if unique[i].Table != unique[j].Table {
			return unique[i].Table < unique[j].Table
		}
		return unique[i].Chain < unique[j].Chain
	})
	return unique
}

// readLinkSpeed returns the negotiated speed (Mbit/s) and duplex of a
// physical port from sysfs; virtual devices report nothing.
func readLinkSpeed(netClassDir, name string) (int, string) {
	if netClassDir == "" {
		netClassDir = "/sys/class/net"
	}
	speed := 0
	if data, err := os.ReadFile(filepath.Join(netClassDir, name, "speed")); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && v > 0 && v < 1_000_000 {
			speed = v
		}
	}
	duplex := "Unknown"
	if data, err := os.ReadFile(filepath.Join(netClassDir, name, "duplex")); err == nil {
		switch strings.TrimSpace(string(data)) {
		case "full":
			duplex = "Full"
		case "half":
			duplex = "Half"
		}
	}
	return speed, duplex
}

// readBridgeHosts reads every Linux bridge forwarding database through the
// binary /sys/class/net/<bridge>/brforward interface (struct __fdb_entry,
// 16 bytes) and maps each remote MAC to its bridge port and that port's link.
func readBridgeHosts(netClassDir string) []wiredHostSample {
	if netClassDir == "" {
		netClassDir = "/sys/class/net"
	}
	entries, err := os.ReadDir(netClassDir)
	if err != nil {
		return nil
	}
	var out []wiredHostSample
	seen := make(map[string]bool)
	for _, entry := range entries {
		bridge := entry.Name()
		if _, err := os.Stat(filepath.Join(netClassDir, bridge, "bridge")); err != nil {
			continue
		}
		ports := make(map[int]string)
		portDirs, _ := os.ReadDir(filepath.Join(netClassDir, bridge, "brif"))
		for _, port := range portDirs {
			data, err := os.ReadFile(filepath.Join(netClassDir, bridge, "brif", port.Name(), "port_no"))
			if err != nil {
				continue
			}
			if n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 0, 32); err == nil {
				ports[int(n)] = port.Name()
			}
		}
		raw, err := os.ReadFile(filepath.Join(netClassDir, bridge, "brforward"))
		if err != nil {
			continue
		}
		for _, host := range parseBridgeFDB(raw) {
			port := ports[host.portNo]
			key := host.mac.String()
			if port == "" || seen[key] {
				continue
			}
			seen[key] = true
			speed, duplex := readLinkSpeed(netClassDir, port)
			out = append(out, wiredHostSample{MAC: host.mac, Bridge: bridge, Port: port, LinkSpeed: speed, Duplex: duplex, Idle: host.idleSeconds})
			if len(out) >= wusp.TrafficTelemetryMaxWiredHosts {
				return out
			}
		}
	}
	return out
}

type fdbEntry struct {
	mac         net.HardwareAddr
	portNo      int
	idleSeconds uint32
}

func parseBridgeFDB(raw []byte) []fdbEntry {
	const size = 16
	var out []fdbEntry
	for off := 0; off+size <= len(raw); off += size {
		rec := raw[off : off+size]
		if rec[7] != 0 { // is_local: the bridge's own addresses
			continue
		}
		mac := net.HardwareAddr(append([]byte(nil), rec[0:6]...))
		if mac[0]&1 != 0 {
			continue
		}
		out = append(out, fdbEntry{
			mac:    mac,
			portNo: int(rec[12])<<8 | int(rec[6]),
			// ageing_timer_value is in USER_HZ (100) clock ticks.
			idleSeconds: binary.NativeEndian.Uint32(rec[8:12]) / 100,
		})
	}
	return out
}
