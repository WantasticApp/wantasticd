package platforms

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/platform/dns"
	"wantastic-agent/internal/wusp"
)

// Device.WUSP_DNS: the device's own resolver list, read and written through
// the platform's DNS manager. Values are persisted by that manager (UCI,
// systemd-resolved drop-in, NetworkManager profile, macOS service, Windows
// adapter); where the manager is volatile (Debian resolvconf, plain
// resolv.conf rewritten by DHCP) the agent keeps the list in its state and
// re-applies it at start.

const dnsControlCacheTTL = time.Minute

var dnsControlCache = struct {
	mu    sync.Mutex
	at    time.Time
	state dns.ControlState
}{}

var (
	readDNSControl = dns.ReadControl
	setDNSServers  = dns.SetServers
)

func cachedDNSControl(ctx context.Context) dns.ControlState {
	dnsControlCache.mu.Lock()
	defer dnsControlCache.mu.Unlock()
	if !dnsControlCache.at.IsZero() && time.Since(dnsControlCache.at) < dnsControlCacheTTL {
		return dnsControlCache.state
	}
	dnsControlCache.state = readDNSControl(ctx)
	dnsControlCache.at = time.Now()
	return dnsControlCache.state
}

func invalidateDNSControl() {
	dnsControlCache.mu.Lock()
	dnsControlCache.at = time.Time{}
	dnsControlCache.mu.Unlock()
}

func appendDNSControlFields(msg *wusp.Message, st dns.ControlState) {
	p := wusp.WUSPDNSPrefix
	method := st.Method
	if method == "" {
		method = "unsupported"
	}
	appendField(msg, p+"Supported", wusp.Bool(st.Supported))
	appendField(msg, p+"Method", wusp.String(method))
	mode := "Automatic"
	if st.Manual {
		mode = "Manual"
	}
	appendField(msg, p+"Mode", wusp.String(mode))
	appendField(msg, p+"Servers", stringListValue(st.Servers))
	appendField(msg, p+"EffectiveServers", stringListValue(st.Effective))
	reason := st.Reason
	if len(reason) > 256 {
		reason = reason[:256]
	}
	appendField(msg, p+"LastError", wusp.String(reason))
}

func stringListValue(items []string) wusp.Value {
	values := make([]wusp.Value, 0, len(items))
	for _, item := range items {
		values = append(values, wusp.String(item))
	}
	return wusp.List(values...)
}

func hostKindSupportsDNSControl(kind Kind) bool {
	return kind == KindLinux || kind == KindONU || kind == KindMacOS || kind == KindWindows
}

func (b *hostBackend) setDNSServers(ctx context.Context, value wusp.Value) error {
	servers, err := dns.NormalizeServers(valueStringList(value))
	if err != nil {
		return err
	}
	if err := setDNSServers(ctx, servers); err != nil {
		return err
	}
	invalidateDNSControl()
	return b.updateState(func(state *hostState) { state.DNSServers = servers })
}

var dnsReapplyOnce sync.Once

// reapplyPersistedDNS restores a manual list on managers that do not keep it
// across reboots or DHCP renewals.
func (b *hostBackend) reapplyPersistedDNS(ctx context.Context) {
	dnsReapplyOnce.Do(func() {
		state, _ := b.readState()
		if len(state.DNSServers) == 0 {
			return
		}
		current := readDNSControl(ctx)
		if current.Method != "resolvconf" && current.Method != "resolv.conf" {
			return
		}
		if current.Manual && sameStringSlice(current.Servers, state.DNSServers) {
			return
		}
		if err := setDNSServers(ctx, state.DNSServers); err != nil {
			fmt.Fprintf(os.Stderr, "[USP] DNS re-apply failed: %v\n", err)
		}
		invalidateDNSControl()
	})
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- OpenWrt: dnsmasq upstream resolvers ------------------------------------

const openWrtResolvAuto = "/tmp/resolv.conf.d/resolv.conf.auto"

func (b *OpenWrtBackend) openWrtDNSControl() (dns.ControlState, string, []string, error) {
	dhcp, err := b.readUCIConfig("dhcp")
	if err != nil {
		return dns.ControlState{Method: "openwrt-dnsmasq", Reason: err.Error()}, "", nil, err
	}
	ref := ""
	var section openWrtUCISection
	typeIndex := 0
	for _, s := range dhcp.Sections {
		if s.Type != "dnsmasq" {
			continue
		}
		section = s
		ref = s.Name
		if ref == "" {
			ref = fmt.Sprintf("@dnsmasq[%d]", typeIndex)
		}
		break
	}
	if ref == "" {
		st := dns.ControlState{Method: "openwrt-dnsmasq", Reason: "dnsmasq is not configured on this device"}
		return st, "", nil, fmt.Errorf("%s", st.Reason)
	}
	var manual, other []string
	for _, entry := range section.Lists["server"] {
		if net.ParseIP(strings.TrimSpace(entry)) != nil {
			manual = append(manual, strings.TrimSpace(entry))
		} else {
			other = append(other, entry) // domain-specific forwarders stay untouched
		}
	}
	noresolv := parseOpenWrtBool(section.Options["noresolv"], false)
	st := dns.ControlState{Supported: true, Method: "openwrt-dnsmasq", Manual: noresolv && len(manual) > 0}
	if st.Manual {
		st.Servers = manual
		st.Effective = manual
	} else {
		auto := readResolvFileServers(openWrtResolvAuto)
		if len(auto) == 0 {
			auto = readResolvFileServers("/tmp/resolv.conf.auto")
		}
		st.Effective = append(append([]string{}, manual...), auto...)
	}
	return st, ref, other, nil
}

func (b *OpenWrtBackend) appendOpenWrtDNSControlFields(msg *wusp.Message) {
	st, _, _, _ := b.openWrtDNSControl()
	appendDNSControlFields(msg, st)
}

// setOpenWrtDNSServers writes dnsmasq's upstream list and reloads dnsmasq
// only (no interface restart). An empty list returns to ISP resolvers.
func (b *OpenWrtBackend) setOpenWrtDNSServers(ctx context.Context, value wusp.Value) error {
	servers, err := dns.NormalizeServers(valueStringList(value))
	if err != nil {
		return err
	}
	_, ref, other, err := b.openWrtDNSControl()
	if err != nil {
		return err
	}
	if err := b.writeUCIListViaFile("dhcp", ref, "server", append(append([]string{}, servers...), other...)); err != nil {
		return err
	}
	noresolv := ""
	if len(servers) > 0 {
		noresolv = "1"
	}
	if err := b.writeUCIOptionViaFile("dhcp", ref, "noresolv", noresolv); err != nil {
		return err
	}
	return b.reloadScript(ctx, dnsmasqReloadScript)
}

func readResolvFileServers(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}
