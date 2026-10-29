package exitnode

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// NATBackend names the packet filter carrying the NAT rules.
type NATBackend string

const (
	BackendPF       NATBackend = "pf"       // macOS
	BackendIPTables NATBackend = "iptables" // Linux iptables (legacy or -nft)
	BackendFW4      NATBackend = "nft-fw4"  // OpenWrt fw4: rules inserted into inet fw4
	BackendNft      NATBackend = "nft"      // plain nftables: own table
)

// NAT modes.
const (
	// ModeExit masquerades overlay sources out of the uplink (exit host).
	ModeExit = "exit"
	// ModeClient masquerades forwarded LAN sources into the tunnel, so hosts
	// behind a router using an exit node keep working.
	ModeClient = "client"
)

// PFAnchor is a child of "com.apple": the stock macOS /etc/pf.conf already
// evaluates nat-anchor "com.apple/*", so the rules apply without touching the
// main ruleset (an anchor elsewhere would never be consulted).
const PFAnchor = "com.apple/wantasticd-exit"

// ErrUnsupported marks platforms without an automatic NAT backend.
var ErrUnsupported = errors.New("not supported on this platform")

// NATPlan describes the NAT/forwarding rules for one mode.
type NATPlan struct {
	Backend NATBackend     `json:"backend"`
	Mode    string         `json:"mode"`
	Tun     string         `json:"tun"`
	Uplink  string         `json:"uplink,omitempty"`  // exit: WAN interface
	Sources []netip.Prefix `json:"sources,omitempty"` // exit: overlay prefixes
	Own     netip.Addr     `json:"own,omitempty"`     // client: own overlay IPv4
}

var ifNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,15}$`)

func (p NATPlan) validate() error {
	if !ifNameRE.MatchString(p.Tun) {
		return fmt.Errorf("invalid tunnel interface %q", p.Tun)
	}
	switch p.Mode {
	case ModeExit:
		if !ifNameRE.MatchString(p.Uplink) {
			return fmt.Errorf("invalid uplink interface %q", p.Uplink)
		}
		if len(p.Sources) == 0 {
			return errors.New("no overlay source prefixes")
		}
		for _, s := range p.Sources {
			if !s.IsValid() || !s.Addr().Is4() || s.Bits() == 0 {
				return fmt.Errorf("invalid source prefix %s", s)
			}
		}
	case ModeClient:
		if !p.Own.Is4() {
			return errors.New("client NAT needs the device's overlay IPv4")
		}
	default:
		return fmt.Errorf("unknown NAT mode %q", p.Mode)
	}
	return nil
}

func (p NATPlan) tag() string { return "wantasticd-" + p.Mode }

// ── pf (macOS) ──────────────────────────────────────────────────────────────

// PFRules is the anchor ruleset for an exit plan.
func PFRules(p NATPlan) string {
	var b strings.Builder
	for _, s := range p.Sources {
		fmt.Fprintf(&b, "nat on %s inet from %s to any -> (%s)\n", p.Uplink, s.Masked(), p.Uplink)
	}
	return b.String()
}

func PFLoadCmd(p NATPlan) Cmd {
	return Cmd{Name: "/sbin/pfctl", Args: []string{"-a", PFAnchor, "-f", "-"}, Stdin: PFRules(p)}
}
func PFFlushCmd() Cmd { return Cmd{Name: "/sbin/pfctl", Args: []string{"-a", PFAnchor, "-F", "all"}} }
func PFShowNATCmd() Cmd {
	return Cmd{Name: "/sbin/pfctl", Args: []string{"-a", PFAnchor, "-s", "nat"}}
}

// PFEnableCmd takes a pf enable reference; PFReleaseCmd gives it back, so pf
// stays on only if something else also enabled it.
func PFEnableCmd() Cmd              { return Cmd{Name: "/sbin/pfctl", Args: []string{"-E"}} }
func PFReleaseCmd(token string) Cmd { return Cmd{Name: "/sbin/pfctl", Args: []string{"-X", token}} }

var pfTokenRE = regexp.MustCompile(`(?m)^Token\s*:\s*(\d+)`)

// ParsePFToken extracts the reference token printed by `pfctl -E`.
func ParsePFToken(out string) string {
	if m := pfTokenRE.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// ── iptables ────────────────────────────────────────────────────────────────

// IPTRule is one iptables rule; Insert puts it at the top of the chain.
type IPTRule struct {
	Table, Chain string
	Insert       bool
	Args         []string
}

// IPTablesRules returns the rules for a plan.
func IPTablesRules(p NATPlan) []IPTRule {
	if p.Mode == ModeClient {
		return []IPTRule{{Table: "nat", Chain: "POSTROUTING", Args: []string{"-o", p.Tun, "!", "-s", p.Own.String() + "/32", "-j", "MASQUERADE"}}}
	}
	var rules []IPTRule
	for _, s := range p.Sources {
		src := s.Masked().String()
		rules = append(rules,
			IPTRule{Table: "nat", Chain: "POSTROUTING", Args: []string{"-s", src, "-o", p.Uplink, "-j", "MASQUERADE"}},
			IPTRule{Table: "filter", Chain: "FORWARD", Insert: true, Args: []string{"-i", p.Tun, "-o", p.Uplink, "-s", src, "-j", "ACCEPT"}},
			IPTRule{Table: "filter", Chain: "FORWARD", Insert: true, Args: []string{"-i", p.Uplink, "-o", p.Tun, "-d", src, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
		)
	}
	return rules
}

func (r IPTRule) CheckCmd(bin string) Cmd {
	return Cmd{Name: bin, Args: append([]string{"-t", r.Table, "-C", r.Chain}, r.Args...)}
}
func (r IPTRule) AddCmd(bin string) Cmd {
	if r.Insert {
		return Cmd{Name: bin, Args: append([]string{"-t", r.Table, "-I", r.Chain, "1"}, r.Args...)}
	}
	return Cmd{Name: bin, Args: append([]string{"-t", r.Table, "-A", r.Chain}, r.Args...)}
}
func (r IPTRule) DelCmd(bin string) Cmd {
	return Cmd{Name: bin, Args: append([]string{"-t", r.Table, "-D", r.Chain}, r.Args...)}
}

// ── nftables ────────────────────────────────────────────────────────────────

func q(s string) string { return `"` + s + `"` }

// FW4Script inserts the plan's rules into OpenWrt's inet fw4 table, tagged
// with a comment so teardown finds exactly these rules.
func FW4Script(p NATPlan) string {
	c := "comment " + q(p.tag())
	var b strings.Builder
	if p.Mode == ModeClient {
		fmt.Fprintf(&b, "insert rule inet fw4 forward oifname %s counter accept %s\n", q(p.Tun), c)
		fmt.Fprintf(&b, "insert rule inet fw4 forward iifname %s ct state established,related counter accept %s\n", q(p.Tun), c)
		fmt.Fprintf(&b, "insert rule inet fw4 srcnat oifname %s ip saddr != %s counter masquerade %s\n", q(p.Tun), p.Own, c)
		return b.String()
	}
	for _, s := range p.Sources {
		src := s.Masked().String()
		fmt.Fprintf(&b, "insert rule inet fw4 forward iifname %s oifname %s ip saddr %s counter accept %s\n", q(p.Tun), q(p.Uplink), src, c)
		fmt.Fprintf(&b, "insert rule inet fw4 forward iifname %s oifname %s ip daddr %s ct state established,related counter accept %s\n", q(p.Uplink), q(p.Tun), src, c)
		fmt.Fprintf(&b, "insert rule inet fw4 srcnat oifname %s ip saddr %s counter masquerade %s\n", q(p.Uplink), src, c)
	}
	return b.String()
}

func fw4RuleCount(p NATPlan) int {
	if p.Mode == ModeClient {
		return 3
	}
	return 3 * len(p.Sources)
}

func NftScriptCmd(script string) Cmd {
	return Cmd{Name: "nft", Args: []string{"-f", "-"}, Stdin: script}
}
func FW4ListCmd() Cmd { return Cmd{Name: "nft", Args: []string{"-a", "list", "table", "inet", "fw4"}} }
func FW4DeleteCmd(chain string, handle int) Cmd {
	return Cmd{Name: "nft", Args: []string{"delete", "rule", "inet", "fw4", chain, "handle", strconv.Itoa(handle)}}
}

// NftHandle locates one tagged rule.
type NftHandle struct {
	Chain  string
	Handle int
}

var (
	nftChainRE  = regexp.MustCompile(`^\s*chain\s+(\S+)\s*\{`)
	nftHandleRE = regexp.MustCompile(`#\s*handle\s+(\d+)\s*$`)
)

// ParseNftHandles finds the rules carrying comment tag in `nft -a list` output.
func ParseNftHandles(out, tag string) []NftHandle {
	var res []NftHandle
	chain := ""
	needle := "comment " + q(tag)
	for _, line := range strings.Split(out, "\n") {
		if m := nftChainRE.FindStringSubmatch(line); m != nil {
			chain = m[1]
			continue
		}
		if chain == "" || !strings.Contains(line, needle) {
			continue
		}
		if m := nftHandleRE.FindStringSubmatch(line); m != nil {
			h, _ := strconv.Atoi(m[1])
			res = append(res, NftHandle{Chain: chain, Handle: h})
		}
	}
	return res
}

func nftTableName(p NATPlan) string { return "wantasticd_" + p.Mode }

// NftTableScript (re)creates a dedicated table. The leading empty table +
// delete makes it idempotent on nft versions without "destroy".
func NftTableScript(p NATPlan) string {
	name := nftTableName(p)
	var b strings.Builder
	fmt.Fprintf(&b, "table ip %s {\n}\ndelete table ip %s\ntable ip %s {\n", name, name, name)
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority -5; policy accept;\n")
	if p.Mode == ModeClient {
		fmt.Fprintf(&b, "\t\toifname %s accept\n", q(p.Tun))
		fmt.Fprintf(&b, "\t\tiifname %s ct state established,related accept\n", q(p.Tun))
	} else {
		for _, s := range p.Sources {
			fmt.Fprintf(&b, "\t\tiifname %s oifname %s ip saddr %s accept\n", q(p.Tun), q(p.Uplink), s.Masked())
			fmt.Fprintf(&b, "\t\tiifname %s oifname %s ip daddr %s ct state established,related accept\n", q(p.Uplink), q(p.Tun), s.Masked())
		}
	}
	b.WriteString("\t}\n\tchain postrouting {\n\t\ttype nat hook postrouting priority 100; policy accept;\n")
	if p.Mode == ModeClient {
		fmt.Fprintf(&b, "\t\toifname %s ip saddr != %s masquerade\n", q(p.Tun), p.Own)
	} else {
		for _, s := range p.Sources {
			fmt.Fprintf(&b, "\t\toifname %s ip saddr %s masquerade\n", q(p.Uplink), s.Masked())
		}
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func NftTableDeleteCmd(p NATPlan) Cmd {
	return Cmd{Name: "nft", Args: []string{"delete", "table", "ip", nftTableName(p)}}
}
func NftTableListCmd(p NATPlan) Cmd {
	return Cmd{Name: "nft", Args: []string{"list", "table", "ip", nftTableName(p)}}
}

// ── forwarding ──────────────────────────────────────────────────────────────

const linuxIPForward = "/proc/sys/net/ipv4/ip_forward"

func DarwinForwardGetCmd() Cmd {
	return Cmd{Name: "/usr/sbin/sysctl", Args: []string{"-n", "net.inet.ip.forwarding"}}
}
func DarwinForwardSetCmd(v string) Cmd {
	return Cmd{Name: "/usr/sbin/sysctl", Args: []string{"-w", "net.inet.ip.forwarding=" + v}}
}

// ── manager ─────────────────────────────────────────────────────────────────

// NATState is what was applied, persisted for crash-safe teardown.
type NATState struct {
	Plan        NATPlan `json:"plan"`
	PFToken     string  `json:"pf_token,omitempty"`
	PrevForward string  `json:"prev_forward,omitempty"` // "0"/"1"; "" = untouched
}

func (h Host) iptablesBin() string {
	return h.firstExisting("iptables", "/usr/sbin/iptables", "/sbin/iptables", "/usr/sbin/iptables-nft", "/sbin/iptables-nft")
}

func (h Host) hasNft() bool {
	return h.Exists != nil && (h.Exists("/usr/sbin/nft") || h.Exists("/sbin/nft") || h.Exists("/usr/bin/nft"))
}

// DetectBackend picks the NAT backend for this host. On Linux fw4 wins even
// when an iptables binary exists: iptables-nft rules live in a separate
// table and cannot override fw4's forward policy.
func DetectBackend(h Host) (NATBackend, error) {
	switch h.OS {
	case "darwin":
		return BackendPF, nil
	case "linux":
		if h.hasNft() {
			if _, err := h.Run(Cmd{Name: "nft", Args: []string{"list", "table", "inet", "fw4"}}); err == nil {
				return BackendFW4, nil
			}
		}
		if bin := h.iptablesBin(); bin != "iptables" {
			return BackendIPTables, nil
		}
		if h.hasNft() {
			return BackendNft, nil
		}
		return "", errors.New("neither iptables nor nft is installed")
	case "windows":
		return "", fmt.Errorf("exit-node NAT is %w (Windows has no built-in NAT without Hyper-V WinNAT or Internet Connection Sharing)", ErrUnsupported)
	}
	return "", fmt.Errorf("exit-node NAT is %w (%s)", ErrUnsupported, h.OS)
}

// EnableNAT applies plan. On failure it rolls back what it applied.
func EnableNAT(h Host, plan NATPlan) (NATState, error) {
	if err := plan.validate(); err != nil {
		return NATState{}, err
	}
	st := NATState{Plan: plan}
	if plan.Mode == ModeExit {
		prev, err := enableForwarding(h)
		if err != nil {
			return NATState{}, fmt.Errorf("enable IP forwarding: %w", err)
		}
		st.PrevForward = prev
	}
	if err := applyRules(h, &st); err != nil {
		_ = DisableNAT(h, st)
		return NATState{}, err
	}
	return st, nil
}

func applyRules(h Host, st *NATState) error {
	p := st.Plan
	switch p.Backend {
	case BackendPF:
		if p.Mode != ModeExit {
			return nil
		}
		if _, err := h.Run(PFLoadCmd(p)); err != nil {
			return fmt.Errorf("load pf anchor %s: %w", PFAnchor, err)
		}
		if st.PFToken == "" {
			out, err := h.Run(PFEnableCmd())
			if err != nil {
				return fmt.Errorf("enable pf: %w", err)
			}
			st.PFToken = ParsePFToken(string(out))
		}
	case BackendIPTables:
		bin := h.iptablesBin()
		for _, r := range IPTablesRules(p) {
			if _, err := h.Run(r.CheckCmd(bin)); err == nil {
				continue
			}
			if _, err := h.Run(r.AddCmd(bin)); err != nil {
				return fmt.Errorf("iptables: %w", err)
			}
		}
	case BackendFW4:
		removeFW4(h, p)
		if _, err := h.Run(NftScriptCmd(FW4Script(p))); err != nil {
			return fmt.Errorf("nft fw4: %w", err)
		}
	case BackendNft:
		if _, err := h.Run(NftScriptCmd(NftTableScript(p))); err != nil {
			return fmt.Errorf("nft: %w", err)
		}
	default:
		return fmt.Errorf("unknown NAT backend %q", p.Backend)
	}
	return nil
}

func removeFW4(h Host, p NATPlan) int {
	out, err := h.Run(FW4ListCmd())
	if err != nil {
		return 0
	}
	hs := ParseNftHandles(string(out), p.tag())
	for _, x := range hs {
		_, _ = h.Run(FW4DeleteCmd(x.Chain, x.Handle))
	}
	return len(hs)
}

// DisableNAT removes everything st applied; safe to call repeatedly.
func DisableNAT(h Host, st NATState) error {
	p := st.Plan
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	switch p.Backend {
	case BackendPF:
		_, err := h.Run(PFFlushCmd())
		note(err)
		if st.PFToken != "" {
			_, _ = h.Run(PFReleaseCmd(st.PFToken)) // stale tokens after reboot fail harmlessly
		}
	case BackendIPTables:
		bin := h.iptablesBin()
		for _, r := range IPTablesRules(p) {
			for i := 0; i < 4; i++ { // remove duplicates too
				if _, err := h.Run(r.CheckCmd(bin)); err != nil {
					break
				}
				if _, err := h.Run(r.DelCmd(bin)); err != nil {
					note(err)
					break
				}
			}
		}
	case BackendFW4:
		removeFW4(h, p)
	case BackendNft:
		_, _ = h.Run(NftTableDeleteCmd(p))
	}
	if st.PrevForward == "0" {
		note(restoreForwarding(h))
	}
	return firstErr
}

// EnsureNAT re-applies rules a firewall reload removed. It reports whether a
// repair was needed.
func EnsureNAT(h Host, st *NATState) (bool, error) {
	p := st.Plan
	present := true
	switch p.Backend {
	case BackendPF:
		out, err := h.Run(PFShowNATCmd())
		present = err == nil && strings.Contains(string(out), "nat on")
	case BackendIPTables:
		bin := h.iptablesBin()
		for _, r := range IPTablesRules(p) {
			if _, err := h.Run(r.CheckCmd(bin)); err != nil {
				present = false
				break
			}
		}
	case BackendFW4:
		out, err := h.Run(FW4ListCmd())
		present = err == nil && len(ParseNftHandles(string(out), p.tag())) == fw4RuleCount(p)
	case BackendNft:
		_, err := h.Run(NftTableListCmd(p))
		present = err == nil
	}
	if present {
		return false, nil
	}
	return true, applyRules(h, st)
}

func enableForwarding(h Host) (string, error) {
	switch h.OS {
	case "darwin":
		out, err := h.Run(DarwinForwardGetCmd())
		if err != nil {
			return "", err
		}
		prev := strings.TrimSpace(string(out))
		if prev == "1" {
			return "1", nil
		}
		_, err = h.Run(DarwinForwardSetCmd("1"))
		return "0", err
	case "linux":
		data, err := h.ReadFile(linuxIPForward)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(string(data)) == "1" {
			return "1", nil
		}
		return "0", h.WriteFile(linuxIPForward, []byte("1"))
	}
	return "", ErrUnsupported
}

func restoreForwarding(h Host) error {
	switch h.OS {
	case "darwin":
		_, err := h.Run(DarwinForwardSetCmd("0"))
		return err
	case "linux":
		return h.WriteFile(linuxIPForward, []byte("0"))
	}
	return nil
}
