package exitnode

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
)

// RouteKind says where a planned route points.
type RouteKind string

const (
	// RouteTunnel sends the prefix into the tunnel interface.
	RouteTunnel RouteKind = "tunnel"
	// RouteBypass pins a host to the original default gateway so the tunnel's
	// own UDP (hub, peers, hole punching) never loops into itself.
	RouteBypass RouteKind = "bypass"
	// RouteReject makes the prefix unreachable (IPv6 leak prevention).
	RouteReject RouteKind = "reject"
)

// Route is one planned or installed route.
type Route struct {
	Dst  netip.Prefix `json:"dst"`
	Kind RouteKind    `json:"kind"`
}

func (r Route) key() string { return string(r.Kind) + " " + r.Dst.String() }

// Gateway is the original default route the bypass routes keep using.
type Gateway struct {
	Interface string     `json:"interface"`
	Addr      netip.Addr `json:"addr"`
	// IfIndex is needed on Windows only.
	IfIndex int `json:"if_index,omitempty"`
}

func (g Gateway) Valid() bool { return g.Interface != "" || g.Addr.IsValid() }

// Split default routes: more specific than any 0.0.0.0/0, so the original
// default route stays untouched and comes back by itself when these go.
var (
	splitV4 = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	splitV6 = []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
)

// ClientPlan is the input to PlanClientRoutes.
type ClientPlan struct {
	// Bypass are the addresses the tunnel itself talks to: the hub, the exit
	// peer's endpoint and other P2P endpoints/candidates.
	Bypass []netip.Addr
	// OnLink reports whether an address is reachable on a directly connected
	// (non-tunnel) subnet; such addresses must not be pinned to the gateway.
	OnLink func(netip.Addr) bool
	// Overlay prefixes are tenant addresses carried by the tunnel anyway.
	Overlay []netip.Prefix
	// BlockIPv6 installs reject routes for global IPv6 so it cannot leak
	// around an IPv4-only exit.
	BlockIPv6 bool
	// MaxBypass caps host routes (0 = 64).
	MaxBypass int
}

// PlanClientRoutes returns the routes exit-node client mode needs, bypass
// routes first (they must exist before the split default goes in).
func PlanClientRoutes(p ClientPlan) []Route {
	max := p.MaxBypass
	if max <= 0 {
		max = 64
	}
	seen := map[netip.Addr]bool{}
	var bypass []netip.Addr
	for _, a := range p.Bypass {
		a = a.Unmap()
		if !a.Is4() || seen[a] || !bypassable(a) {
			continue
		}
		if inAny(a, p.Overlay) || (p.OnLink != nil && p.OnLink(a)) {
			continue
		}
		seen[a] = true
		bypass = append(bypass, a)
	}
	sort.Slice(bypass, func(i, j int) bool { return bypass[i].Less(bypass[j]) })
	if len(bypass) > max {
		bypass = bypass[:max]
	}
	out := make([]Route, 0, len(bypass)+4)
	for _, a := range bypass {
		out = append(out, Route{Dst: netip.PrefixFrom(a, 32), Kind: RouteBypass})
	}
	for _, p := range splitV4 {
		out = append(out, Route{Dst: p, Kind: RouteTunnel})
	}
	if p.BlockIPv6 {
		for _, p := range splitV6 {
			out = append(out, Route{Dst: p, Kind: RouteReject})
		}
	}
	return out
}

func bypassable(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() &&
		!a.IsLinkLocalUnicast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func inAny(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Bits() > 0 && p.Contains(a) {
			return true
		}
	}
	return false
}

// DiffRoutes returns what to add and remove to go from current to desired.
// Removals come back in reverse install order (split default before bypass).
func DiffRoutes(current, desired []Route) (add, del []Route) {
	cur := map[string]bool{}
	for _, r := range current {
		cur[r.key()] = true
	}
	want := map[string]bool{}
	for _, r := range desired {
		want[r.key()] = true
		if !cur[r.key()] {
			add = append(add, r)
		}
	}
	for i := len(current) - 1; i >= 0; i-- {
		if !want[current[i].key()] {
			del = append(del, current[i])
		}
	}
	return add, del
}

// RouteAddCmd builds the command installing r on goos.
func RouteAddCmd(goos string, r Route, tun string, gw Gateway) (Cmd, error) {
	return routeCmd(goos, r, tun, gw, true)
}

// RouteDelCmd builds the command removing r on goos.
func RouteDelCmd(goos string, r Route, tun string, gw Gateway) (Cmd, error) {
	return routeCmd(goos, r, tun, gw, false)
}

func routeCmd(goos string, r Route, tun string, gw Gateway, add bool) (Cmd, error) {
	dst := r.Dst.Masked().String()
	switch goos {
	case "darwin":
		op := "delete"
		if add {
			op = "add"
		}
		switch r.Kind {
		case RouteTunnel:
			return Cmd{Name: "/sbin/route", Args: []string{"-n", op, family(r), dst, "-interface", tun}}, nil
		case RouteBypass:
			if gw.Addr.IsValid() {
				return Cmd{Name: "/sbin/route", Args: []string{"-n", op, family(r), dst, gw.Addr.String()}}, nil
			}
			if gw.Interface == "" {
				return Cmd{}, fmt.Errorf("no gateway for bypass route %s", dst)
			}
			return Cmd{Name: "/sbin/route", Args: []string{"-n", op, family(r), dst, "-interface", gw.Interface}}, nil
		case RouteReject:
			if add {
				return Cmd{Name: "/sbin/route", Args: []string{"-n", "add", family(r), dst, "::1", "-reject"}}, nil
			}
			return Cmd{Name: "/sbin/route", Args: []string{"-n", "delete", family(r), dst}}, nil
		}
	case "linux":
		op := "del"
		if add {
			op = "replace"
		}
		switch r.Kind {
		case RouteTunnel:
			return Cmd{Name: "ip", Args: []string{"route", op, dst, "dev", tun}}, nil
		case RouteBypass:
			args := []string{"route", op, dst}
			if gw.Addr.IsValid() {
				args = append(args, "via", gw.Addr.String())
			}
			if gw.Interface != "" {
				args = append(args, "dev", gw.Interface)
			}
			if len(args) == 3 {
				return Cmd{}, fmt.Errorf("no gateway for bypass route %s", dst)
			}
			return Cmd{Name: "ip", Args: args}, nil
		case RouteReject:
			return Cmd{Name: "ip", Args: []string{"-6", "route", op, "unreachable", dst}}, nil
		}
	case "windows":
		op := "delete"
		if add {
			op = "add"
		}
		switch r.Kind {
		case RouteTunnel:
			args := []string{"interface", "ipv4", op, "route", "prefix=" + dst, "interface=" + tun}
			if add {
				args = append(args, "metric=5", "store=active")
			}
			return Cmd{Name: "netsh", Args: args}, nil
		case RouteBypass:
			if gw.IfIndex <= 0 || !gw.Addr.IsValid() {
				return Cmd{}, fmt.Errorf("no gateway for bypass route %s", dst)
			}
			args := []string{"interface", "ipv4", op, "route", "prefix=" + dst, "interface=" + strconv.Itoa(gw.IfIndex), "nexthop=" + gw.Addr.String()}
			if add {
				args = append(args, "store=active")
			}
			return Cmd{Name: "netsh", Args: args}, nil
		case RouteReject:
			return Cmd{}, fmt.Errorf("IPv6 reject routes are not supported on Windows")
		}
	}
	return Cmd{}, fmt.Errorf("routes of kind %q are not supported on %s", r.Kind, goos)
}

func family(r Route) string {
	if r.Dst.Addr().Is6() {
		return "-inet6"
	}
	return "-inet"
}
