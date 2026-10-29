package device

import (
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"wantastic-agent/internal/device/wireguard-go/tun"
	"wantastic-agent/internal/exitnode"
)

// exitGuard enforces the exit-node opt-in on the receive path: a peer can only
// get internet-bound packets forwarded by this host when exit-node is on
// here. Tenant/overlay, LAN (private) and own-address traffic is never
// touched, so device<->peer reachability cannot be affected.
type exitGuard struct {
	allow  atomic.Bool
	tenant atomic.Pointer[[]netip.Prefix]

	// users: overlay source -> last seen (unix seconds).
	users    sync.Map
	onNew    atomic.Pointer[func(netip.Addr)]
	lastDrop atomic.Int64
	dropped  atomic.Uint64
}

func newExitGuard() *exitGuard { return &exitGuard{} }

func (g *exitGuard) setTenant(addrs []netip.Prefix, allowed []string) {
	var ps []netip.Prefix
	for _, a := range addrs {
		ps = append(ps, a.Masked())
	}
	for _, s := range allowed {
		if p, err := netip.ParsePrefix(s); err == nil && p.Bits() > 0 {
			ps = append(ps, p.Masked())
		}
	}
	g.tenant.Store(&ps)
}

// forwardable reports whether a packet written toward the host may pass.
func (g *exitGuard) forwardable(pkt []byte, now int64) bool {
	src, dst, ok := exitnode.PacketAddrs(pkt)
	if !ok || !exitnode.IsInternet(dst) {
		return true
	}
	if t := g.tenant.Load(); t != nil {
		for _, p := range *t {
			if p.Contains(dst) {
				return true
			}
		}
	}
	if !g.allow.Load() {
		g.dropped.Add(1)
		if last := g.lastDrop.Load(); now-last >= 30 && g.lastDrop.CompareAndSwap(last, now) {
			log.Printf("[EXIT] Refused internet-bound traffic from peer %s to %s: exit-node is off on this device", src, dst)
		}
		return false
	}
	if v, ok := g.users.Load(src); ok {
		ts := v.(*atomic.Int64)
		if prev := ts.Load(); prev != now {
			ts.Store(now)
			if now-prev > 600 {
				g.announce(src)
			}
		}
		return true
	}
	ts := &atomic.Int64{}
	ts.Store(now)
	if _, loaded := g.users.LoadOrStore(src, ts); !loaded {
		g.announce(src)
	}
	return true
}

func (g *exitGuard) announce(src netip.Addr) {
	if fn := g.onNew.Load(); fn != nil {
		go (*fn)(src)
	}
}

// recentUsers lists sources seen within window.
func (g *exitGuard) recentUsers(window time.Duration) map[netip.Addr]time.Time {
	out := map[netip.Addr]time.Time{}
	cutoff := time.Now().Add(-window).Unix()
	g.users.Range(func(k, v any) bool {
		if ts := v.(*atomic.Int64).Load(); ts >= cutoff {
			out[k.(netip.Addr)] = time.Unix(ts, 0)
		}
		return true
	})
	return out
}

func (g *exitGuard) resetUsers() {
	g.users.Range(func(k, _ any) bool { g.users.Delete(k); return true })
}

// exitGuardTUN wraps the native TUN; only Write (WireGuard -> host) filters.
type exitGuardTUN struct {
	tun.Device
	guard *exitGuard
}

func (t *exitGuardTUN) Write(bufs [][]byte, offset int) (int, error) {
	now := time.Now().Unix()
	keep := bufs
	filtered := false
	for i, b := range bufs {
		if len(b) <= offset || t.guard.forwardable(b[offset:], now) {
			if filtered {
				keep = append(keep, b)
			}
			continue
		}
		if !filtered {
			filtered = true
			keep = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
		}
	}
	if len(keep) == 0 {
		return len(bufs), nil
	}
	if _, err := t.Device.Write(keep, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}
