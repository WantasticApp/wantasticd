package device

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	wgdevice "wantastic-agent/internal/device/wireguard-go/device"
	"wantastic-agent/internal/exitnode"
)

// Exit-node mode, Tailscale style but local-first:
//   - The exit side opts in (`exit-node on`): forwarding + NAT, and the TUN
//     guard starts letting peers' internet-bound packets through.
//   - The client (`jumpto <vpn-ip>`) asks the exit over their direct
//     WireGuard session, then gives the exit peer 0.0.0.0/0, pins every
//     tunnel endpoint to the physical gateway and adds 0/1 + 128/1 via the
//     TUN. Without a confirmed live direct path it fails open (normal
//     routing) and says why.
//
// Peer-to-peer control (TUN control type 7, over the direct session):
//
//	[10, op]    exit request: op 0 release, 1 use, 2 query
//	[11, flags] exit status:  bit0 offering, bit1 granted (reply to use)
const (
	exitOpRelease = 0
	exitOpUse     = 1
	exitOpQuery   = 2

	exitFlagOffered = 1
	exitFlagGranted = 2

	exitReconcileEvery = 2 * time.Second
	exitEnsureEvery    = 30 * time.Second
	exitQueryEvery     = 60 * time.Second
	exitRequestEvery   = 5 * time.Second
	exitUserWindow     = 10 * time.Minute
)

// ExitNodeStatus is the exit-node part of /api/status and /api/exitnode.
type ExitNodeStatus struct {
	// Exit side.
	Supported         bool       `json:"supported"`
	UnsupportedReason string     `json:"unsupported_reason,omitempty"`
	Offering          bool       `json:"offering"`
	Backend           string     `json:"backend,omitempty"`
	OfferError        string     `json:"offer_error,omitempty"`
	Users             []ExitUser `json:"users,omitempty"`
	Refused           uint64     `json:"refused_packets,omitempty"`
	// Client side.
	ClientSupported bool            `json:"client_supported"`
	Using           *ExitUse        `json:"using,omitempty"`
	Candidates      []ExitCandidate `json:"candidates,omitempty"`
}

type ExitUser struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	LastSeen int64  `json:"last_seen"`
}

type ExitUse struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	State     string `json:"state"` // pending | active | standby
	Path      string `json:"path"`  // direct | relay | offline
	Endpoint  string `json:"endpoint,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Since     int64  `json:"since"`
}

type ExitCandidate struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	PublicKey string `json:"public_key"`
	Path      string `json:"path"`   // direct | relay
	Offers    string `json:"offers"` // yes | no | unknown
	Online    bool   `json:"online"`
}

type exitEngine struct {
	d         *Device
	host      exitnode.Host
	statePath string

	mu       sync.Mutex
	st       exitnode.State
	offerErr string

	// client runtime
	useKey      wgdevice.NoisePublicKey
	phase       exitnode.ClientPhase
	reason      string
	since       time.Time
	granted     bool
	lastRequest time.Time
	lastTry     time.Time
	retryAt     time.Time // backoff after a failed activation
	allowedSet  bool      // 0.0.0.0/0 was given to a peer
	offered     map[wgdevice.NoisePublicKey]bool

	kick chan struct{}
	stop chan struct{}
	done chan struct{}
}

func (d *Device) exitEngine() *exitEngine {
	d.exitMu.Lock()
	defer d.exitMu.Unlock()
	return d.exit
}

func exitStatePath(cfgPath string) string {
	if cfgPath == "" {
		return filepath.Join(os.TempDir(), "wantasticd-exitnode.json")
	}
	return filepath.Join(filepath.Dir(cfgPath), "exitnode.json")
}

func (d *Device) startExitEngine() {
	e := &exitEngine{
		d:         d,
		host:      exitnode.SystemHost(runtime.GOOS),
		statePath: exitStatePath(d.config.FilePath()),
		phase:     exitnode.PhaseOff,
		offered:   map[wgdevice.NoisePublicKey]bool{},
		kick:      make(chan struct{}, 1),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	st, exists, err := exitnode.LoadState(e.statePath)
	if err != nil {
		log.Printf("[EXIT] Ignoring unreadable state %s: %v", e.statePath, err)
	}
	if !exists && d.config.ExitNode.Enabled {
		st.Offer = true // legacy config flag
	}
	e.st = st
	e.cleanupStale()

	fn := e.onNewUser
	d.exitGuard.onNew.Store(&fn)

	d.exitMu.Lock()
	d.exit = e
	d.exitMu.Unlock()

	if e.st.Offer {
		if err := e.enableOffer(); err != nil {
			log.Printf("[EXIT] Could not re-enable exit-node sharing: %v", err)
		}
	}
	if e.st.Use != "" {
		e.setPhase(exitnode.PhaseStandby, "starting")
		log.Printf("[EXIT] Restoring exit node %s from saved state", e.st.Use)
	}
	e.save()
	go e.loop()
}

func (d *Device) stopExitEngine() {
	d.exitMu.Lock()
	e := d.exit
	d.exit = nil
	d.exitMu.Unlock()
	if e == nil {
		return
	}
	close(e.stop)
	<-e.done
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deactivateLocked("daemon stopping")
	if e.st.NAT != nil {
		e.disableNATLocked()
	}
	d.exitGuard.allow.Store(false)
	e.saveLocked() // keeps Offer/Use for the next start
}

// cleanupStale removes routes/NAT a previous (crashed) run left behind.
func (e *exitEngine) cleanupStale() {
	if len(e.st.Routes) > 0 {
		log.Printf("[EXIT] Removing %d stale exit-node route(s) from a previous run", len(e.st.Routes))
		for i := len(e.st.Routes) - 1; i >= 0; i-- {
			r := e.st.Routes[i]
			if c, err := exitnode.RouteDelCmd(e.host.OS, r, e.st.RouteTun, e.st.RouteGW); err == nil {
				_, _ = e.host.Run(c)
			}
		}
		e.st.Routes = nil
	}
	if e.st.ClientNAT != nil {
		_ = exitnode.DisableNAT(e.host, *e.st.ClientNAT)
		e.st.ClientNAT = nil
	}
	if e.st.NAT != nil {
		log.Printf("[EXIT] Removing stale exit-node NAT (%s) from a previous run", e.st.NAT.Plan.Backend)
		_ = exitnode.DisableNAT(e.host, *e.st.NAT)
		e.st.NAT = nil
	}
	e.st.ServerHadV4Default = false
}

func (e *exitEngine) save() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.saveLocked()
}

func (e *exitEngine) saveLocked() {
	if err := exitnode.SaveState(e.statePath, e.st); err != nil {
		log.Printf("[EXIT] Could not save state %s: %v", e.statePath, err)
	}
}

func (e *exitEngine) poke() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

func (e *exitEngine) loop() {
	defer close(e.done)
	t := time.NewTicker(exitReconcileEvery)
	defer t.Stop()
	var lastEnsure, lastQuery time.Time
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
		case <-e.kick:
		}
		now := time.Now()
		e.reconcileClient(now)
		if now.Sub(lastEnsure) >= exitEnsureEvery {
			lastEnsure = now
			e.ensureNAT()
		}
		if now.Sub(lastQuery) >= exitQueryEvery {
			lastQuery = now
			e.queryDirectPeers()
		}
	}
}

// ── exit side ───────────────────────────────────────────────────────────────

// SetExitOffer turns exit-node sharing on or off (persisted locally).
func (d *Device) SetExitOffer(on bool) error {
	e := d.exitEngine()
	if e == nil {
		return errors.New("tunnel is not running")
	}
	var err error
	if on {
		err = e.enableOffer()
	} else {
		err = e.disableOffer()
	}
	e.save()
	return err
}

func (e *exitEngine) overlaySources() []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	add := func(p netip.Prefix) {
		p = p.Masked()
		if p.Addr().Is4() && p.Bits() > 0 && p.Bits() < 32 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, s := range e.d.config.Server.AllowedIPs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			add(p)
		}
	}
	for _, a := range e.d.config.Interface.Addresses {
		add(a)
	}
	if len(out) == 0 {
		for _, a := range e.d.config.Interface.Addresses {
			if a.Addr().Is4() {
				add(netip.PrefixFrom(a.Addr(), 24))
			}
		}
	}
	return out
}

func (e *exitEngine) enableOffer() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.st.Offer && e.st.NAT != nil {
		return nil
	}
	backend, err := exitnode.DetectBackend(e.host)
	if err != nil {
		e.offerErr = err.Error()
		return err
	}
	tun := e.d.GetTUNName()
	gw, err := exitnode.DefaultGateway(e.host, tun)
	if err != nil {
		e.offerErr = "no default route: " + err.Error()
		return fmt.Errorf("find uplink: %w", err)
	}
	plan := exitnode.NATPlan{Backend: backend, Mode: exitnode.ModeExit, Tun: tun, Uplink: gw.Interface, Sources: e.overlaySources()}
	ns, err := exitnode.EnableNAT(e.host, plan)
	if err != nil {
		e.offerErr = err.Error()
		return err
	}
	e.st.NAT = &ns
	e.st.Offer = true
	e.offerErr = ""
	e.d.exitGuard.allow.Store(true)
	log.Printf("[EXIT] Exit-node sharing ON: %s NAT for %v out of %s", backend, plan.Sources, plan.Uplink)
	if backend == exitnode.BackendPF && !pfConfHasAppleNATAnchor() {
		log.Printf("[EXIT] Warning: /etc/pf.conf has no nat-anchor \"com.apple/*\"; macOS will not apply the exit NAT rules")
	}
	go e.announceOffer(true)
	return nil
}

func (e *exitEngine) disableOffer() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.st.Offer = false
	e.offerErr = ""
	e.d.exitGuard.allow.Store(false)
	e.d.exitGuard.resetUsers()
	var err error
	if e.st.NAT != nil {
		err = e.disableNATLocked()
	}
	log.Printf("[EXIT] Exit-node sharing OFF")
	go e.announceOffer(false)
	return err
}

func (e *exitEngine) disableNATLocked() error {
	ns := *e.st.NAT
	e.d.mu.RLock()
	localAccess := e.d.localAccessShared
	e.d.mu.RUnlock()
	if localAccess {
		ns.PrevForward = "" // local-access sharing still needs forwarding
	}
	err := exitnode.DisableNAT(e.host, ns)
	e.st.NAT = nil
	return err
}

// ensureNAT repairs rules a firewall reload removed and follows uplink
// changes (Wi-Fi to Ethernet, new default route).
func (e *exitEngine) ensureNAT() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.st.NAT != nil {
		if gw, err := exitnode.DefaultGateway(e.host, e.d.GetTUNName()); err == nil && gw.Interface != "" && gw.Interface != e.st.NAT.Plan.Uplink {
			log.Printf("[EXIT] Uplink changed %s -> %s; moving exit NAT", e.st.NAT.Plan.Uplink, gw.Interface)
			plan := e.st.NAT.Plan
			_ = e.disableNATLocked()
			plan.Uplink = gw.Interface
			if ns, err := exitnode.EnableNAT(e.host, plan); err == nil {
				e.st.NAT = &ns
			} else {
				e.offerErr = err.Error()
				log.Printf("[EXIT] Re-enabling exit NAT failed: %v", err)
			}
			e.saveLocked()
		} else if repaired, err := exitnode.EnsureNAT(e.host, e.st.NAT); err != nil {
			log.Printf("[EXIT] Restoring exit NAT rules failed: %v", err)
		} else if repaired {
			log.Printf("[EXIT] Exit NAT rules were removed externally; restored")
			e.saveLocked()
		}
	} else if e.st.Offer {
		e.mu.Unlock()
		if err := e.enableOffer(); err == nil {
			e.save()
		}
		e.mu.Lock()
	}
	if e.st.ClientNAT != nil {
		if repaired, err := exitnode.EnsureNAT(e.host, e.st.ClientNAT); err == nil && repaired {
			log.Printf("[EXIT] Client masquerade rules restored")
		}
	}
}

func pfConfHasAppleNATAnchor() bool {
	b, err := os.ReadFile("/etc/pf.conf")
	return err != nil || strings.Contains(string(b), `nat-anchor "com.apple/*"`)
}

// announceOffer tells the hub (existing registry flag) and every direct peer.
func (e *exitEngine) announceOffer(on bool) {
	if e.d.config.Server.PublicKey != "" {
		_ = e.d.SendTUNControl(e.d.config.Server.PublicKey, EncodeExitNodeOfferTUNControl(on))
	}
	flags := byte(0)
	if on {
		flags = exitFlagOffered
	}
	for _, p := range e.directPeers() {
		p.SendTUNControl([]byte{byte(TUNControlActionExitStatus), flags})
	}
}

func (e *exitEngine) onNewUser(src netip.Addr) {
	name := ""
	if p := e.discoveredByIP(src); p != nil {
		name = e.d.getPeerHostname(hex.EncodeToString(p.PublicKey[:]))
	}
	log.Printf("[EXIT] Peer %s (%s) is using this device as its exit node", src, orUnknown(name))
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown host"
	}
	return s
}

// ── peer-to-peer control ────────────────────────────────────────────────────

func (e *exitEngine) handleControl(peer *wgdevice.Peer, action TUNControlAction, data []byte) {
	if e.d.isServerTUNControlPeer(peer.PublicKeyHex()) {
		return // negotiation is between devices only
	}
	var key wgdevice.NoisePublicKey
	if err := key.FromHex(peer.PublicKeyHex()); err != nil || len(data) < 2 {
		return
	}
	name := e.d.getPeerHostname(peer.PublicKeyHex())
	switch action {
	case TUNControlActionExitRequest:
		e.mu.Lock()
		offering := e.st.Offer && e.st.NAT != nil
		e.mu.Unlock()
		flags := byte(0)
		if offering {
			flags |= exitFlagOffered
		}
		switch data[1] {
		case exitOpUse:
			if offering {
				flags |= exitFlagGranted
				log.Printf("[EXIT] Peer %s (%s) requested this device as exit node: granted", peer, orUnknown(name))
			} else {
				log.Printf("[EXIT] Peer %s (%s) requested this device as exit node: refused (exit-node is off here)", peer, orUnknown(name))
			}
		case exitOpRelease:
			log.Printf("[EXIT] Peer %s (%s) stopped using this device as exit node", peer, orUnknown(name))
		}
		peer.SendTUNControl([]byte{byte(TUNControlActionExitStatus), flags})
	case TUNControlActionExitStatus:
		offered := data[1]&exitFlagOffered != 0
		granted := data[1]&exitFlagGranted != 0
		e.mu.Lock()
		e.offered[key] = offered
		if key == e.useKey && e.st.Use != "" {
			if granted {
				e.granted = true
			} else if !offered {
				e.granted = false
			}
		}
		e.mu.Unlock()
		e.poke()
	}
}

func (e *exitEngine) directPeers() []*wgdevice.Peer {
	wd := e.d.device
	if wd == nil || wd.GetP2PClient() == nil {
		return nil
	}
	var out []*wgdevice.Peer
	for _, dp := range wd.GetP2PClient().GetDiscoveredPeers() {
		if dp.State != wgdevice.P2PStateEstablished {
			continue
		}
		if p := wd.LookupPeer(dp.PublicKey); p != nil {
			out = append(out, p)
		}
	}
	return out
}

func (e *exitEngine) queryDirectPeers() {
	for _, p := range e.directPeers() {
		p.SendTUNControl([]byte{byte(TUNControlActionExitRequest), exitOpQuery})
	}
}

// ── client side ─────────────────────────────────────────────────────────────

// UseExitNode makes target (VPN IP or hostname) this device's exit node. It
// waits up to wait for the route to go live and returns the resulting state.
func (d *Device) UseExitNode(target string, wait time.Duration) (*ExitUse, error) {
	e := d.exitEngine()
	if e == nil {
		return nil, errors.New("tunnel is not running")
	}
	if e.host.OS != "darwin" && e.host.OS != "linux" && e.host.OS != "windows" {
		return nil, fmt.Errorf("exit-node client mode is not supported on %s", e.host.OS)
	}
	dp, err := e.resolveTarget(target)
	if err != nil {
		return nil, err
	}
	ip := netip.AddrFrom4([4]byte(dp.AssignedIP.To4()))
	e.mu.Lock()
	if e.st.Use != "" && e.st.Use != ip.String() {
		e.deactivateLocked("switching exit node")
		e.releaseLocked()
	}
	if e.st.Use != ip.String() {
		e.st.Use = ip.String()
		e.useKey = dp.PublicKey
		e.granted = false
		delete(e.offered, dp.PublicKey) // wait for a fresh answer
		e.retryAt = time.Time{}
		e.lastRequest = time.Time{}
		e.lastTry = time.Time{}
		e.phase = exitnode.PhaseOff
	}
	e.saveLocked()
	e.mu.Unlock()
	log.Printf("[EXIT] Exit node set to %s (%s)", ip, orUnknown(d.getPeerHostname(hex.EncodeToString(dp.PublicKey[:]))))
	e.poke()

	deadline := time.Now().Add(wait)
	for {
		u := e.useStatus()
		if u == nil {
			return nil, errors.New("exit node was cleared")
		}
		e.mu.Lock()
		refused := e.offered[e.useKey] == false && hasKey(e.offered, e.useKey)
		e.mu.Unlock()
		if refused {
			_ = d.ClearExitNode()
			return nil, fmt.Errorf("%s has not enabled exit-node; run `sudo wantasticd exit-node on` on that device", ip)
		}
		if u.State == string(exitnode.PhaseActive) || time.Now().After(deadline) {
			return u, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func hasKey(m map[wgdevice.NoisePublicKey]bool, k wgdevice.NoisePublicKey) bool {
	_, ok := m[k]
	return ok
}

// ClearExitNode stops using an exit node and restores normal routing.
// Idempotent.
func (d *Device) ClearExitNode() error {
	e := d.exitEngine()
	if e == nil {
		return errors.New("tunnel is not running")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	had := e.st.Use
	e.deactivateLocked("comeback")
	e.releaseLocked()
	e.st.Use = ""
	e.useKey = wgdevice.NoisePublicKey{}
	e.granted = false
	e.phase = exitnode.PhaseOff
	e.reason = ""
	e.saveLocked()
	if had != "" {
		log.Printf("[EXIT] Stopped using exit node %s; normal routing restored", had)
	}
	return nil
}

func (e *exitEngine) releaseLocked() {
	if e.useKey.IsZero() || e.d.device == nil {
		return
	}
	if p := e.d.device.LookupPeer(e.useKey); p != nil {
		p.SendTUNControl([]byte{byte(TUNControlActionExitRequest), exitOpRelease})
	}
}

func (e *exitEngine) resolveTarget(target string) (*wgdevice.DiscoveredPeer, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("missing exit node VPN IP")
	}
	for _, a := range e.d.config.Interface.Addresses {
		if a.Addr().String() == target {
			return nil, errors.New("a device cannot be its own exit node")
		}
	}
	if e.d.device == nil || e.d.device.GetP2PClient() == nil {
		return nil, errors.New("peer discovery is not running")
	}
	var matches []*wgdevice.DiscoveredPeer
	for _, dp := range e.d.device.GetP2PClient().GetDiscoveredPeers() {
		if dp.AssignedIP.To4() == nil {
			continue
		}
		name := e.d.getPeerHostname(hex.EncodeToString(dp.PublicKey[:]))
		if dp.AssignedIP.String() == target || (name != "" && strings.EqualFold(name, target)) {
			matches = append(matches, dp)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no peer %s in this network (see `wantasticd peers`)", target)
	case 1:
		return matches[0], nil
	}
	return nil, fmt.Errorf("%q matches %d peers; use the VPN IP", target, len(matches))
}

func (e *exitEngine) discoveredByIP(ip netip.Addr) *wgdevice.DiscoveredPeer {
	if e.d.device == nil || e.d.device.GetP2PClient() == nil {
		return nil
	}
	for _, dp := range e.d.device.GetP2PClient().GetDiscoveredPeers() {
		if a, ok := netip.AddrFromSlice(dp.AssignedIP.To4()); ok && a == ip {
			return dp
		}
	}
	return nil
}

func (e *exitEngine) setPhase(p exitnode.ClientPhase, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.setPhaseLocked(p, reason)
}

func (e *exitEngine) setPhaseLocked(p exitnode.ClientPhase, reason string) {
	if e.phase != p || e.reason != reason {
		if e.st.Use != "" && p != exitnode.PhaseOff {
			if reason != "" {
				log.Printf("[EXIT] Exit node %s: %s (%s)", e.st.Use, p, reason)
			} else {
				log.Printf("[EXIT] Exit node %s: %s", e.st.Use, p)
			}
		}
		if e.phase != p {
			e.since = time.Now()
		}
		e.phase, e.reason = p, reason
	}
}

func (e *exitEngine) reconcileClient(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.st.Use == "" {
		if len(e.st.Routes) > 0 {
			e.deactivateLocked("not in use")
		}
		return
	}
	ip, err := netip.ParseAddr(e.st.Use)
	if err != nil {
		e.st.Use = ""
		return
	}
	dp := e.discoveredByIP(ip)
	health := exitnode.PathHealth{Listed: dp != nil}
	var ipcPeers map[string]ipcPeer
	if dp != nil {
		if dp.PublicKey != e.useKey {
			e.useKey = dp.PublicKey
			e.granted = false
		}
		if v, ok := e.offered[e.useKey]; ok {
			health.Offered = &v
		}
		ipcPeers = e.ipcPeers()
		if dp.State == wgdevice.P2PStateEstablished && e.d.device.LookupPeer(dp.PublicKey) != nil {
			health.Direct = true
			if ip := ipcPeers[hex.EncodeToString(dp.PublicKey[:])]; ip.lastHandshake > 0 {
				health.LastHandshake = time.Unix(ip.lastHandshake, 0)
			}
		}
		if !health.Direct {
			e.granted = false
			if now.Sub(e.lastTry) > 10*time.Second {
				e.lastTry = now
				go e.d.device.GetP2PClient().TryP2P(dp.ID)
			}
		} else if !e.granted && now.Sub(e.lastRequest) >= exitRequestEvery {
			e.lastRequest = now
			if p := e.d.device.LookupPeer(dp.PublicKey); p != nil {
				p.SendTUNControl([]byte{byte(TUNControlActionExitRequest), exitOpUse})
			}
		}
	}
	health.Granted = e.granted
	phase, reason := exitnode.NextPhase(health, now)
	if phase != exitnode.PhaseActive {
		if len(e.st.Routes) > 0 || e.allowedSet {
			e.deactivateLocked(reason)
		}
		e.setPhaseLocked(phase, reason)
		return
	}
	if now.Before(e.retryAt) {
		return
	}
	if err := e.activateLocked(dp, ipcPeers); err != nil {
		e.retryAt = now.Add(30 * time.Second)
		e.deactivateLocked(err.Error())
		e.setPhaseLocked(exitnode.PhaseStandby, err.Error())
		return
	}
	e.setPhaseLocked(exitnode.PhaseActive, "")
}

type ipcPeer struct {
	endpoint      string
	lastHandshake int64
	allowedIPs    []string
}

func (e *exitEngine) ipcPeers() map[string]ipcPeer {
	if e.d.device == nil {
		return nil
	}
	s, err := e.d.device.IpcGet()
	if err != nil {
		return nil
	}
	return parseIPCPeers(s)
}

// parseIPCPeers indexes the UAPI dump by hex public key.
func parseIPCPeers(s string) map[string]ipcPeer {
	out := map[string]ipcPeer{}
	cur := ""
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			cur = v
			out[cur] = ipcPeer{}
			continue
		}
		if cur == "" {
			continue
		}
		p := out[cur]
		switch k {
		case "endpoint":
			p.endpoint = v
		case "last_handshake_time_sec":
			p.lastHandshake, _ = strconv.ParseInt(v, 10, 64)
		case "allowed_ip":
			p.allowedIPs = append(p.allowedIPs, v)
		}
		out[cur] = p
	}
	return out
}

func endpointAddr(ep string) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(ep)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// bypassAddrs collects every address the tunnel's own UDP goes to.
func (e *exitEngine) bypassAddrs(peers map[string]ipcPeer, exitKey string) (all []netip.Addr, critical map[netip.Addr]bool) {
	critical = map[netip.Addr]bool{}
	srvHex, _ := base64ToHex(e.d.config.Server.PublicKey)
	for k, p := range peers {
		if a, ok := endpointAddr(p.endpoint); ok {
			all = append(all, a)
			if k == srvHex || k == exitKey {
				critical[a] = true
			}
		}
	}
	if c := e.d.device.GetP2PClient(); c != nil {
		for _, dp := range c.GetDiscoveredPeers() {
			for _, u := range append([]net.UDPAddr{dp.ObservedAddr, dp.LocalAddr}, dp.CandidateAddrs...) {
				// Only public candidates: a peer's private LAN address may be
				// a host this device reaches through some other route.
				if a, ok := netip.AddrFromSlice(u.IP); ok && exitnode.IsInternet(a) {
					all = append(all, a.Unmap())
				}
			}
		}
	}
	return all, critical
}

func onLinkFunc(tun string) func(netip.Addr) bool {
	var prefixes []netip.Prefix
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Name == tun || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(n.String()); err == nil {
					prefixes = append(prefixes, p.Masked())
				}
			}
		}
	}
	return func(a netip.Addr) bool {
		for _, p := range prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
}

func (e *exitEngine) overlayPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range e.d.config.Server.AllowedIPs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil && p.Bits() > 0 {
			out = append(out, p.Masked())
		}
	}
	return out
}

// activateLocked installs (or refreshes) client routing through dp.
func (e *exitEngine) activateLocked(dp *wgdevice.DiscoveredPeer, peers map[string]ipcPeer) error {
	tun := e.d.GetTUNName()
	gw, err := exitnode.DefaultGateway(e.host, tun)
	if err != nil {
		if !e.st.RouteGW.Valid() {
			return fmt.Errorf("cannot find the physical default route: %v", err)
		}
		gw = e.st.RouteGW
	}
	exitHex := hex.EncodeToString(dp.PublicKey[:])
	first := len(e.st.Routes) == 0

	// Bypass routes move when the network changes.
	if !first && (gw != e.st.RouteGW || tun != e.st.RouteTun) {
		log.Printf("[EXIT] Default route changed (%s via %s -> %s via %s); re-pinning tunnel endpoints",
			e.st.RouteGW.Addr, e.st.RouteGW.Interface, gw.Addr, gw.Interface)
		e.deleteRoutesLocked(func(r exitnode.Route) bool { return r.Kind == exitnode.RouteBypass })
	}

	addrs, critical := e.bypassAddrs(peers, exitHex)
	desired := exitnode.PlanClientRoutes(exitnode.ClientPlan{
		Bypass:    addrs,
		OnLink:    onLinkFunc(tun),
		Overlay:   e.overlayPrefixes(),
		BlockIPv6: e.host.OS != "windows",
	})

	if first {
		if srv, ok := peers[mustHex(e.d.config.Server.PublicKey)]; ok {
			e.st.ServerHadV4Default = contains(srv.allowedIPs, "0.0.0.0/0")
		}
	}
	add, del := exitnode.DiffRoutes(e.st.Routes, desired)
	for _, r := range del {
		e.deleteRoutesLocked(func(x exitnode.Route) bool { return x == r })
	}
	e.st.RouteTun, e.st.RouteGW = tun, gw

	// The exit peer owns 0.0.0.0/0 before the split routes send anything in.
	// Re-asserted every pass: a re-punch resets the peer's allowed IPs.
	if !contains(peers[exitHex].allowedIPs, "0.0.0.0/0") {
		if err := e.d.device.IpcSet(addAllowedIPCmd(exitHex, "0.0.0.0/0")); err != nil {
			return fmt.Errorf("route 0.0.0.0/0 to the exit peer: %v", err)
		}
		e.allowedSet = true
	}
	changed := len(del) > 0
	for _, r := range add {
		c, err := exitnode.RouteAddCmd(e.host.OS, r, tun, gw)
		if err == nil {
			_, err = e.host.Run(c)
		}
		if err != nil && routeExists(err) {
			if r.Kind == exitnode.RouteBypass {
				continue // someone else's route for the same host; leave it
			}
			// A stale split/reject route (e.g. on another interface): replace it.
			if d, derr := exitnode.RouteDelCmd(e.host.OS, exitnode.Route{Dst: r.Dst, Kind: r.Kind}, tun, gw); derr == nil {
				_, _ = e.host.Run(exitnode.Cmd{Name: d.Name, Args: stripInterface(d.Args)})
			}
			_, err = e.host.Run(c)
		}
		if err != nil {
			switch {
			case r.Kind == exitnode.RouteTunnel:
				return fmt.Errorf("install %s via %s: %v", r.Dst, tun, err)
			case r.Kind == exitnode.RouteBypass && critical[r.Dst.Addr()]:
				return fmt.Errorf("pin %s to the physical gateway: %v", r.Dst.Addr(), err)
			default:
				log.Printf("[EXIT] Warning: %s: %v", r.Dst, err)
				continue
			}
		}
		e.st.Routes = append(e.st.Routes, r)
		changed = true
	}
	if e.host.OS == "linux" && e.st.ClientNAT == nil {
		e.enableClientNATLocked(tun)
	}
	if first {
		log.Printf("[EXIT] Internet traffic now goes through exit node %s (endpoint %s, gateway %s via %s)",
			e.st.Use, peers[exitHex].endpoint, gw.Addr, gw.Interface)
	}
	if changed || first {
		e.saveLocked()
	}
	return nil
}

// enableClientNATLocked lets hosts behind a Linux router use the exit too.
func (e *exitEngine) enableClientNATLocked(tun string) {
	var own netip.Addr
	for _, a := range e.d.config.Interface.Addresses {
		if a.Addr().Is4() {
			own = a.Addr()
			break
		}
	}
	backend, err := exitnode.DetectBackend(e.host)
	if err != nil || !own.IsValid() {
		return
	}
	ns, err := exitnode.EnableNAT(e.host, exitnode.NATPlan{Backend: backend, Mode: exitnode.ModeClient, Tun: tun, Own: own})
	if err != nil {
		log.Printf("[EXIT] Note: LAN hosts behind this device will not use the exit node (masquerade failed: %v)", err)
		return
	}
	e.st.ClientNAT = &ns
}

func (e *exitEngine) deleteRoutesLocked(match func(exitnode.Route) bool) {
	kept := e.st.Routes[:0:0]
	for i := len(e.st.Routes) - 1; i >= 0; i-- {
		r := e.st.Routes[i]
		if !match(r) {
			kept = append([]exitnode.Route{r}, kept...)
			continue
		}
		if c, err := exitnode.RouteDelCmd(e.host.OS, r, e.st.RouteTun, e.st.RouteGW); err == nil {
			if _, err := e.host.Run(c); err != nil {
				log.Printf("[EXIT] Warning: removing %s: %v", r.Dst, err)
			}
		}
	}
	e.st.Routes = kept
}

// addAllowedIPCmd adds one prefix to an existing peer. Appending is the UAPI
// default: replace_allowed_ips accepts only "true", so it is left out.
func addAllowedIPCmd(peerHex, prefix string) string {
	return fmt.Sprintf("public_key=%s\nupdate_only=true\nallowed_ip=%s\n", peerHex, prefix)
}

// deactivateLocked restores normal routing; the exit choice is kept.
func (e *exitEngine) deactivateLocked(reason string) {
	if len(e.st.Routes) == 0 && e.st.ClientNAT == nil && !e.allowedSet {
		return
	}
	// Split default and IPv6 reject first, so nothing is sent into a tunnel
	// that is about to lose its 0.0.0.0/0 owner.
	e.deleteRoutesLocked(func(r exitnode.Route) bool { return r.Kind != exitnode.RouteBypass })
	if e.d.device != nil {
		peers := e.ipcPeers()
		for k, p := range peers {
			if k == mustHex(e.d.config.Server.PublicKey) || !contains(p.allowedIPs, "0.0.0.0/0") {
				continue
			}
			var b strings.Builder
			fmt.Fprintf(&b, "public_key=%s\nupdate_only=true\nreplace_allowed_ips=true\n", k)
			for _, a := range p.allowedIPs {
				if a != "0.0.0.0/0" {
					fmt.Fprintf(&b, "allowed_ip=%s\n", a)
				}
			}
			if err := e.d.device.IpcSet(b.String()); err != nil {
				log.Printf("[EXIT] Warning: removing 0.0.0.0/0 from peer: %v", err)
			}
		}
		if e.st.ServerHadV4Default && e.d.config.Server.PublicKey != "" {
			_ = e.d.device.IpcSet(addAllowedIPCmd(mustHex(e.d.config.Server.PublicKey), "0.0.0.0/0"))
		}
	}
	e.allowedSet = false
	e.st.ServerHadV4Default = false
	e.deleteRoutesLocked(func(exitnode.Route) bool { return true })
	if e.st.ClientNAT != nil {
		_ = exitnode.DisableNAT(e.host, *e.st.ClientNAT)
		e.st.ClientNAT = nil
	}
	e.granted = e.granted && reason != "comeback"
	log.Printf("[EXIT] Normal routing restored (%s)", reason)
	e.saveLocked()
}

func mustHex(b64 string) string {
	h, _ := base64ToHex(b64)
	return h
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ── status ──────────────────────────────────────────────────────────────────

func (e *exitEngine) useStatus() *ExitUse {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.useStatusLocked()
}

func (e *exitEngine) useStatusLocked() *ExitUse {
	if e.st.Use == "" {
		return nil
	}
	u := &ExitUse{IP: e.st.Use, State: string(e.phase), Reason: e.reason, Since: e.since.Unix(), Path: "offline"}
	if e.phase == exitnode.PhaseOff {
		u.State = string(exitnode.PhasePending)
	}
	if ip, err := netip.ParseAddr(e.st.Use); err == nil {
		if dp := e.discoveredByIP(ip); dp != nil {
			k := hex.EncodeToString(dp.PublicKey[:])
			u.PublicKey = k
			u.Hostname = e.d.getPeerHostname(k)
			u.Path = "relay"
			if dp.State == wgdevice.P2PStateEstablished {
				u.Path = "direct"
				if dp.Endpoint != nil {
					u.Endpoint = dp.Endpoint.DstToString()
				}
			}
		}
	}
	return u
}

// ExitStatus reports exit-node state for the local API.
func (d *Device) ExitStatus() ExitNodeStatus {
	st := ExitNodeStatus{ClientSupported: runtime.GOOS == "darwin" || runtime.GOOS == "linux" || runtime.GOOS == "windows"}
	// Only the OS decides support here; backend detection runs commands and
	// happens when sharing is actually enabled.
	if _, err := exitnode.DetectBackend(exitnode.Host{OS: runtime.GOOS}); err != nil && errors.Is(err, exitnode.ErrUnsupported) {
		st.UnsupportedReason = err.Error()
	} else {
		st.Supported = true
	}
	e := d.exitEngine()
	if e == nil {
		return st
	}
	e.mu.Lock()
	st.Offering = e.st.Offer && e.st.NAT != nil
	if e.st.NAT != nil {
		st.Backend = string(e.st.NAT.Plan.Backend)
	}
	st.OfferError = e.offerErr
	st.Using = e.useStatusLocked()
	offered := make(map[wgdevice.NoisePublicKey]bool, len(e.offered))
	for k, v := range e.offered {
		offered[k] = v
	}
	e.mu.Unlock()
	st.Refused = d.exitGuard.dropped.Load()

	if st.Offering {
		for ip, ts := range d.exitGuard.recentUsers(exitUserWindow) {
			u := ExitUser{IP: ip.String(), LastSeen: ts.Unix()}
			if dp := e.discoveredByIP(ip); dp != nil {
				u.Hostname = d.getPeerHostname(hex.EncodeToString(dp.PublicKey[:]))
			}
			st.Users = append(st.Users, u)
		}
		sort.Slice(st.Users, func(i, j int) bool { return st.Users[i].IP < st.Users[j].IP })
	}
	if d.device != nil && d.device.GetP2PClient() != nil {
		for _, dp := range d.device.GetP2PClient().GetDiscoveredPeers() {
			if dp.AssignedIP.To4() == nil {
				continue
			}
			k := hex.EncodeToString(dp.PublicKey[:])
			c := ExitCandidate{IP: dp.AssignedIP.String(), Hostname: d.getPeerHostname(k), PublicKey: k, Path: "relay", Offers: "unknown",
				Online: time.Since(dp.LastSeen) < 6*time.Minute || dp.State == wgdevice.P2PStateEstablished}
			if dp.State == wgdevice.P2PStateEstablished {
				c.Path = "direct"
			}
			if v, ok := offered[dp.PublicKey]; ok {
				c.Offers = map[bool]string{true: "yes", false: "no"}[v]
			}
			st.Candidates = append(st.Candidates, c)
		}
		sortCandidates(st.Candidates)
	}
	return st
}

// sortCandidates: offering first, then online, direct, then by IP.
func sortCandidates(cs []ExitCandidate) {
	rank := func(c ExitCandidate) int {
		r := 0
		if c.Offers != "yes" {
			r += 4
		}
		if !c.Online {
			r += 2
		}
		if c.Path != "direct" {
			r++
		}
		return r
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if a, b := rank(cs[i]), rank(cs[j]); a != b {
			return a < b
		}
		ai, _ := netip.ParseAddr(cs[i].IP)
		bi, _ := netip.ParseAddr(cs[j].IP)
		return ai.Less(bi)
	})
}

func routeExists(err error) bool {
	s := err.Error()
	return strings.Contains(s, "File exists") || strings.Contains(s, "already exists")
}

// stripInterface drops "-interface X" so a delete matches the route on any
// interface (macOS).
func stripInterface(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "-interface" {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// ipForKey returns the VPN IP of a discovered peer.
func (e *exitEngine) ipForKey(key [32]byte) string {
	if e.d.device == nil || e.d.device.GetP2PClient() == nil {
		return ""
	}
	for _, dp := range e.d.device.GetP2PClient().GetDiscoveredPeers() {
		if dp.PublicKey == wgdevice.NoisePublicKey(key) && dp.AssignedIP.To4() != nil {
			return dp.AssignedIP.String()
		}
	}
	return ""
}
