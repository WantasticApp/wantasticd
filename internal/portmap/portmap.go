// Package portmap asks the local router to forward a UDP port to this host,
// like Tailscale's port mapper: NAT-PMP first (Linux gateways), then UPnP
// IGD. A mapped public address lets peers reach this device directly even
// when hole punching alone fails. Collections stay passive: it only talks to
// the local gateway.
package portmap

import (
	"context"
	"log"
	"net/netip"
	"time"
)

const (
	requestedLifetime = 2 * time.Hour
	minRenew          = 30 * time.Second
	retryInitial      = time.Minute
	retryMax          = 30 * time.Minute
)

// Mapper keeps one UDP port mapping alive and reports its public address.
type Mapper struct {
	internalPort uint16
	onChange     func(netip.AddrPort) // zero AddrPort = no mapping

	// replaceable for tests
	gateway func() (netip.Addr, error)
	natpmp  func(gw netip.Addr, port uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error)
	upnp    func(ctx context.Context, port uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, func(), error)
	now     func() time.Time
	after   func(time.Duration) <-chan time.Time
}

// New returns a mapper for internalPort; onChange is called whenever the
// public address appears, changes or goes away.
func New(internalPort uint16, onChange func(netip.AddrPort)) *Mapper {
	m := &Mapper{
		internalPort: internalPort,
		onChange:     onChange,
		gateway:      defaultGateway,
		natpmp:       natpmpMap,
		now:          time.Now,
		after:        time.After,
	}
	m.upnp = m.upnpMapper()
	return m
}

func (m *Mapper) upnpMapper() func(ctx context.Context, port uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, func(), error) {
	return func(ctx context.Context, port uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, func(), error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		client, err := discoverUPnP(ctx)
		if err != nil {
			return netip.AddrPort{}, 0, nil, err
		}
		local, err := localIPFor(netip.MustParseAddr("192.0.2.1"))
		if err != nil {
			return netip.AddrPort{}, 0, nil, err
		}
		external, lease, err := upnpMap(ctx, client, local, port, lifetime)
		if err != nil {
			return netip.AddrPort{}, 0, nil, err
		}
		release := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = client.DeletePortMappingCtx(ctx, "", port, "UDP")
		}
		return external, lease, release, nil
	}
}

// mapOnce tries NAT-PMP, then UPnP. release removes the mapping.
func (m *Mapper) mapOnce(ctx context.Context) (netip.AddrPort, time.Duration, func(), error) {
	if gw, err := m.gateway(); err == nil {
		if external, lease, err := m.natpmp(gw, m.internalPort, requestedLifetime); err == nil && usablePublic(external) {
			release := func() { _, _, _ = m.natpmp(gw, m.internalPort, 0) }
			return external, lease, release, nil
		}
	}
	external, lease, release, err := m.upnp(ctx, m.internalPort, requestedLifetime)
	if err != nil {
		return netip.AddrPort{}, 0, nil, err
	}
	if !usablePublic(external) {
		// The router itself sits behind another NAT (CGNAT): a mapping on
		// it is not reachable from the Internet.
		if release != nil {
			release()
		}
		return netip.AddrPort{}, 0, nil, errNotPublic
	}
	return external, lease, release, nil
}

// Run keeps the mapping alive until ctx ends, then removes it.
func (m *Mapper) Run(ctx context.Context) {
	var (
		current netip.AddrPort
		release func()
		retry   = retryInitial
	)
	defer func() {
		if release != nil {
			release()
		}
		if current.IsValid() {
			m.onChange(netip.AddrPort{})
		}
	}()
	for {
		external, lease, rel, err := m.mapOnce(ctx)
		wait := retry
		if err != nil {
			if current.IsValid() {
				current = netip.AddrPort{}
				m.onChange(current)
			}
			retry = min(retry*2, retryMax)
		} else {
			if release != nil && rel == nil {
				release()
			}
			release = rel
			retry = retryInitial
			if external != current {
				current = external
				log.Printf("Router port mapping: %s -> UDP %d", external, m.internalPort)
				m.onChange(current)
			}
			wait = renewAfter(lease)
		}
		select {
		case <-ctx.Done():
			return
		case <-m.after(wait):
		}
	}
}

// renewAfter renews at half the lease; permanent (0) leases are re-checked
// every 30 minutes in case the router dropped them.
func renewAfter(lease time.Duration) time.Duration {
	if lease <= 0 {
		return retryMax
	}
	return max(lease/2, minRenew)
}

func usablePublic(addr netip.AddrPort) bool {
	ip := addr.Addr()
	return addr.IsValid() && addr.Port() != 0 && ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(ip) // carrier-grade NAT
}
