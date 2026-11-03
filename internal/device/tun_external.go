package device

import "net/netip"

// TUNRequest is what the platform must configure on a tunnel it provides.
type TUNRequest struct {
	MTU       int
	Addresses []netip.Prefix
	Routes    []netip.Prefix
	DNS       []string
}

// ExternalTUN, when set, provides the tunnel instead of the OS: on Android
// the VpnService owns the interface, its addresses, routes and DNS, and
// hands over the file descriptor. The device then configures nothing itself.
var ExternalTUN func(TUNRequest) (fd int, err error)

// ExternalDefaultRoute, with ExternalTUN, asks the platform to route (or stop
// routing) the default into the tunnel when an exit node starts or stops
// carrying this device's internet. Called on its own goroutine.
var ExternalDefaultRoute func(on bool)

func tunRequest(mtu int, addrs []netip.Prefix, allowed []string, dns []string) TUNRequest {
	req := TUNRequest{MTU: mtu, Addresses: addrs, DNS: dns}
	for _, s := range allowed {
		if p, err := netip.ParsePrefix(s); err == nil {
			req.Routes = append(req.Routes, p.Masked())
		}
	}
	return req
}
