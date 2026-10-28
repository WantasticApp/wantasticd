package portmap

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

// upnpClient is the subset of the IGD WAN connection services we use; the
// WANIPConnection1/2 and WANPPPConnection1 clients all provide it.
type upnpClient interface {
	AddPortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string, internalPort uint16, internalClient string, enabled bool, description string, leaseDuration uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
}

const upnpDescription = "wantasticd"

// discoverUPnP finds the internet gateway's WAN connection service by SSDP.
func discoverUPnP(ctx context.Context) (upnpClient, error) {
	if clients, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx); err == nil && len(clients) > 0 {
		return clients[0], nil
	}
	if clients, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx); err == nil && len(clients) > 0 {
		return clients[0], nil
	}
	if clients, _, err := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx); err == nil && len(clients) > 0 {
		return clients[0], nil
	}
	return nil, errors.New("no UPnP internet gateway found")
}

// upnpMap forwards external UDP port internalPort to localIP:internalPort.
// Some IGDv1 routers only accept permanent leases; those get lease 0 and are
// removed explicitly on shutdown.
func upnpMap(ctx context.Context, client upnpClient, localIP netip.Addr, internalPort uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	lease := uint32(lifetime / time.Second)
	err := client.AddPortMappingCtx(ctx, "", internalPort, "UDP", internalPort, localIP.String(), true, upnpDescription, lease)
	if err != nil && lease != 0 {
		lease = 0
		err = client.AddPortMappingCtx(ctx, "", internalPort, "UDP", internalPort, localIP.String(), true, upnpDescription, 0)
	}
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	externalIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	addr, err := netip.ParseAddr(externalIP)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	return netip.AddrPortFrom(addr, internalPort), time.Duration(lease) * time.Second, nil
}
