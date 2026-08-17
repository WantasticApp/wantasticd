//go:build linux

package iwinfo

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	linuxwifi "github.com/mdlayher/wifi"
)

// RuntimeInterfaces enumerates the interfaces known to nl80211. This is the
// authoritative runtime inventory on generic Linux and a fallback when
// OpenWrt netifd/rpcd objects are unavailable.
func RuntimeInterfaces() ([]WirelessInterface, error) {
	client, err := linuxwifi.New()
	if err != nil {
		return nil, fmt.Errorf("open nl80211: %w", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	interfaces, err := client.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list nl80211 interfaces: %w", err)
	}
	out := make([]WirelessInterface, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface == nil || strings.TrimSpace(iface.Name) == "" {
			continue
		}
		out = append(out, WirelessInterface{
			Index:        iface.Index,
			Name:         iface.Name,
			PHY:          iface.PHY,
			Mode:         runtimeInterfaceMode(iface.Type),
			Up:           runtimeInterfaceUp(iface.Name),
			HardwareAddr: append(net.HardwareAddr(nil), iface.HardwareAddr...),
			Frequency:    iface.Frequency,
			ChannelWidth: runtimeChannelWidth(iface.ChannelWidth),
		})
	}
	return out, nil
}

func runtimeInterfaceUp(ifname string) bool {
	iface, err := net.InterfaceByName(ifname)
	return err == nil && iface.Flags&net.FlagUp != 0
}

// CachedScan reads the current nl80211 BSS cache without initiating RF work.
func CachedScan(ifname string) ([]ScanEntry, error) {
	return scanWithNL80211(context.Background(), ifname, false)
}

// ActiveScan initiates one nl80211 scan and returns the refreshed BSS cache.
func ActiveScan(ctx context.Context, ifname string) ([]ScanEntry, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return scanWithNL80211(ctx, ifname, true)
}

func scanWithNL80211(ctx context.Context, ifname string, active bool) ([]ScanEntry, error) {
	client, iface, err := runtimeNL80211Interface(ifname)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if active {
		if err := client.Scan(ctx, iface); err != nil {
			return nil, fmt.Errorf("nl80211 scan for %s: %w", ifname, err)
		}
	}
	accessPoints, err := client.AccessPoints(iface)
	if err != nil {
		return nil, fmt.Errorf("nl80211 BSS dump for %s: %w", ifname, err)
	}
	out := make([]ScanEntry, 0, len(accessPoints))
	for _, bss := range accessPoints {
		if bss == nil || len(bss.BSSID) != 6 {
			continue
		}
		entry := ScanEntry{
			SSID:               bss.SSID,
			BSSID:              append(net.HardwareAddr(nil), bss.BSSID...),
			Frequency:          bss.Frequency,
			SignalDBM:          int(bss.Signal / 100),
			LastSeen:           bss.LastSeen,
			BSSLoadKnown:       bss.Load.Version == 1 || bss.Load.Version == 2,
			StationCount:       bss.Load.StationCount,
			ChannelUtilization: bss.Load.ChannelUtilization,
		}
		entry.ChannelUtilizationKnown = entry.BSSLoadKnown
		out = append(out, entry)
	}
	return out, nil
}

func runtimeNL80211Interface(ifname string) (*linuxwifi.Client, *linuxwifi.Interface, error) {
	client, err := linuxwifi.New()
	if err != nil {
		return nil, nil, fmt.Errorf("open nl80211: %w", err)
	}
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	interfaces, err := client.Interfaces()
	if err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("list nl80211 interfaces: %w", err)
	}
	for _, iface := range interfaces {
		if iface != nil && iface.Name == ifname {
			// GET_STATION and GET_SCAN dumps are scoped by IFINDEX. Supplying the
			// interface's own MAC accidentally turns AP dumps into a lookup for
			// the AP itself on kernels which honor NL80211_ATTR_MAC.
			copyIface := *iface
			copyIface.HardwareAddr = nil
			return client, &copyIface, nil
		}
	}
	client.Close()
	return nil, nil, fmt.Errorf("nl80211 interface %s not found", ifname)
}

func runtimeInterfaceMode(mode linuxwifi.InterfaceType) string {
	switch mode {
	case linuxwifi.InterfaceTypeAP:
		return "ap"
	case linuxwifi.InterfaceTypeAPVLAN:
		return "ap-vlan"
	case linuxwifi.InterfaceTypeStation:
		return "station"
	case linuxwifi.InterfaceTypeMeshPoint:
		return "mesh"
	case linuxwifi.InterfaceTypeWDS:
		return "wds"
	case linuxwifi.InterfaceTypeMonitor:
		return "monitor"
	case linuxwifi.InterfaceTypeAdHoc:
		return "adhoc"
	default:
		return "unknown"
	}
}

func runtimeChannelWidth(width linuxwifi.ChannelWidth) string {
	switch width {
	case linuxwifi.ChannelWidth20NoHT, linuxwifi.ChannelWidth20:
		return "20"
	case linuxwifi.ChannelWidth40:
		return "40"
	case linuxwifi.ChannelWidth80:
		return "80"
	case linuxwifi.ChannelWidth80P80:
		return "80+80"
	case linuxwifi.ChannelWidth160:
		return "160"
	case linuxwifi.ChannelWidth320:
		return "320"
	case linuxwifi.ChannelWidth1:
		return "1"
	case linuxwifi.ChannelWidth2:
		return "2"
	case linuxwifi.ChannelWidth4:
		return "4"
	case linuxwifi.ChannelWidth5:
		return "5"
	case linuxwifi.ChannelWidth8:
		return "8"
	case linuxwifi.ChannelWidth10:
		return "10"
	case linuxwifi.ChannelWidth16:
		return "16"
	default:
		return ""
	}
}
