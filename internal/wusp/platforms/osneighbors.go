package platforms

import (
	"context"
	"net"
	"sort"
	"strings"

	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/neighbors"
)

// osNeighborReading is what a platform's passive read of the OS neighbor
// cache returns. Every field is what that OS can supply and empty where it
// cannot.
type osNeighborReading struct {
	Entries []neighbors.Entry
	// Gateways maps an interface name to its default gateway address.
	Gateways map[string]string
	// Aliases maps an interface name to the friendlier name the OS shows.
	Aliases map[string]string
	// Types maps an interface name to its medium as the OS classifies it,
	// in the Interface.{i}.Type vocabulary. Empty where the OS does not say
	// and the name heuristic has to stand in.
	Types map[string]string
	// Status is a neighbors.Status* value; empty means ok.
	Status       string
	StatusDetail string
}

// maxNeighborEntries bounds how many cache entries a platform read decodes, so
// a pathological table cannot grow the agent without limit. The model caps the
// reported rows separately, at WUSPNeighborsMaxNeighbors.
const maxNeighborEntries = 1024

// neighborFirstSeen remembers when each neighbor was first seen, so a row can
// report FirstSeenTime. It is filled by collection only: nothing here runs on
// a timer.
var neighborFirstSeen = neighbors.NewFirstSeen()

// collectNeighbors fills Device.WUSP_Neighbors. from the OS's own ARP and
// neighbor caches.
//
// Strictly passive: it reads the cache the OS already keeps and never probes,
// pings, ARP-sweeps or scans a neighbor. Reachable is derived from the cache
// state the OS reported.
func (b *hostBackend) collectNeighbors(ctx context.Context, msg *wusp.Message, desktop *desktopSnapshot) {
	platform := neighborPlatform(b.kind)
	installed := osNeighborsSupported && platform != "" && desktopKind(b.kind)
	enabled := osFeatureEnabled(featureNeighbors)

	snap := neighbors.Snapshot{Platform: platform}
	if installed && enabled {
		reading, err := osReadNeighborCache(ctx)
		switch {
		case err != nil:
			snap.Status = neighbors.StatusReadError
			snap.StatusDetail = err.Error()
			if isPermissionError(err) {
				snap.Status = neighbors.StatusPermissionDenied
			}
		default:
			snap.Status = reading.Status
			snap.StatusDetail = reading.StatusDetail
			snap.Entries = reading.Entries
			snap.Interfaces = neighborInterfaces(desktop, reading, snap.Entries)
		}
	}
	neighbors.Append(msg, snap, installed, enabled, b.now(), neighborFirstSeen)
}

func neighborPlatform(kind Kind) string {
	switch kind {
	case KindMacOS:
		return neighbors.PlatformMacOS
	case KindWindows:
		return neighbors.PlatformWindows
	default:
		return ""
	}
}

// setNeighborsParam applies a Device.WUSP_Neighbors. write. The only
// writable leaf in the model is Enable; everything else is read-only, so an
// attempt to write it is reported as unsupported rather than silently ignored.
func setNeighborsParam(path string, value wusp.Value) error {
	if strings.TrimSpace(path) == wusp.WUSPNeighborsPrefix+"Enable" {
		return setOSFeatureEnabled(featureNeighbors, value.AsBool())
	}
	return wusp.ErrUSPPathUnsupported
}

// neighborInterfaces builds the interface table from net.Interfaces() plus
// whatever the platform could add. Interfaces that actually have neighbors
// come first, so the table cap never drops a populated one.
func neighborInterfaces(desktop *desktopSnapshot, reading osNeighborReading, entries []neighbors.Entry) []neighbors.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	withNeighbors := make(map[string]bool, len(entries))
	for _, entry := range entries {
		withNeighbors[entry.Interface] = true
	}

	out := make([]neighbors.Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		up := iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagRunning != 0
		if !up && !withNeighbors[iface.Name] {
			continue
		}
		row := neighbors.Interface{
			Name:           iface.Name,
			Alias:          reading.Aliases[iface.Name],
			Type:           neighborInterfaceType(iface, desktop, reading.Types[iface.Name]),
			MACAddress:     strings.ToUpper(iface.HardwareAddr.String()),
			GatewayAddress: reading.Gateways[iface.Name],
			Up:             up,
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			prefix, ok := addr.(*net.IPNet)
			if !ok || prefix.IP == nil {
				continue
			}
			if v4 := prefix.IP.To4(); v4 != nil {
				if row.IPv4Address == "" {
					row.IPv4Address = prefix.String()
				}
				continue
			}
			row.IPv6Addresses = append(row.IPv6Addresses, prefix.String())
		}
		out = append(out, row)
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := withNeighbors[out[i].Name], withNeighbors[out[j].Name]
		if a != b {
			return a
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// neighborInterfaceType classifies an interface's medium the way the model's
// Interface.{i}.Type enum wants it. What the OS itself says wins; the name
// heuristic only stands in where it says nothing.
func neighborInterfaceType(iface net.Interface, desktop *desktopSnapshot, osKind string) string {
	name := strings.ToLower(iface.Name)
	if kind := neighbors.NormalizeInterfaceType(osKind); kind != "" && kind != "other" {
		return kind
	}
	if desktop != nil {
		if info, ok := desktop.Interfaces[iface.Name]; ok {
			switch {
			case info.Wireless:
				return "wifi"
			case info.Tunnel:
				return "vpn"
			}
		}
	}
	switch {
	case strings.HasPrefix(name, "bridge"), strings.HasPrefix(name, "br-"), strings.HasPrefix(name, "br"):
		return "bridge"
	case strings.HasPrefix(name, "utun"), strings.HasPrefix(name, "ipsec"), strings.HasPrefix(name, "wg"),
		strings.Contains(name, "wintun"), strings.Contains(name, "wantastic"):
		return "vpn"
	case strings.HasPrefix(name, "pdp_ip"), strings.Contains(name, "cellular"), strings.Contains(name, "wwan"):
		return "cellular"
	case strings.HasPrefix(name, "wi-fi"), strings.HasPrefix(name, "wlan"), strings.HasPrefix(name, "wifi"):
		return "wifi"
	case strings.HasPrefix(name, "ethernet"), strings.HasPrefix(name, "en"), strings.HasPrefix(name, "eth"):
		if len(iface.HardwareAddr) > 0 {
			return "ethernet"
		}
		return "virtual"
	case len(iface.HardwareAddr) > 0:
		return "ethernet"
	default:
		return "virtual"
	}
}

// isPermissionError reports whether err says the agent is not privileged
// enough, which the model distinguishes from a plain read failure.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "permission denied") ||
		strings.Contains(text, "operation not permitted") ||
		strings.Contains(text, "access is denied") ||
		strings.Contains(text, "not privileged")
}
