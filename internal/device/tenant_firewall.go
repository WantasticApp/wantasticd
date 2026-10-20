package device

import (
	"net/netip"
	"sort"
	"strings"

	"wantastic-agent/internal/netctl"
)

// tenantFirewallRules derives host-inbound exceptions from the same AllowedIPs
// that configure WireGuard. Default routes are deliberately excluded: they do
// not describe a tenant subnet and must never turn into a broad firewall allow.
func tenantFirewallRules(ifname string, addresses []netip.Prefix, allowedIPs []string) []netctl.TenantFirewallRule {
	remoteByFamily := map[bool]map[netip.Prefix]struct{}{
		false: {},
		true:  {},
	}
	for _, value := range allowedIPs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			continue
		}
		remoteByFamily[prefix.Addr().Is6()][prefix] = struct{}{}
	}

	result := make([]netctl.TenantFirewallRule, 0, len(addresses))
	for _, localPrefix := range addresses {
		local := localPrefix.Addr().Unmap()
		if !local.IsValid() || local.IsUnspecified() || local.IsMulticast() {
			continue
		}
		remoteSet := remoteByFamily[local.Is6()]
		if len(remoteSet) == 0 {
			continue
		}
		remote := make([]netip.Prefix, 0, len(remoteSet))
		for prefix := range remoteSet {
			remote = append(remote, prefix)
		}
		sort.Slice(remote, func(i, j int) bool { return remote[i].String() < remote[j].String() })
		result = append(result, netctl.TenantFirewallRule{
			Interface: ifname,
			Local:     local,
			Remote:    remote,
		})
	}
	return result
}
