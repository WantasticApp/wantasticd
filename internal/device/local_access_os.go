//go:build !windows

package device

// Linux shares LANs with kernel forwarding and NAT; macOS does not yet.
func (d *Device) enableLocalAccessOS(tunName string, routes, sources []string) error {
	return enableLocalAccessSharingOS(tunName, routes, sources)
}

func (d *Device) disableLocalAccessOS(tunName string, routes, sources []string) error {
	return disableLocalAccessSharingOS(tunName, routes, sources)
}
