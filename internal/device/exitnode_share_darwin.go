//go:build darwin
// +build darwin

package device

func enableExitNodeSharingOS(tunName string) (string, error) {
	if err := ctl.IPForwardingSet(true); err != nil {
		return "", err
	}
	return "IP forwarding enabled. NAT requires manual PF or Internet Sharing on macOS.", nil
}

func disableExitNodeSharingOS(tunName string) error {
	return ctl.IPForwardingSet(false)
}
