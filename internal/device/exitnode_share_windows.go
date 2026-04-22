//go:build windows
// +build windows

package device

func enableExitNodeSharingOS(tunName string) (string, error) {
	if err := ctl.IPForwardingSet(true); err != nil {
		return "", err
	}
	return "IP forwarding enabled. NAT requires manual configuration on Windows.", nil
}

func disableExitNodeSharingOS(tunName string) error {
	return ctl.IPForwardingSet(false)
}
