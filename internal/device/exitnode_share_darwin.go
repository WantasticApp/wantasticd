//go:build darwin
// +build darwin

package device

import "fmt"

func enableExitNodeSharingOS(tunName string) (string, error) {
	if err := ctl.IPForwardingSet(true); err != nil {
		return "", err
	}
	return "IP forwarding enabled. NAT requires manual PF or Internet Sharing on macOS.", nil
}

func disableExitNodeSharingOS(tunName string) error {
	return ctl.IPForwardingSet(false)
}

func enableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	return fmt.Errorf("automatic local-access subnet routing is not supported on macOS yet")
}

func disableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	return nil
}
