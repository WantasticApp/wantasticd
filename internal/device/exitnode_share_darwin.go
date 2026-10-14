//go:build darwin
// +build darwin

package device

import "fmt"

func enableExitNodeSharingOS(tunName string) (string, error) {
	return "", fmt.Errorf("exit-node sharing requires a Network Extension with managed NAT on macOS")
}

func disableExitNodeSharingOS(tunName string) error {
	return nil
}

func enableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	return fmt.Errorf("automatic local-access subnet routing is not supported on macOS yet")
}

func disableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	return nil
}
