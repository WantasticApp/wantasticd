//go:build windows
// +build windows

package device

import "fmt"

func enableExitNodeSharingOS(tunName string) (string, error) {
	return "", fmt.Errorf("exit-node sharing requires a privileged service with managed NAT on Windows")
}

func disableExitNodeSharingOS(tunName string) error {
	return nil
}

func enableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	return fmt.Errorf("automatic local-access subnet routing is not supported on Windows yet")
}

func disableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	return nil
}
