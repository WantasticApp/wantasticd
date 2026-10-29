//go:build darwin
// +build darwin

package device

import "fmt"

func enableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	return fmt.Errorf("automatic local-access subnet routing is not supported on macOS yet")
}

func disableLocalAccessSharingOS(tunName string, routes, sources []string) error {
	return nil
}
