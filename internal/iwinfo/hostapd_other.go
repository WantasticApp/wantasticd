//go:build !linux

package iwinfo

import "fmt"

func getHostapdAssocList(ifName string) ([]AssocEntry, error) {
	return nil, fmt.Errorf("hostapd control socket unsupported on this platform")
}
