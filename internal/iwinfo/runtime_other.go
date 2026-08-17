//go:build !linux

package iwinfo

import (
	"context"
	"fmt"
)

func RuntimeInterfaces() ([]WirelessInterface, error) {
	return nil, fmt.Errorf("nl80211 runtime inventory is only available on Linux")
}

func CachedScan(string) ([]ScanEntry, error) {
	return nil, fmt.Errorf("nl80211 scan cache is only available on Linux")
}

func ActiveScan(context.Context, string) ([]ScanEntry, error) {
	return nil, fmt.Errorf("nl80211 active scan is only available on Linux")
}
