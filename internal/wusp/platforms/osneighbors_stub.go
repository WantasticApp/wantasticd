//go:build !darwin && !windows

package platforms

import "context"

// osNeighborsSupported: Device.WUSP_Neighbors. is a Windows and macOS model.
// Linux devices report their neighbors through the OpenWrt/Linux WiFi and
// link-discovery collectors instead, so this backend says it is not
// installed rather than inventing a table.
const osNeighborsSupported = false

func osReadNeighborCache(context.Context) (osNeighborReading, error) {
	return osNeighborReading{}, nil
}
