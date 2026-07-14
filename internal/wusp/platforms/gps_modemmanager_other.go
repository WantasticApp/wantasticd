//go:build !linux

package platforms

func gpsFromModemManager() *gpsInfo { return nil }
