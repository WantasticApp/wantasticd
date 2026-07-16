//go:build !linux

package platforms

func gpsFromModemManager() *gpsInfo { return nil }

func gpsFromQuectelAT() *gpsInfo { return nil }
