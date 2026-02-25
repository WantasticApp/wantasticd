//go:build darwin && !cgo

package stats

// collectWiFiStatisticsNative returns empty when CGO is disabled.
// The system_profiler fallback in collect_darwin.go will be used instead.
func collectWiFiStatisticsNative() ([]WiFiInterfaceInfo, bool) {
	return nil, false
}
