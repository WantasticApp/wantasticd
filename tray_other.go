//go:build !darwin

package main

// dispatchSyncMain on non-macOS platforms: call fn directly.
// Linux (GTK) and Windows (UI thread) initialise their systray
// differently and do not require a CGO main-queue dispatch.
func dispatchSyncMain(fn func()) {
	fn()
}
