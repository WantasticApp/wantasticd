//go:build !windows

package runner

// TrayAlreadyRunning is false outside Windows: launchd runs one menu-bar
// agent per user, and Linux builds are headless.
func TrayAlreadyRunning() bool { return false }
