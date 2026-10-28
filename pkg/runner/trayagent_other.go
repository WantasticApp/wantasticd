//go:build !darwin

package runner

// EnsureTrayAgent is a no-op outside macOS: the Windows installer registers
// the tray, and Linux builds are headless.
func EnsureTrayAgent() {}
