//go:build !darwin && !windows

package runner

// EnsureTrayAgent is a no-op on headless platforms.
func EnsureTrayAgent() {}
