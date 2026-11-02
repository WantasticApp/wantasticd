//go:build !darwin && !windows

package platforms

func newDesktopProbe(CommandRunner) desktopProbe { return nil }
