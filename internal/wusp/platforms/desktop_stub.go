//go:build !darwin && !windows && !android

package platforms

func newDesktopProbe(CommandRunner) desktopProbe { return nil }
