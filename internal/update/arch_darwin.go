//go:build darwin

package update

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// releaseArch is the architecture to download. An Intel build running under
// Rosetta on Apple silicon (installed from a translated shell) updates to the
// native arm64 build instead of staying translated forever.
func releaseArch() string {
	if runtime.GOARCH == "amd64" {
		if translated, err := unix.SysctlUint32("sysctl.proc_translated"); err == nil && translated == 1 {
			return "arm64"
		}
	}
	return runtime.GOARCH
}
