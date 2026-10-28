//go:build !darwin

package update

import "runtime"

// releaseArch is the architecture to download.
func releaseArch() string {
	return runtime.GOARCH
}
