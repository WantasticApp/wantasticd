//go:build (linux && !cgo) || (linux && cgo && !amd64 && !arm64) || (!linux && !darwin && !windows) || nosystray
// +build linux,!cgo linux,cgo,!amd64,!arm64 !linux,!darwin,!windows nosystray

package runner

import (
	"context"
	"log"
)

// RunSystray is a stub for headless Linux environments where CGO is disabled
// and GTK libraries are not available.
func RunSystray(ctx context.Context, cancel context.CancelFunc) {
	log.Println("System tray is not supported in this headless (CGO_ENABLED=0) build.")
	<-ctx.Done()
}
