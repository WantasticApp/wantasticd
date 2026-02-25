//go:build (!windows && !darwin && !linux) || (linux && !cgo) || (linux && cgo && !amd64 && !arm64) || nosystray

package runner

import (
	"context"
	"log"
)

// RunSystray is a stub for headless Linux environments where CGO is disabled
// and GTK libraries are not available.
func RunSystray(ctx context.Context, cancel context.CancelFunc) {
	log.Println("System tray is not supported in this build (Headless or nosystray).")
	<-ctx.Done()
}
