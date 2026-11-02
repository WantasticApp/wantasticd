//go:build (windows || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import "errors"

// The tray offers no uninstall here: Linux uses install.sh --uninstall,
// Windows `wantasticd uninstall` or install.ps1 -Uninstall.
const trayCanUninstall = false

var errUninstallCanceled = errors.New("uninstall canceled")

func trayUninstall() error { return errors.New("uninstall is not available here") }
