//go:build linux && cgo && (amd64 || arm64) && !nosystray

package runner

import "errors"

// Linux installs are removed with install.sh --uninstall.
const trayCanUninstall = false

var errUninstallCanceled = errors.New("uninstall canceled")

func trayUninstall() error { return errors.New("uninstall is not available here") }
