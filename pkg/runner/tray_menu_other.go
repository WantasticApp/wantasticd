//go:build (windows || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import "github.com/getlantern/systray"

// The menu open/close hooks, keep-open rows, switches and large images are
// macOS only; elsewhere the menu keeps its usual behaviour and refreshes on
// its timer.
const trayKnowsMenuOpen = false

func watchMenu(*systray.MenuItem, func(), func()) {}

func keepMenuOpen(...*systray.MenuItem) {}

func menuSwitch(...*systray.MenuItem) {}

// setMenuImage reports false: the menu library draws item images at 16 px,
// too small for a QR code.
func setMenuImage(*systray.MenuItem, []byte, int) bool { return false }
