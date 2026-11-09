//go:build (windows || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"runtime"

	"github.com/getlantern/systray"
)

// The menu open/close hooks, keep-open rows, switches and large images are
// macOS only; elsewhere the menu keeps its usual behaviour and refreshes on
// its timer.
const trayKnowsMenuOpen = false

func watchMenu(*systray.MenuItem, func(), func()) {}

func keepMenuOpen(...*systray.MenuItem) {}

func menuSwitch(...*systray.MenuItem) {}

// Rows are plain menu items here: the menu is not redrawn live while open, so
// a title change cannot make it flicker.
func bindRow(*systray.MenuItem, string, bool, bool, ...string) {}

func setRowText(item *systray.MenuItem, text string) { setTitle(item, text) }

func setRowTip(item *systray.MenuItem, tip string) { setTooltip(item, tip) }

// setMenuImage reports false: the menu library draws item images at 16 px,
// too small for a QR code.
func setMenuImage(*systray.MenuItem, []byte, int) bool { return false }

// menuTrash reports false: rows cannot carry their own bin here, so the
// Account submenu lists removable accounts under "Remove an account".
func menuTrash(*systray.MenuItem, bool, bool, func()) bool { return false }

func rowsCarryTrash() bool { return false }

// trashMenuIcon is the bin beside each "Remove an account" entry, in the
// format the menu library wants (.ico on Windows).
func trashMenuIcon() []byte {
	png := trashIconPNG(16)
	if runtime.GOOS == "windows" {
		return pngToICO(png, 16)
	}
	return png
}
