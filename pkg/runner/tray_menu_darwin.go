//go:build darwin && !nosystray

package runner

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa

void wtWatchMenu(int menuId);
void wtKeepOpen(int menuId, int asSwitch);
void wtSetImage(int menuId, const void *bytes, int length, int points);
*/
import "C"

import (
	"os/exec"
	"reflect"
	"sync"
	"unsafe"

	"github.com/getlantern/systray"
)

// trayKnowsMenuOpen: the menu reports when it opens, so the tray pings live
// and polls fast only while it is showing.
const trayKnowsMenuOpen = true

const darwinTrayLog = "/Library/Logs/Wantastic/wantasticd.log"

func trayLogPath() string { return darwinTrayLog }

// openLogFile shows the log in Console, which follows it live.
func openLogFile(path string) error { return exec.Command("open", "-a", "Console", path).Start() }

var menuHooks sync.Map // menu id -> *menuHook

type menuHook struct {
	opened, closed func()
}

// watchMenu calls opened when the user opens the menu (item nil) or the
// submenu under item, and closed when it closes. Callbacks run on their own
// goroutine.
func watchMenu(item *systray.MenuItem, opened, closed func()) {
	id := 0
	if item != nil {
		id = menuItemID(item)
	}
	menuHooks.Store(id, &menuHook{opened: opened, closed: closed})
	C.wtWatchMenu(C.int(id))
}

// keepMenuOpen makes clicks on items run their action without closing the
// menu, so the result shows in place.
func keepMenuOpen(items ...*systray.MenuItem) {
	for _, item := range items {
		C.wtKeepOpen(C.int(menuItemID(item)), 0)
	}
}

// menuSwitch shows each item's checked state as an on/off switch; the
// item also stays open on click.
func menuSwitch(items ...*systray.MenuItem) {
	for _, item := range items {
		C.wtKeepOpen(C.int(menuItemID(item)), 1)
	}
}

// setMenuImage shows png at points x points beside the item's title.
func setMenuImage(item *systray.MenuItem, png []byte, points int) bool {
	if len(png) == 0 {
		return false
	}
	C.wtSetImage(C.int(menuItemID(item)), unsafe.Pointer(&png[0]), C.int(len(png)), C.int(points))
	return true
}

// menuItemID is the library's id for item; the native menu tags each
// NSMenuItem with it.
func menuItemID(item *systray.MenuItem) int {
	return int(reflect.ValueOf(item).Elem().FieldByName("id").Uint())
}

//export wantasticMenuOpened
func wantasticMenuOpened(id C.int) {
	if h, ok := menuHooks.Load(int(id)); ok && h.(*menuHook).opened != nil {
		go h.(*menuHook).opened()
	}
}

//export wantasticMenuClosed
func wantasticMenuClosed(id C.int) {
	if h, ok := menuHooks.Load(int(id)); ok && h.(*menuHook).closed != nil {
		go h.(*menuHook).closed()
	}
}
