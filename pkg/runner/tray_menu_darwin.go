//go:build darwin && !nosystray

package runner

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>

void wtWatchMenu(int menuId);
void wtKeepOpen(int menuId, int asSwitch);
void wtSetImage(int menuId, const void *bytes, int length, int points);
void wtSetTrash(int menuId, int mode);
void wtBindText(int menuId, const char *templates, const char *initial, int tabular, int reserve);
void wtSetText(int menuId, const char *text, const char *tip);
*/
import "C"

import (
	"os/exec"
	"reflect"
	"strings"
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

// bindRow makes item a natively drawn row whose text changes with setRowText.
// Only that row redraws: the item's title is never touched, so AppKit never
// re-lays out the open menu (which is what made live values flicker).
// templates are the texts the row may show; the widest sizes it up front so
// a changing value never widens the menu. tabular draws digits at a fixed
// width. reserve keeps the menu's checkmark column, so native rows line up
// with drawn ones whether or not a switch is on.
func bindRow(item *systray.MenuItem, initial string, tabular, reserve bool, templates ...string) {
	tpl := C.CString(strings.Join(append(templates, initial), "\n"))
	first := C.CString(initial)
	defer C.free(unsafe.Pointer(tpl))
	defer C.free(unsafe.Pointer(first))
	C.wtBindText(C.int(menuItemID(item)), tpl, first, cBool(tabular), cBool(reserve))
	boundRows.Store(item, true)
	menuText.Store(menuTextKey{item: item, bound: true}, initial)
}

var boundRows sync.Map // *systray.MenuItem -> true

// setRowText shows text on a row; a bound row redraws only itself.
func setRowText(item *systray.MenuItem, text string) {
	if _, ok := boundRows.Load(item); !ok {
		setTitle(item, text)
		return
	}
	setMenuText(menuTextKey{item: item, bound: true}, text, func(t string) {
		ct := C.CString(t)
		defer C.free(unsafe.Pointer(ct))
		C.wtSetText(C.int(menuItemID(item)), ct, nil)
	})
}

// setRowTip sets a row's tooltip; on a bound row without touching the item.
func setRowTip(item *systray.MenuItem, tip string) {
	if _, ok := boundRows.Load(item); !ok {
		setTooltip(item, tip)
		return
	}
	setMenuText(menuTextKey{item: item, bound: true, tooltip: true}, tip, func(t string) {
		key := menuTextKey{item: item, bound: true}
		cur := ""
		if v, ok := menuText.Load(key); ok {
			cur = v.(string)
		}
		ct, ctip := C.CString(cur), C.CString(t)
		defer C.free(unsafe.Pointer(ct))
		defer C.free(unsafe.Pointer(ctip))
		C.wtSetText(C.int(menuItemID(item)), ct, ctip)
	})
}

func cBool(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

// setMenuImage shows png at points x points beside the item's title.
func setMenuImage(item *systray.MenuItem, png []byte, points int) bool {
	if len(png) == 0 {
		return false
	}
	C.wtSetImage(C.int(menuItemID(item)), unsafe.Pointer(&png[0]), C.int(len(png)), C.int(points))
	return true
}

var trashHooks sync.Map // menu id -> func()

// menuTrash puts a bin at the right edge of item's row (macOS): a click on
// it runs onClick, the rest of the row keeps its action. Armed draws it red.
// Off removes it. It reports whether rows can carry a bin here.
func menuTrash(item *systray.MenuItem, show, armed bool, onClick func()) bool {
	id := menuItemID(item)
	mode := 0
	switch {
	case show && armed:
		mode = 2
	case show:
		mode = 1
	}
	if mode == 0 {
		trashHooks.Delete(id)
	} else {
		trashHooks.Store(id, onClick)
	}
	C.wtSetTrash(C.int(id), C.int(mode))
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

//export wantasticMenuTrash
func wantasticMenuTrash(id C.int) {
	if fn, ok := trashHooks.Load(int(id)); ok && fn.(func()) != nil {
		go fn.(func())()
	}
}

//export wantasticMenuClosed
func wantasticMenuClosed(id C.int) {
	if h, ok := menuHooks.Load(int(id)); ok && h.(*menuHook).closed != nil {
		go h.(*menuHook).closed()
	}
}

// rowsCarryTrash: account rows draw their own bin (menuTrash).
func rowsCarryTrash() bool { return true }

// trashMenuIcon is unused on macOS: rows draw the system trash symbol.
func trashMenuIcon() []byte { return nil }
