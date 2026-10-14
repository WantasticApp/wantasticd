//go:build darwin

package main

// Preamble may only contain declarations (not definitions) because this file
// uses //export. See cmd/cgo documentation: "Using //export in a file places a
// restriction on the preamble: since it is copied into two C output files, it
// must not contain any definitions, only declarations."

/*
extern void dispatchSyncMainImpl(void);
extern void configureTrayOnlyAppImpl(void);
extern void activateDesktopAppImpl(void);
*/
import "C"

// _trayPendingFn holds the function to be called on the main thread.
// Set before calling dispatchSyncMainImpl; cleared inside goTrayDispatchCB.
var _trayPendingFn func()

//export goTrayDispatchCB
func goTrayDispatchCB() {
	fn := _trayPendingFn
	_trayPendingFn = nil
	if fn != nil {
		fn()
	}
}

// dispatchSyncMain runs fn synchronously on the macOS main thread.
// Safe to call from any goroutine once the NSApplication run loop is active
// (i.e., after wails.Run has started, which is the case by OnStartup time).
func dispatchSyncMain(fn func()) {
	_trayPendingFn = fn
	C.dispatchSyncMainImpl()
}

// configureTrayOnlyApp makes Wantastic a menu-bar application without a Dock
// icon. The Wails window remains available and is opened from the tray.
func configureTrayOnlyApp() {
	C.configureTrayOnlyAppImpl()
}

func activateDesktopApp() {
	C.activateDesktopAppImpl()
}
