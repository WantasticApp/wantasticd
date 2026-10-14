//go:build darwin

package main

// This file defines the C function declared in tray_darwin_export.go.
// It must NOT use //export — the definition lives here to satisfy the CGO rule.

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

extern void goTrayDispatchCB(void);

void dispatchSyncMainImpl(void) {
    // Submit goTrayDispatchCB to the macOS main run loop and wait for it to
    // complete. dispatch_sync from a background thread to the main queue is
    // safe as long as the main run loop is already running (guaranteed here
    // because Wails calls OnStartup only after NSApplicationMain is active).
    dispatch_sync(dispatch_get_main_queue(), ^{
        goTrayDispatchCB();
    });
}

void configureTrayOnlyAppImpl(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    });
}

void activateDesktopAppImpl(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp activateIgnoringOtherApps:YES];
    });
}
*/
import "C"
