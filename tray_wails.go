package main

import (
	"fmt"
	"log"
	"time"

	"fyne.io/systray"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"wantastic-agent/assets"
)

// startSystray initialises the system tray icon using fyne.io/systray's
// RunWithExternalLoop so that the systray does NOT start its own [NSApp run]
// or define a competing AppDelegate — Wails owns the main run loop.
//
// On macOS, NSStatusItem creation must happen on the main thread. We use
// dispatchSyncMain (see tray_darwin_export.go / tray_darwin_impl.go) to
// submit start() to the Cocoa main run loop via dispatch_sync.
//
// Must be called as a goroutine from startup() after Wails has booted.
func (a *App) startSystray() {
	start, end := systray.RunWithExternalLoop(a.onSystrayReady, func() {
		log.Println("systray: exited")
	})

	// dispatch_sync to main thread; blocks until NSStatusItem is created.
	dispatchSyncMain(start)

	<-a.ctx.Done()
	end()
}

func (a *App) onSystrayReady() {
	// macOS: use template icon so it adapts to light/dark menu bar.
	// Other platforms: use the colour icon.
	systray.SetTemplateIcon(assets.TrayIconTemplate, assets.TrayIcon)
	systray.SetTooltip("Wantastic VPN")

	mStatus := systray.AddMenuItem("Status: –", "")
	mStatus.Disable()
	mIP := systray.AddMenuItem("IP: –", "")
	mIP.Disable()
	systray.AddSeparator()

	mToggle  := systray.AddMenuItem("Connect", "Toggle VPN connection")
	mLogin   := systray.AddMenuItem("Sign In…", "Sign in to Wantastic")
	mConsole := systray.AddMenuItem("Open Console", "Open the Wantastic portal")
	mShow    := systray.AddMenuItem("Show Window", "Bring the window to the front")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit Wantastic", "Stop VPN and exit")

	// Initial visibility: hide login/console until we know auth state.
	mLogin.Hide()
	mConsole.Hide()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Refresh immediately on first tick.
	a.updateTray(mStatus, mIP, mToggle, mLogin, mConsole)

	for {
		select {
		case <-a.ctx.Done():
			systray.Quit()
			return

		case <-mQuit.ClickedCh:
			a.stopEmbeddedAgent()
			systray.Quit()
			wailsruntime.Quit(a.ctx)
			return

		case <-mShow.ClickedCh:
			wailsruntime.WindowShow(a.ctx)

		case <-mToggle.ClickedCh:
			go func() {
				if err := a.ToggleVPN(); err != nil {
					log.Printf("systray: ToggleVPN: %v", err)
				}
			}()

		case <-mLogin.ClickedCh:
			wailsruntime.WindowShow(a.ctx)
			a.StartLogin()

		case <-mConsole.ClickedCh:
			wailsruntime.WindowShow(a.ctx)
			a.OpenConsoleWebView()

		case <-ticker.C:
			a.updateTray(mStatus, mIP, mToggle, mLogin, mConsole)
		}
	}
}

// updateTray refreshes tray menu labels and item visibility.
func (a *App) updateTray(
	mStatus, mIP *systray.MenuItem,
	mToggle, mLogin, mConsole *systray.MenuItem,
) {
	st, err := a.GetStatus()
	if err == nil && st != nil {
		if st.Running {
			mToggle.SetTitle("Disconnect")
			mStatus.SetTitle("Status: Connected")
		} else {
			mToggle.SetTitle("Connect")
			if st.Configured {
				mStatus.SetTitle("Status: Disconnected")
			} else {
				mStatus.SetTitle("Status: Not configured")
			}
		}
		ip := "–"
		if len(st.IPs) > 0 {
			ip = st.IPs[0]
		}
		mIP.SetTitle(fmt.Sprintf("IP: %s", ip))
	}

	if a.auth.StoredToken() == "" {
		mLogin.Show()
		mConsole.Hide()
	} else {
		mLogin.Hide()
		mConsole.Show()
	}
}
