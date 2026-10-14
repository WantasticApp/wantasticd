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
	systray.SetOnTapped(a.showMainWindow)

	mStatus := systray.AddMenuItem("Status: –", "")
	mStatus.Disable()
	mIP := systray.AddMenuItem("IP: –", "")
	mIP.Disable()
	systray.AddSeparator()

	mToggle := systray.AddMenuItem("Connect", "Toggle VPN connection")
	mClaim := systray.AddMenuItem("Generate Claim Link", "Claim this device into a tenant")
	mConsole := systray.AddMenuItem("Open Console", "Open the Wantastic portal")
	mShow := systray.AddMenuItem("Open Wantastic", "Open peer and routing controls")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit Wantastic", "Stop VPN and exit")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Refresh immediately on first tick.
	a.updateTray(mStatus, mIP, mToggle)

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
			a.showMainWindow()

		case <-mToggle.ClickedCh:
			go func() {
				if err := a.ToggleVPN(); err != nil {
					log.Printf("systray: ToggleVPN: %v", err)
				}
			}()

		case <-mClaim.ClickedCh:
			claim, err := a.GenerateClaimLink("https://console.wantastic.app", false)
			if err != nil {
				log.Printf("systray: GenerateClaimLink: %v", err)
				continue
			}
			_ = a.OpenURL(claim.ClaimURL)

		case <-mConsole.ClickedCh:
			a.OpenConsole()

		case <-ticker.C:
			a.updateTray(mStatus, mIP, mToggle)
		}
	}
}

// updateTray refreshes tray menu labels and item visibility.
func (a *App) updateTray(
	mStatus, mIP *systray.MenuItem,
	mToggle *systray.MenuItem,
) {
	st, err := a.GetStatus()
	presentation := makeTrayPresentation(st, err)
	mToggle.SetTitle(presentation.toggleTitle)
	mStatus.SetTitle(presentation.statusTitle)
	mIP.SetTitle(presentation.ipTitle)
	systray.SetTooltip(presentation.tooltip)
}

type trayPresentation struct {
	statusTitle string
	ipTitle     string
	toggleTitle string
	tooltip     string
}

func makeTrayPresentation(st *StatusData, err error) trayPresentation {
	state := "Unavailable"
	toggle := "Connect"
	ip := "–"

	if err == nil && st != nil {
		switch {
		case st.Running:
			state = "Connected"
			toggle = "Disconnect"
		case st.Configured:
			state = "Disconnected"
		default:
			state = "Not configured"
		}
		if len(st.IPs) > 0 && st.IPs[0] != "" {
			ip = st.IPs[0]
		}
	}

	tooltip := fmt.Sprintf("Wantastic VPN — %s", state)
	if ip != "–" {
		tooltip = fmt.Sprintf("%s — %s", tooltip, ip)
	}
	return trayPresentation{
		statusTitle: fmt.Sprintf("Status: %s", state),
		ipTitle:     fmt.Sprintf("IP: %s", ip),
		toggleTitle: toggle,
		tooltip:     tooltip,
	}
}
