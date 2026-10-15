package main

import (
	"embed"
	"io/fs"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"wantastic-agent/assets"
)

//go:embed all:gui/frontend/dist
var frontendAssets embed.FS

func main() {
	if handled, err := runPrivilegedAgentMode(); handled {
		if err != nil {
			log.Printf("privileged tunnel helper: %v", err)
			os.Exit(1)
		}
		return
	}
	webAssets, err := fs.Sub(frontendAssets, "gui/frontend/dist")
	if err != nil {
		log.Fatal(err)
	}

	desktop := application.New(application.Options{
		Name:        "Wantastic",
		Description: "Secure access to your Wantastic tenant network",
		Icon:        assets.TrayIcon,
		Assets: application.AssetOptions{
			Handler:        application.AssetFileServerFS(webAssets),
			DisableLogging: true,
		},
		Mac: application.MacOptions{
			ActivationPolicy: application.ActivationPolicyAccessory,
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
		Windows: application.WindowsOptions{
			DisableQuitOnLastWindowClosed: true,
		},
		Linux: application.LinuxOptions{
			DisableQuitOnLastWindowClosed: true,
			ApplicationID:                 "app.wantastic.desktop",
			ProgramName:                   "Wantastic",
		},
	})

	service := NewApp(desktop)
	desktop.RegisterService(application.NewService(service))
	windowURL := "/"
	if os.Getenv("WANTASTIC_DESKTOP_PREVIEW") == "1" {
		windowURL = "/?preview=1"
	}

	window := desktop.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:                       "wantastic-tray",
		Title:                      "Wantastic",
		Width:                      420,
		Height:                     680,
		MinWidth:                   420,
		MinHeight:                  680,
		MaxWidth:                   420,
		MaxHeight:                  680,
		Frameless:                  true,
		AlwaysOnTop:                true,
		Hidden:                     true,
		DisableResize:              true,
		HideOnEscape:               true,
		HideOnFocusLost:            true,
		DefaultContextMenuDisabled: true,
		BackgroundColour:           application.NewRGB(7, 17, 27),
		URL:                        windowURL,
		Windows: application.WindowsWindow{
			HiddenOnTaskbar:         true,
			Theme:                   application.Dark,
			NonClientRegionSupport:  true,
			GeneralAutofillEnabled:  false,
			PasswordAutosaveEnabled: false,
		},
		Mac: application.MacWindow{
			Appearance:  application.NSAppearanceNameDarkAqua,
			WindowClass: application.MacWindowClassPanel,
			CornerType:  application.MacWindowCornerTypeRounded,
			WindowLevel: application.MacWindowLevelFloating,
			TabbingMode: application.MacWindowTabbingModeDisallowed,
			PanelPreferences: application.MacPanelPreferences{
				FloatingPanel: true,
			},
		},
	})
	window.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		window.Hide()
		event.Cancel()
	})
	service.setWindow(window)

	tray := desktop.SystemTray.New()
	tray.SetTooltip("Wantastic")
	if runtime.GOOS == "darwin" {
		tray.SetTemplateIcon(assets.TrayIconTemplate)
	} else {
		tray.SetIcon(assets.TrayIcon)
		tray.SetDarkModeIcon(assets.TrayIcon)
	}
	tray.AttachWindow(window).WindowOffset(6).WindowDebounce(180 * time.Millisecond)
	service.setSystemTray(tray)

	if err := desktop.Run(); err != nil {
		log.Fatal(err)
	}
}
