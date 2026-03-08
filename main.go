package main

import (
	"context"
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:gui/frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:             "Wantastic",
		Width:             420,
		Height:            640,
		MinWidth:          380,
		MinHeight:         520,
		MaxWidth:          520,
		MaxHeight:         860,
		DisableResize:     false,
		Fullscreen:        false,
		Frameless:         false,
		StartHidden:       false,
		HideWindowOnClose: false,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 10, G: 12, B: 20, A: 255},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		OnBeforeClose:    app.beforeClose,
		Bind: []interface{}{
			app,
		},
		Mac: &mac.Options{
			About: &mac.AboutInfo{
				Title:   "Wantastic",
				Message: "Wantastic VPN Desktop Client\n© 2026 Wantastic",
			},
			Appearance:           mac.NSAppearanceNameDarkAqua,
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			DisablePinchZoom:     true,
			DisableWindowIcon:    false,
		},
	})

	if err != nil {
		log.Fatal(err)
	}
}

func (a *App) beforeClose(_ context.Context) bool {
	return false // allow close
}
