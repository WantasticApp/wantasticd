// Package assets embeds the application icon assets used by the systray
// and any other component that needs binary icon data at runtime.
package assets

import _ "embed"

// TrayIcon is the 22×22 colour PNG used for the systray on Linux/Windows
// and as a fallback on macOS.
//
//go:embed tray_icon.png
var TrayIcon []byte

// TrayIconTemplate is the 22×22 grayscale PNG used as a macOS template image
// so the menu-bar icon adapts automatically to light/dark mode.
//
//go:embed tray_icon_template.png
var TrayIconTemplate []byte
