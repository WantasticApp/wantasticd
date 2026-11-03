//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"time"

	"rsc.io/qr"
)

const (
	trayConsoleURL = "https://console.wantastic.app"
	// trayIdleRefresh is the poll period while the menu is closed, where the
	// tray can tell (macOS); only the icon shows then.
	trayIdleRefresh = 3 * time.Second
	// loginQRPoints is the drawn size of the login QR code, large enough
	// for a phone camera at arm's length.
	loginQRPoints = 180
)

// loginQRPNG is the claim link as a QR code: the genkey claim flow the
// console's Scan QR and the phone app read.
func loginQRPNG(link string) ([]byte, error) {
	code, err := qr.Encode(link, qr.M)
	if err != nil {
		return nil, err
	}
	code.Scale = 8
	return code.PNG(), nil
}
