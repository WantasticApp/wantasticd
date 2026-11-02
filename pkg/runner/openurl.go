//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import (
	"errors"
	"net/url"
)

// openURL opens an https link in the default browser.
func openURL(link string) error {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("not an https link")
	}
	return openBrowser(u.String())
}
