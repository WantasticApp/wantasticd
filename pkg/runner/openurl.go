package runner

import (
	"errors"
	"net/url"
)

// OpenURL opens an https link in the default browser.
func OpenURL(link string) error {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("not an https link")
	}
	return openBrowser(u.String())
}
