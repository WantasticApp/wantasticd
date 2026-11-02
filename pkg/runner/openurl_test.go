//go:build (windows || darwin || (linux && cgo && (amd64 || arm64))) && !nosystray

package runner

import "testing"

func TestOpenURLRefusesNonHTTPS(t *testing.T) {
	for _, bad := range []string{"", "http://wantastic.app/claim", "file:///etc/passwd", "javascript:alert(1)", "https://"} {
		if openURL(bad) == nil {
			t.Errorf("%q was opened", bad)
		}
	}
}
