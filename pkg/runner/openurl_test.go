package runner

import "testing"

func TestOpenURLRefusesNonHTTPS(t *testing.T) {
	for _, bad := range []string{"", "http://wantastic.app/claim", "file:///etc/passwd", "javascript:alert(1)", "https://"} {
		if OpenURL(bad) == nil {
			t.Errorf("%q was opened", bad)
		}
	}
}
