package auth

import (
	"strings"
	"testing"
)

func TestWrapRunesKeepsWholeURL(t *testing.T) {
	url := "https://console.wantastic.app/activate?user_code=3LCT-LYQG"
	lines := wrapRunes(url, 52)
	if len(lines) != 2 || strings.Join(lines, "") != url {
		t.Fatalf("wrap = %q", lines)
	}
	for _, l := range lines {
		if len([]rune(l)) > 52 {
			t.Fatalf("line too long: %q", l)
		}
	}
	if got := wrapRunes("", 52); len(got) != 1 || got[0] != "" {
		t.Fatalf("empty = %q", got)
	}
}
