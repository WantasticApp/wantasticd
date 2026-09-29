package update

import "testing"

func TestBuildUpdateURLUsesImmutableReleaseTag(t *testing.T) {
	got := BuildUpdateURL("v1.0.5+a065504", "linux-arm64")
	want := "https://get.wantastic.app/v1.0.5/wantasticd-linux-arm64.tar.gz"
	if got != want {
		t.Fatalf("BuildUpdateURL() = %q, want %q", got, want)
	}
}
