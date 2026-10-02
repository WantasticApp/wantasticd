package update

import (
	"strings"
	"testing"
)

func TestBuildUpdateURLUsesImmutableReleaseTag(t *testing.T) {
	got := BuildUpdateURL("v1.0.5+a065504", "linux-arm64")
	want := "https://get.wantastic.app/v1.0.5/wantasticd-linux-arm64.tar.gz"
	if got != want {
		t.Fatalf("BuildUpdateURL() = %q, want %q", got, want)
	}
}

func TestManagerShouldUpdateOnlyToNewerRelease(t *testing.T) {
	tests := []struct {
		name    string
		current string
		target  string
		want    bool
		wantErr bool
	}{
		{name: "new patch", current: "v1.0.14+abff3d0", target: "v1.0.15", want: true},
		{name: "same tag ignores build", current: "v1.0.15+ec3f15a", target: "v1.0.15", want: false},
		{name: "stale channel cannot downgrade", current: "v1.0.15+ec3f15a", target: "v1.0.14", want: false},
		{name: "new major", current: "v1.9.9", target: "v2.0.0", want: true},
		{name: "release supersedes prerelease", current: "v1.0.15-rc1", target: "v1.0.15", want: true},
		{name: "prerelease cannot replace release", current: "v1.0.15", target: "v1.0.15-rc1", want: false},
		{name: "numeric prerelease order", current: "v1.0.15-beta.2", target: "v1.0.15-beta.10", want: true},
		{name: "invalid target rejected", current: "v1.0.15", target: "latest", wantErr: true},
		{name: "invalid current rejected", current: "dev", target: "v1.0.15", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NewManager(test.current).ShouldUpdate(test.target)
			if (err != nil) != test.wantErr {
				t.Fatalf("ShouldUpdate() error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("ShouldUpdate() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSelfUpdateVerifiesAndRollsBackFailedService(t *testing.T) {
	script, err := updateScript.ReadFile("self-update.sh")
	if err != nil {
		t.Fatalf("read self-update script: %v", err)
	}
	text := string(script)
	for _, required := range []string{
		"NEW_VERSION_OUTPUT=",
		"service_is_running",
		`ubus call service list`,
		`"running"[[:space:]]*:[[:space:]]*true`,
		"verify_update",
		"wantasticd.previous",
		"wantasticd.rollback",
		"restoring previous binary",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("self-update script missing %q", required)
		}
	}
}
