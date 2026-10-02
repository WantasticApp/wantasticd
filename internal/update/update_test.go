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
