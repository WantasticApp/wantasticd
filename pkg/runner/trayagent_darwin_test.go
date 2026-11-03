//go:build darwin

package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrayAgentPlistIsValid(t *testing.T) {
	content := trayAgentPlistContent("/usr/local/bin/wantasticd & <co>")
	if !strings.Contains(content, "/usr/local/bin/wantasticd &amp; &lt;co&gt;") {
		t.Fatalf("binary path not escaped:\n%s", content)
	}
	path := filepath.Join(t.TempDir(), "tray.plist")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil rejected the plist: %v: %s", err, out)
	}
}

func TestDaemonPlistIsValid(t *testing.T) {
	content := DaemonPlistContent("/usr/local/bin/wantasticd", "/Library/Application Support/Wantastic/config.conf", "/Library/Logs/Wantastic/wantasticd.log")
	path := filepath.Join(t.TempDir(), "daemon.plist")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil rejected the plist: %v: %s", err, out)
	}
	out, err := exec.Command("plutil", "-extract", "ProgramArguments", "json", "-o", "-", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := `["\/usr\/local\/bin\/wantasticd","connect","--config","\/Library\/Application Support\/Wantastic\/config.conf","--tray=false"]`; strings.TrimSpace(string(out)) != want {
		t.Fatalf("ProgramArguments = %s, want %s", out, want)
	}
}
