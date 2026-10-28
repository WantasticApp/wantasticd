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
