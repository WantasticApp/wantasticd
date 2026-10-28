//go:build !windows

package update

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestInstallOutlivesStoppedAgent reproduces a real update: the script
// restarts the service, which stops the agent that launched it. The script
// must carry on, verify the new build and clean up after itself.
func TestInstallOutlivesStoppedAgent(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	packageDir := filepath.Join(root, "package")
	for _, dir := range []string{binDir, packageDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	writeExecutable(filepath.Join(packageDir, "wantasticd"), "#!/bin/sh\necho 'wantasticd version v9.9.9'\n")
	archiveDir, err := os.MkdirTemp(root, "download-")
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(archiveDir, "pkg.tar.gz")
	if out, err := exec.Command("tar", "-czf", archive, "-C", packageDir, "wantasticd").CombinedOutput(); err != nil {
		t.Fatalf("create archive: %v: %s", err, out)
	}

	restarted := filepath.Join(root, "restarted")
	writeExecutable(filepath.Join(binDir, "uname"), "#!/bin/sh\nif [ \"${1:-}\" = \"-s\" ]; then echo Linux; else echo x86_64; fi\n")
	// restart marks the service restarted after a delay, so the agent is
	// "stopped" while the script is still verifying.
	writeExecutable(filepath.Join(binDir, "systemctl"), `#!/bin/sh
case "${1:-}" in
  # Running before the restart, down while it happens, up afterwards.
  is-active) [ ! -f "$WANTASTIC_TEST_RESTARTED.begin" ] || [ -f "$WANTASTIC_TEST_RESTARTED" ] ;;
  restart) : > "$WANTASTIC_TEST_RESTARTED.begin"; sleep 1; : > "$WANTASTIC_TEST_RESTARTED" ;;
  *) exit 0 ;;
esac
`)
	target := filepath.Join(root, "wantasticd")
	writeExecutable(target, "#!/bin/sh\necho 'wantasticd version v1.0.0'\n")

	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Setenv("WANTASTIC_TEST_RESTARTED", restarted)
	t.Setenv("WANTASTIC_UPDATE_VERIFY_TIMEOUT", "10")

	// The agent's context ends as soon as the service restart begins.
	parent, stop := context.WithCancel(context.Background())
	go func() {
		for parent.Err() == nil {
			if _, err := os.Stat(restarted + ".begin"); err == nil {
				stop()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	attempt, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()

	m := NewManager("v1.0.0")
	err = m.install(parent, attempt, "v9.9.9", target, archiveDir, archive)
	if err != context.Canceled {
		t.Fatalf("install() = %v, want context.Canceled once the agent stops", err)
	}

	// The detached script finishes on its own.
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, _ := exec.Command(target, "version").CombinedOutput()
		_, workErr := os.Stat(archiveDir)
		if strings.Contains(string(out), "v9.9.9") && os.IsNotExist(workErr) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("detached update did not finish: version=%q workdir err=%v", out, workErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	prev, err := exec.Command(target+".previous", "version").CombinedOutput()
	if err != nil || !strings.Contains(string(prev), "v1.0.0") {
		t.Fatalf("previous build not kept for rollback: %v %q", err, prev)
	}
}

func TestInstallReportsScriptFailure(t *testing.T) {
	root := t.TempDir()
	archiveDir, err := os.MkdirTemp(root, "download-")
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(archiveDir, "pkg.tar.gz")
	if err := os.WriteFile(archive, []byte("not a tarball"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "wantasticd")
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho 'wantasticd version v1.0.0'\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	m := NewManager("v1.0.0")
	m.Output = &out
	ctx := context.Background()
	err = m.install(ctx, ctx, "v9.9.9", target, archiveDir, archive)
	if err == nil || !strings.Contains(err.Error(), "log kept at") {
		t.Fatalf("install() = %v, want a script failure naming its log", err)
	}
	if out.Len() == 0 {
		t.Fatal("script output was not reported to Output")
	}
	if got, _ := exec.Command(target, "version").CombinedOutput(); !strings.Contains(string(got), "v1.0.0") {
		t.Fatalf("failed update touched the installed binary: %q", got)
	}
}
