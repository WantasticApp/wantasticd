//go:build !windows

// self-update.sh is the Unix updater; Windows updates in Go (install_windows.go).

package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelfUpdateRollsBackWhenRestartedServiceIsUnhealthy(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	packageDir := filepath.Join(root, "package")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}

	writeExecutable := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable(filepath.Join(packageDir, "wantasticd"), "#!/bin/sh\necho 'wantasticd version v9.9.9'\n")
	archive := filepath.Join(root, "release.tar.gz")
	tar := exec.Command("tar", "-czf", archive, "-C", packageDir, "wantasticd")
	if output, err := tar.CombinedOutput(); err != nil {
		t.Fatalf("create test archive: %v: %s", err, output)
	}

	statePath := filepath.Join(root, "service-restarted")
	writeExecutable(filepath.Join(binDir, "uname"), `#!/bin/sh
if [ "${1:-}" = "-s" ]; then echo Linux; else echo x86_64; fi
`)
	writeExecutable(filepath.Join(binDir, "curl"), `#!/bin/sh
dest=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then dest="$2"; shift 2; continue; fi
  shift
done
cp "$WANTASTIC_TEST_ARCHIVE" "$dest"
printf 200
`)
	writeExecutable(filepath.Join(binDir, "systemctl"), `#!/bin/sh
case "${1:-}" in
  is-active) [ ! -f "$WANTASTIC_TEST_SERVICE_STATE" ] ;;
  restart) : > "$WANTASTIC_TEST_SERVICE_STATE" ;;
  *) exit 0 ;;
esac
`)

	target := filepath.Join(root, "wantasticd")
	writeExecutable(target, "#!/bin/sh\necho 'wantasticd version v1.0.14'\n")
	script, err := updateScript.ReadFile("self-update.sh")
	if err != nil {
		t.Fatalf("read embedded updater: %v", err)
	}
	scriptPath := filepath.Join(root, "self-update.sh")
	writeExecutable(scriptPath, string(script))

	// A backup copy cut short by a full flash (T2, 2026-11-12) is removed.
	writeExecutable(target+".previous.tmp", "partial")

	command := exec.Command("/bin/sh", scriptPath, "v9.9.9", target)
	command.Env = append(os.Environ(),
		"PATH="+binDir+":"+os.Getenv("PATH"),
		"WANTASTIC_TEST_ARCHIVE="+archive,
		"WANTASTIC_TEST_SERVICE_STATE="+statePath,
		"WANTASTIC_UPDATE_VERIFY_TIMEOUT=1",
	)
	output, runErr := command.CombinedOutput()
	if runErr == nil {
		t.Fatalf("unhealthy update unexpectedly succeeded: %s", output)
	}
	if !strings.Contains(string(output), "restoring previous binary") {
		t.Fatalf("rollback was not reported: %s", output)
	}

	restored, err := exec.Command(target, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("run restored binary: %v: %s", err, restored)
	}
	if !strings.Contains(string(restored), "v1.0.14") {
		t.Fatalf("target was not rolled back: %s", restored)
	}
}

// Without room for the backup and the staged binary, the updater stops
// before writing anything, and says so.
func TestSelfUpdateRefusesWhenFlashIsFull(t *testing.T) {
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
	archive := filepath.Join(root, "release.tar.gz")
	if output, err := exec.Command("tar", "-czf", archive, "-C", packageDir, "wantasticd").CombinedOutput(); err != nil {
		t.Fatalf("create test archive: %v: %s", err, output)
	}
	writeExecutable(filepath.Join(binDir, "uname"), "#!/bin/sh\nif [ \"${1:-}\" = \"-s\" ]; then echo Linux; else echo x86_64; fi\n")
	writeExecutable(filepath.Join(binDir, "curl"), `#!/bin/sh
dest=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then dest="$2"; shift 2; continue; fi
  shift
done
cp "$WANTASTIC_TEST_ARCHIVE" "$dest"
printf 200
`)
	writeExecutable(filepath.Join(binDir, "df"), "#!/bin/sh\necho 'Filesystem 1024-blocks Used Available Capacity Mounted on'\necho '/dev/ubi0_3 61132 61132 0 100% /overlay'\n")
	writeExecutable(filepath.Join(binDir, "systemctl"), "#!/bin/sh\nexit 0\n")

	target := filepath.Join(root, "wantasticd")
	writeExecutable(target, "#!/bin/sh\necho 'wantasticd version v1.0.14'\n")
	script, err := updateScript.ReadFile("self-update.sh")
	if err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(root, "self-update.sh")
	writeExecutable(scriptPath, string(script))

	writeExecutable(target+".previous.tmp", "partial") // left by an earlier full-flash attempt

	command := exec.Command("/bin/sh", scriptPath, "v9.9.9", target)
	command.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "WANTASTIC_TEST_ARCHIVE="+archive)
	output, runErr := command.CombinedOutput()
	if runErr == nil || !strings.Contains(string(output), "not enough space") {
		t.Fatalf("full flash must stop the update: %v %s", runErr, output)
	}
	if current, _ := exec.Command(target, "version").CombinedOutput(); !strings.Contains(string(current), "v1.0.14") {
		t.Fatalf("target must be untouched: %s", current)
	}
	leftovers, _ := filepath.Glob(filepath.Join(root, ".wantasticd.*"))
	if _, err := os.Stat(target + ".previous.tmp"); err == nil || len(leftovers) > 0 {
		t.Fatalf("no partial files may be left: %v", leftovers)
	}
}
