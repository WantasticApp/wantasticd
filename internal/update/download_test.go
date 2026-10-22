package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadReleaseUsesImmutableTagPath(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte("archive-bytes"))
	}))
	defer server.Close()

	m := NewManager("v1.0.0")
	m.baseURL = server.URL
	dest := filepath.Join(t.TempDir(), "pkg.tar.gz")
	if err := m.downloadRelease(context.Background(), "v1.2.3+abc", dest); err != nil {
		t.Fatal(err)
	}
	if want := "/v1.2.3/wantasticd-" + GetPlatform() + ".tar.gz"; gotPath != want {
		t.Fatalf("downloaded %q, want %q", gotPath, want)
	}
	if data, _ := os.ReadFile(dest); string(data) != "archive-bytes" {
		t.Fatalf("archive content = %q", data)
	}
}

// Stock OpenWrt has no curl: the agent passes its own download to the script,
// which must install it without calling any downloader.
func TestSelfUpdateInstallsPassedArchiveWithoutCurl(t *testing.T) {
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
	for _, fetcher := range []string{"curl", "wget", "uclient-fetch"} {
		writeExecutable(filepath.Join(binDir, fetcher), "#!/bin/sh\necho downloader-called >&2\nexit 1\n")
	}
	writeExecutable(filepath.Join(binDir, "systemctl"), "#!/bin/sh\nexit 0\n")

	target := filepath.Join(root, "wantasticd")
	writeExecutable(target, "#!/bin/sh\necho 'wantasticd version v1.0.14'\n")
	script, err := updateScript.ReadFile("self-update.sh")
	if err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(root, "self-update.sh")
	writeExecutable(scriptPath, string(script))

	command := exec.Command("/bin/sh", scriptPath, "v9.9.9", target, archive)
	command.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "WANTASTIC_UPDATE_VERIFY_TIMEOUT=2")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("update failed: %v: %s", err, output)
	}
	if strings.Contains(string(output), "downloader-called") {
		t.Fatalf("script downloaded despite a passed archive: %s", output)
	}
	installed, _ := exec.Command(target, "version").CombinedOutput()
	if !strings.Contains(string(installed), "v9.9.9") {
		t.Fatalf("target not updated: %s", installed)
	}
}
