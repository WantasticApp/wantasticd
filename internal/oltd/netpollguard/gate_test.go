package netpollguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The shipping build must never start the Go network poller (fatal on the
// OLT's epoll-less kernel). These are the design's two static gates.

// Packages whose use starts the poller (net, os/exec via os.Pipe) or that
// may fall back to os.Open on old kernels (crypto/rand) or run a signal
// pump we have not proven safe (os/signal).
var forbiddenDeps = []string{"net", "net/http", "os/exec", "os/signal", "crypto/rand", "context"}

func TestDependencyGate(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not in PATH")
	}
	for _, target := range [][]string{
		{"GOOS=linux", "GOARCH=arm", "GOARM=5", "CGO_ENABLED=1"},
		{"GOOS=linux", "GOARCH=arm", "GOARM=5", "CGO_ENABLED=0"},
	} {
		cmd := exec.Command("go", "list", "-deps", "wantastic-agent/cmd/wantastic-oltd")
		cmd.Env = append(os.Environ(), target...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go list %v: %v\n%s", target, err, out)
		}
		deps := map[string]bool{}
		for _, l := range strings.Fields(string(out)) {
			deps[l] = true
		}
		for _, bad := range forbiddenDeps {
			if deps[bad] {
				t.Errorf("%v: wantastic-oltd depends on %q", target, bad)
			}
		}
		if !deps["wantastic-agent/internal/oltd/server"] {
			t.Errorf("%v: dependency list looks wrong:\n%s", target, out)
		}
	}
}

// Calls that start the poller (files, pipes, exec, Go timers, context
// deadlines) or write through *os.File; checked in every non-test Go file
// of the helper tree.
var forbiddenCalls = regexp.MustCompile(`\b(time\.(Sleep|After|AfterFunc|NewTimer|NewTicker|Tick)\(|context\.(WithTimeout|WithDeadline)|os\.(Open|OpenFile|NewFile|Pipe|Create|ReadFile|WriteFile|ReadDir|Stdout|Stderr|Stdin)\b|exec\.Command|fmt\.Print|log\.|go:linkname)`)

// Anything that would run or re-enable the garbage collector: a completed
// GC cycle lets the background scavenger arm a runtime timer, which starts
// the netpoller (fatal without epoll). Only memguard may touch GC settings.
var forbiddenGC = regexp.MustCompile(`\b(runtime\.GC\(|debug\.(FreeOSMemory|SetGCPercent|SetMemoryLimit)\()`)

var forbiddenImport = regexp.MustCompile(`"(net|net/http|os/exec|os/signal|crypto/rand|context|log)"`)

func TestGrepGate(t *testing.T) {
	roots := []string{"..", filepath.Join("..", "..", "..", "cmd", "wantastic-oltd")}
	checked := 0
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(raw), "\n") {
				code := line
				if j := strings.Index(code, "//"); j >= 0 && !strings.Contains(code[:j], "\"") {
					code = code[:j]
				}
				if m := forbiddenGC.FindString(code); m != "" && !strings.Contains(filepath.ToSlash(path), "/memguard/") {
					t.Errorf("%s:%d: forbidden GC control %q: %s", path, i+1, m, strings.TrimSpace(line))
				}
				if m := forbiddenCalls.FindString(code); m != "" {
					t.Errorf("%s:%d: forbidden %q: %s", path, i+1, m, strings.TrimSpace(line))
				}
				if m := forbiddenImport.FindString(code); m != "" && strings.HasPrefix(strings.TrimSpace(code), "\"") {
					t.Errorf("%s:%d: forbidden import %s", path, i+1, m)
				}
			}
			checked++
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d files checked; wrong roots?", checked)
	}
}

func TestProbe(t *testing.T) {
	ok, detail := Probe()
	if detail == "" {
		t.Fatal("empty detail")
	}
	aborted := ""
	Require("test", func(m string) { aborted = m })
	if ok && aborted != "" {
		t.Fatal("Require aborted although epoll is available")
	}
	probed.Store(2)
	defer probed.Store(0)
	Require("test", func(m string) { aborted = m })
	if !strings.Contains(aborted, "no epoll") {
		t.Fatalf("Require did not abort on a no-epoll kernel: %q", aborted)
	}
}

// main must enforce GOGC=off before doing anything else.
func TestMainEnsuresGCOffFirst(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "cmd", "wantastic-oltd", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	i := strings.Index(src, "func main() {")
	if i < 0 {
		t.Fatal("no main")
	}
	var first string
	for _, l := range strings.Split(src[i+len("func main() {"):], "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "//") {
			continue
		}
		first = l
		break
	}
	if !strings.HasPrefix(first, "if err := memguard.Ensure(); err != nil {") {
		t.Fatalf("first statement of main is %q, want memguard.Ensure()", first)
	}
}
