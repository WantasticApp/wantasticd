package qcaspectral

import (
	"os/exec"
	"testing"
)

// TestPackedLayoutOffsets compiles testdata/layout.c, whose _Static_asserts
// pin every packed offset parse.go reads, for little- and big-endian ABIs.
func TestPackedLayoutOffsets(t *testing.T) {
	compiler := ""
	for _, candidate := range []string{"clang", "cc", "gcc"} {
		if path, err := exec.LookPath(candidate); err == nil {
			compiler = path
			break
		}
	}
	if compiler == "" {
		t.Skip("no C compiler available")
	}
	out, err := exec.Command(compiler, "-fsyntax-only", "-std=c11", "testdata/layout.c").CombinedOutput()
	if err != nil {
		t.Fatalf("packed layout assertions failed: %v\n%s", err, out)
	}
}
