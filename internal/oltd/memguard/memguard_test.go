package memguard

import (
	"strings"
	"testing"
)

func TestNeedsReexec(t *testing.T) {
	for _, c := range []struct {
		env  []string
		want bool
	}{
		{nil, true},
		{[]string{"GOGC=100"}, true},
		{[]string{"GOGC=off"}, false},
		{[]string{"GOGC=off", "GOMEMLIMIT=64MiB"}, true},
		{[]string{"GOGC=off", "GOMEMLIMIT=off"}, false},
		{[]string{"PATH=/bin", "GOGC=off"}, false},
	} {
		if got := NeedsReexec(c.env); got != c.want {
			t.Errorf("%v: %v want %v", c.env, got, c.want)
		}
	}
}

func TestFixEnv(t *testing.T) {
	got := FixEnv([]string{"PATH=/bin", "GOGC=50", "GOMEMLIMIT=1GiB", EnvListenFD + "=3"}, EnvListenFD+"=7", EnvRestarts+"=2")
	s := strings.Join(got, " ")
	if s != "PATH=/bin GOGC=off "+EnvListenFD+"=7 "+EnvRestarts+"=2" {
		t.Fatalf("%s", s)
	}
	if NeedsReexec(got) {
		t.Fatal("fixed env still needs re-exec")
	}
}
