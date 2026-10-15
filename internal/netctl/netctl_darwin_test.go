//go:build darwin

package netctl

import "testing"

func TestShellQuotePreventsArgumentInjection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "plain", value: "utun7", want: "'utun7'"},
		{name: "spaces", value: "name with spaces", want: "'name with spaces'"},
		{name: "single quote", value: "x'; touch /tmp/pwned; '", want: "'x'\\''; touch /tmp/pwned; '\\'''"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := shellQuote(test.value); got != test.want {
				t.Fatalf("shellQuote(%q)=%q want %q", test.value, got, test.want)
			}
		})
	}
}
