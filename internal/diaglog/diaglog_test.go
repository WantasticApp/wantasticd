package diaglog

import "testing"

func TestEnabled(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "", want: false},
		{value: "0", want: false},
		{value: "false", want: false},
		{value: "1", want: true},
		{value: " TRUE ", want: true},
		{value: "yes", want: true},
		{value: "on", want: true},
	} {
		t.Run(test.value, func(t *testing.T) {
			t.Setenv(verboseEnv, test.value)
			if got := Enabled(); got != test.want {
				t.Fatalf("Enabled() = %t, want %t", got, test.want)
			}
		})
	}
}
