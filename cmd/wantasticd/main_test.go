package main

import (
	"flag"
	"testing"
)

func TestAutoUpdateFlagsDefaultOnAndExplicitOptOut(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "default enables auto update",
			args: nil,
			want: true,
		},
		{
			name: "legacy enable flag stays accepted",
			args: []string{"--auto-update"},
			want: true,
		},
		{
			name: "explicit false disables auto update",
			args: []string{"--auto-update=false"},
			want: false,
		},
		{
			name: "new opt out flag disables auto update",
			args: []string{"--no-auto-update"},
			want: false,
		},
		{
			name: "opt out wins over enable",
			args: []string{"--auto-update", "--no-auto-update"},
			want: false,
		},
		{
			name: "explicit false opt out keeps default enabled",
			args: []string{"--no-auto-update=false"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			flags := registerAutoUpdateFlags(fs, "Enable automatic self-updates (default on)", "Disable automatic self-updates")
			if err := fs.Parse(tt.args); err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			if got := flags.Enabled(); got != tt.want {
				t.Fatalf("Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}
