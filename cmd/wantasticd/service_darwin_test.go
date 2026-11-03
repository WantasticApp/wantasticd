//go:build darwin

package main

import "testing"

func TestParseLaunchdPrint(t *testing.T) {
	out := "system/com.wantastic.wantasticd = {\n" +
		"\tactive count = 1\n" +
		"\tstate = running\n" +
		"\targuments = {\n" +
		"\t\t/usr/local/bin/wantasticd\n" +
		"\t}\n" +
		"\tenvironment = {\n" +
		"\t\tpid = 1\n" +
		"\t}\n" +
		"\tpid = 33896\n" +
		"\tlast exit code = 0\n" +
		"}\n"
	got := parseLaunchdPrint(out)
	if got.pid != 33896 || got.state != "running" || got.lastExit != "0" {
		t.Fatalf("parseLaunchdPrint = %+v", got)
	}
	if got := parseLaunchdPrint("system/x = {\n\tstate = not running\n}\n"); got.pid != 0 || got.state != "not running" {
		t.Fatalf("stopped job = %+v", got)
	}
}
