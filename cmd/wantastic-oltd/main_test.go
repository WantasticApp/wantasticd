//go:build linux || darwin

package main

import "testing"

func TestSelftestPlan(t *testing.T) {
	calls, err := selftestPlan("")
	if err != nil || len(calls) != 4 {
		t.Fatalf("default: %v %v", calls, err)
	}
	calls, err = selftestPlan(" getSysStatus, /goform/getOntListBrife ,getOntDetail?ontid=0/1/1&urltype=1")
	if err != nil || len(calls) != 3 {
		t.Fatalf("%v %v", calls, err)
	}
	if calls[1].args.Str("PonPortName") != "all" || calls[2].args.Str("ontid") != "0/1/1" || calls[2].args.Str("urltype") != "1" {
		t.Fatalf("args %+v", calls)
	}
	for _, bad := range []string{"setOntListConfig", "getSysStatus,delOntList", "setOntListReboot", "getOntAction", "getUserList", "sysReboot", "getNoSuchThing"} {
		if _, err := selftestPlan(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
