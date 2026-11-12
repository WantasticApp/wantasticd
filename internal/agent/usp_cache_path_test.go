package agent

import (
	"runtime"
	"testing"
)

// The cache must not live on a router's flash overlay (it filled /etc on a
// T2 until uci commit failed with "I/O error"): on Linux an /etc path moves
// to RAM and the flash copy and stale temporary files are removed.
func TestDataModelCacheLeavesRouterFlash(t *testing.T) {
	if got := dataModelCachePath("/Users/x/Library/wantastic/wusp-datamodel.v2.cache", "/tmp/wantastic"); got != "/Users/x/Library/wantastic/wusp-datamodel.v2.cache" {
		t.Fatalf("non-router path must stay: %s", got)
	}
	if runtime.GOOS != "linux" {
		if got := dataModelCachePath("/etc/wantastic/wusp-datamodel.v2.cache", "/tmp/wantastic"); got != "/etc/wantastic/wusp-datamodel.v2.cache" {
			t.Fatalf("only Linux routers move the cache: %s", got)
		}
		return
	}
	if got := dataModelCachePath("/etc/wantastic/wusp-datamodel.v2.cache", "/tmp/wantastic"); got != "/tmp/wantastic/wusp-datamodel.v2.cache" {
		t.Fatalf("router cache must move to RAM: %s", got)
	}
	// Legacy layout (G1TK7EY001177): /etc/wantastic is a file, so persistent
	// files sit beside it as /etc/wantastic-<name>.
	if got := dataModelCachePath("/etc/wantastic-wusp-datamodel.v2.cache", "/tmp/wantastic"); got != "/tmp/wantastic/wantastic-wusp-datamodel.v2.cache" {
		t.Fatalf("legacy flat-file layout must move to RAM too: %s", got)
	}
}
