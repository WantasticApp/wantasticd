package endpoints_test

// Helper coverage of the OLT spec: every goform endpoint the spec
// (wusp.OLTPages) reads or writes is cross-referenced against the
// endpoints the helper serves. The test logs the coverage and the missing
// endpoints and fails when coverage drops below the floor reached by the
// ports in this package (raise the floor when more endpoints are ported;
// never lower it without saying why).

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"wantastic-agent/internal/oltd/endpoints"
	"wantastic-agent/internal/wusp"
)

// Coverage floor (endpoints served / settings without full helper
// support). The ceiling follows the spec: adding web-UI controls whose
// endpoints the helper does not serve raises it (PON.Port added
// getPonPortBasicList/setPonPortBasicInfo: 562 -> 598 settings).
const (
	coverageMinServed      = 133
	coverageMaxMissingSets = 228
)

func TestHelperCoverage(t *testing.T) {
	served := map[string]bool{} // "get:name" / "set:name"
	for _, e := range endpoints.Catalog() {
		served[e.Op+":"+e.Name] = true
	}
	name := func(p string) string { return strings.TrimPrefix(p, "/goform/") }
	// A goform getter is "get"; a setter path is "set" (vendor naming: set*/add*/del*/...).
	type use struct{ op, ep string }
	uses := map[use][]string{} // endpoint -> settings (leaves/commands) depending on it
	add := func(op, path, who string) {
		if path == "" {
			return
		}
		k := use{op, name(path)}
		uses[k] = append(uses[k], who)
	}
	pages, unsupported := 0, 0
	settings := 0
	for _, p := range wusp.OLTPages {
		pages++
		if p.Unsupported != "" {
			unsupported++
			continue
		}
		for _, f := range p.Forms {
			for _, fl := range f.Fields {
				settings++
				who := p.Route + " " + f.Object + "." + fl.Leaf
				add("get", f.Get.Path, who)
				if fl.Set != nil {
					add("set", fl.Set.Path, who)
				} else if f.Set != nil {
					add("set", f.Set.Path, who)
				}
			}
		}
		for _, tb := range p.Tables {
			for _, c := range tb.Columns {
				settings++
				who := p.Route + " " + tb.Object + "." + c.Leaf
				add("get", tb.Get.Path, who)
				if tb.Edit != nil {
					add("set", tb.Edit.Path, who)
				}
			}
			if tb.Add != nil {
				add("set", tb.Add.Path, p.Route+" "+tb.Object+" add")
			}
			if tb.Delete != nil {
				add("set", tb.Delete.Path, p.Route+" "+tb.Object+" delete")
			}
		}
		for _, a := range p.Actions {
			settings++
			add("set", a.Write.Path, p.Route+" "+a.Command)
			if a.Read != nil {
				add("get", a.Read.Path, p.Route+" "+a.Command+" (read)")
			}
		}
	}
	var missing []string
	missingSettings := map[string]bool{}
	allSettings := map[string]bool{}
	for k, ws := range uses {
		for _, w := range ws {
			allSettings[w] = true
		}
		if !served[k.op+":"+k.ep] {
			missing = append(missing, fmt.Sprintf("%s %-32s (%d settings)", k.op, k.ep, len(ws)))
			for _, w := range ws {
				missingSettings[w] = true
			}
		}
	}
	sort.Strings(missing)
	t.Logf("pages=%d unsupported_pages=%d", pages, unsupported)
	t.Logf("endpoints used=%d served_by_helper=%d missing=%d", len(uses), len(uses)-len(missing), len(missing))
	t.Logf("settings/commands=%d without full helper support=%d", len(allSettings), len(missingSettings))
	for _, m := range missing {
		t.Log("MISSING " + m)
	}
	if served := len(uses) - len(missing); served < coverageMinServed {
		t.Errorf("helper serves %d spec endpoints, floor is %d", served, coverageMinServed)
	}
	if len(missingSettings) > coverageMaxMissingSets {
		t.Errorf("%d settings lack full helper support, ceiling is %d", len(missingSettings), coverageMaxMissingSets)
	}
}
