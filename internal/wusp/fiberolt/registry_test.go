package fiberolt

import (
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// Declared parameters the engine fills outside the binding tables.
var prologueParams = map[string]bool{
	"Installed": true, "Platform": true, "SupportedOperations": true, "ControlSchemaVersion": true,
	"Enable": true, "Status": true, "StatusDetail": true, "LastCollectTime": true,
	"AlarmNumberOfEntries": true, "PONPortNumberOfEntries": true, "ONUNumberOfEntries": true,
	// Web budget metadata (emitPageCache).
	"PageCacheNumberOfEntries": true, "PageCache.{i}.Name": true, "PageCache.{i}.Endpoint": true,
	"PageCache.{i}.Source": true, "PageCache.{i}.LastRefreshed": true, "PageCache.{i}.Objects": true,
	"WebBudget.Interval": true, "WebBudget.BackoffUntil": true, "WebBudget.PendingPages": true,
}

// Declared parameters nothing collects yet (pre-existing schema entries
// without a known vendor source). Shrink this list; never grow it silently.
var knownUncollected = map[string]bool{
	"ONU.{i}.Distance": true,
	"Alarms.{i}.Time":  true, "Alarms.{i}.Severity": true, "Alarms.{i}.Message": true,
	// The last operation fields are declared for console use; nothing fills
	// them on the OLT backend yet.
	"LastOperationStatus": true, "LastOperationCode": true, "LastOperationMessage": true,
}

// Declared readWrite parameters with no setter yet (schema kept for
// compatibility; the control schema reports them settable=false).
var knownUnboundRW = map[string]bool{}

// Declared multi-instance objects without a binding yet.
var knownUnboundTables = map[string]bool{"Alarms": true, "PageCache": true}

type boundLeaf struct {
	get, set bool
}

// boundLeaves maps every relative canonical path the registry binds.
func boundLeaves() map[string]boundLeaf {
	out := map[string]boundLeaf{}
	for _, b := range Bindings {
		out[b.Leaf] = boundLeaf{get: b.Get != nil, set: b.Set != nil}
	}
	for _, t := range Tables {
		for _, c := range t.Columns {
			out[t.Object+".{i}."+c.Leaf] = boundLeaf{get: c.Get != nil, set: c.Set != nil}
		}
		if t.Count != "" {
			out[t.Count] = boundLeaf{get: true}
		}
	}
	return out
}

// TestRegistryConsistency keeps the declarations (internal/wusp/olt.go)
// and the bindings (this package) in lockstep: that is what makes "one
// table entry per control" hold.
func TestRegistryConsistency(t *testing.T) {
	buildIndex()
	bound := boundLeaves()
	declared := map[string]wusp.OLTParamDef{}
	results := map[string]bool{}
	for _, c := range wusp.WUSPOLTCommands {
		for _, o := range c.Outputs {
			results[strings.TrimPrefix(o.Path, wusp.WUSPOLTPrefix)] = true
		}
	}

	for _, d := range wusp.WUSPOLTAllParamDefs {
		rel := strings.TrimPrefix(d.Path, wusp.WUSPOLTPrefix)
		if _, dup := declared[rel]; dup {
			t.Errorf("%s declared twice", rel)
		}
		declared[rel] = d
		b := bound[rel]
		switch {
		case prologueParams[rel] || results[rel]:
		case knownUncollected[rel]:
			if b.get {
				t.Errorf("%s is collected now: drop it from knownUncollected", rel)
			}
		case !b.get:
			t.Errorf("%s is declared but nothing collects it (bind a getter)", rel)
		}
		if d.Access != wusp.ReadOnly {
			if knownUnboundRW[rel] {
				if b.set {
					t.Errorf("%s has a setter now: drop it from knownUnboundRW", rel)
				}
			} else if !b.set {
				t.Errorf("%s is readWrite but has no setter", rel)
			}
		}
		if d.Effect == "" {
			t.Errorf("%s has no effect class", rel)
		}
		if d.Effect == wusp.OLTEffectDestructive && d.Access != wusp.ReadOnly {
			t.Errorf("%s is destructive: expose it as an Operate command, never a writable parameter", rel)
		}
		if d.Access == wusp.ReadOnly && d.Effect != wusp.OLTEffectNone {
			t.Errorf("%s is read-only but has effect %s", rel, d.Effect)
		}
	}
	for rel, b := range bound {
		d, ok := declared[rel]
		if !ok {
			t.Errorf("%s is bound but not declared in wusp.WUSPOLTAllParamDefs", rel)
			continue
		}
		if b.set && d.Access == wusp.ReadOnly {
			t.Errorf("%s has a setter but is declared readOnly", rel)
		}
	}

	// Sources referenced by getters and tables exist.
	for _, b := range Bindings {
		if b.Get != nil && b.Get.Source != "" && sourceByName[b.Get.Source] == nil {
			t.Errorf("%s: unknown source %q", b.Leaf, b.Get.Source)
		}
	}
	if sourceByName[GateSource] == nil {
		t.Errorf("gate source %q missing", GateSource)
	}

	// Tables <-> multi-instance objects <-> table defs.
	objects := map[string]bool{}
	for _, o := range wusp.WUSPOLTObjects {
		if o.MultiInstance {
			objects[strings.TrimSuffix(strings.TrimPrefix(o.Path, wusp.WUSPOLTPrefix), ".{i}.")] = true
		}
	}
	defs := map[string]wusp.OLTTableDef{}
	for _, td := range wusp.WUSPOLTTableDefs {
		rel := strings.TrimSuffix(strings.TrimPrefix(td.Path, wusp.WUSPOLTPrefix), ".{i}.")
		defs[rel] = td
		if !objects[rel] {
			t.Errorf("table def %s has no multi-instance object", rel)
		}
	}
	for obj := range objects {
		td, ok := defs[obj]
		if !ok {
			t.Errorf("object %s has no OLTTableDef", obj)
			continue
		}
		tb := tableByObj[obj]
		if tb == nil {
			if !knownUnboundTables[obj] {
				t.Errorf("object %s has no Table binding", obj)
			}
			continue
		}
		if td.CountParam != wusp.WUSPOLTPrefix+tb.Count {
			t.Errorf("%s: count param def %q vs binding %q", obj, td.CountParam, tb.Count)
		}
		if td.Addable != (tb.Add != nil) {
			t.Errorf("%s: Addable=%v but Add bound=%v", obj, td.Addable, tb.Add != nil)
		}
		if td.Deletable != (tb.Delete != nil) {
			t.Errorf("%s: Deletable=%v but Delete bound=%v", obj, td.Deletable, tb.Delete != nil)
		}
		for _, cmd := range []string{td.AddCommand, td.DeleteCommand} {
			if cmd != "" && opByCommand[cmd] == nil {
				t.Errorf("%s: command %s is not bound", obj, cmd)
			}
		}
		if (tb.Add != nil || tb.Delete != nil || hasColumnSetter(tb)) && !tb.Positional && tb.Key == nil && len(tb.KeyFields) == 0 {
			t.Errorf("%s: writable table needs a stable key", obj)
		}
	}
	for _, tb := range Tables {
		if !objects[tb.Object] {
			t.Errorf("Table %s is not a declared multi-instance object", tb.Object)
		}
	}

	// Commands: declared <-> bound.
	declaredCmds := map[string]bool{}
	for _, c := range wusp.WUSPOLTCommands {
		declaredCmds[c.Path] = true
		if opByCommand[c.Path] == nil {
			t.Errorf("command %s is declared but not bound", c.Path)
		}
		if c.Effect == "" {
			t.Errorf("command %s has no effect class", c.Path)
		}
		if !strings.HasPrefix(c.Path, wusp.WUSPOLTPrefix) || !strings.HasSuffix(c.Path, "()") {
			t.Errorf("command %s must be Device.WUSP_OLT.<...>()", c.Path)
		}
		for _, o := range c.Outputs {
			if _, ok := declared[strings.TrimPrefix(o.Path, wusp.WUSPOLTPrefix)]; !ok {
				t.Errorf("command %s output %s is not a declared parameter", c.Path, o.Path)
			}
		}
	}
	for _, op := range Operations {
		if !declaredCmds[op.Command] {
			t.Errorf("command %s is bound but not declared", op.Command)
		}
	}
}

func hasColumnSetter(t *Table) bool {
	for _, c := range t.Columns {
		if c.Set != nil {
			return true
		}
	}
	return false
}
