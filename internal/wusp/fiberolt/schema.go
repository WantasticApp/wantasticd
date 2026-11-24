package fiberolt

// Control schema export: the metadata the console needs to render every
// Device.WUSP_OLT control generically (type, access, enum/range, units,
// grouping, side-effect class, table and command shapes). Built from the
// declarations in internal/wusp/olt.go plus what is actually bound here,
// so "settable"/"addable" reflect real agent support.

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"strings"
	"sync"

	"wantastic-agent/internal/wusp"
)

// ControlSchemaFormat identifies the schema layout; bump on breaking change.
const ControlSchemaFormat = "wusp-olt-controls/1"

// ControlSchema is the document DescribeControls() returns.
type ControlSchema struct {
	Format     string          `json:"format"`
	Version    string          `json:"version"`
	Root       string          `json:"root"`
	Params     []SchemaParam   `json:"params"`
	Tables     []SchemaTable   `json:"tables"`
	Operations []SchemaCommand `json:"operations"`
	// Unsupported lists web-UI pages deliberately not exposed, with why.
	Unsupported []SchemaUnsupported `json:"unsupported,omitempty"`
}

// SchemaUnsupported is one web-UI page the agent does not expose.
type SchemaUnsupported struct {
	Route  string `json:"route"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// SchemaParam describes one parameter.
type SchemaParam struct {
	Path string `json:"path"`
	// Table is the multi-instance object the param belongs to ("" for scalars).
	Table string `json:"table,omitempty"`
	Name  string `json:"name"`
	Label string `json:"label"`
	Type  string `json:"type"`
	// Access is the schema access (readOnly/readWrite).
	Access string `json:"access"`
	// Settable is true when the agent actually implements the write;
	// readWrite params without a setter yet report false.
	Settable bool   `json:"settable"`
	Effect   string `json:"effect"`
	Group    string `json:"group"`
	Section  string `json:"section,omitempty"`
	Page     string `json:"page,omitempty"`
	Units    string `json:"units,omitempty"`
	Help     string `json:"help,omitempty"`
	SchemaLimits
}

// SchemaLimits mirrors wusp.Limits with console-friendly names.
type SchemaLimits struct {
	Enum       []string `json:"enum,omitempty"`
	EnumLabels []string `json:"enumLabels,omitempty"`
	Min        *int64   `json:"min,omitempty"`
	Max        *int64   `json:"max,omitempty"`
	MinF       *float64 `json:"minF,omitempty"`
	MaxF       *float64 `json:"maxF,omitempty"`
	MinLength  int      `json:"minLength,omitempty"`
	MaxLength  int      `json:"maxLength,omitempty"`
	Pattern    string   `json:"pattern,omitempty"`
}

// SchemaTable describes one multi-instance object.
type SchemaTable struct {
	Path       string `json:"path"`
	Label      string `json:"label"`
	Group      string `json:"group"`
	Section    string `json:"section,omitempty"`
	Page       string `json:"page,omitempty"`
	Help       string `json:"help,omitempty"`
	Key        string `json:"key,omitempty"`
	CountParam string `json:"countParam,omitempty"`
	// Addable/Deletable: USP Add/Delete on the table are implemented.
	Addable   bool        `json:"addable"`
	Deletable bool        `json:"deletable"`
	AddArgs   []SchemaArg `json:"addArgs,omitempty"`
	// AddCommand/DeleteCommand: the Operate commands that create/remove
	// rows of tables managed through commands.
	AddCommand    string `json:"addCommand,omitempty"`
	DeleteCommand string `json:"deleteCommand,omitempty"`
}

// SchemaCommand describes one Operate command.
type SchemaCommand struct {
	Path    string `json:"path"`
	Label   string `json:"label"`
	Effect  string `json:"effect"`
	Confirm bool   `json:"confirm"`
	Group   string `json:"group"`
	Section string `json:"section,omitempty"`
	Page    string `json:"page,omitempty"`
	Help    string `json:"help,omitempty"`
	// Supported is false for declared commands the agent does not run yet.
	Supported bool        `json:"supported"`
	Inputs    []SchemaArg `json:"inputs,omitempty"`
	Outputs   []SchemaArg `json:"outputs,omitempty"`
}

// SchemaArg is one command argument (or Add initial field).
type SchemaArg struct {
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	Type     string `json:"type"`
	Required bool   `json:"required,omitempty"`
	Help     string `json:"help,omitempty"`
	SchemaLimits
}

var (
	schemaOnce sync.Once
	schemaJSON []byte
	schemaVer  string
	schemaErr  error
)

// ControlSchemaJSON returns the serialized control schema.
func ControlSchemaJSON() ([]byte, error) {
	schemaOnce.Do(func() {
		s := BuildControlSchema()
		s.Version = ""
		raw, err := json.Marshal(s)
		if err != nil {
			schemaErr = err
			log.Printf("[OLT] control schema: %v", err)
			return
		}
		h := fnv.New64a()
		_, _ = h.Write(raw)
		schemaVer = fmt.Sprintf("%016x", h.Sum64())
		s.Version = schemaVer
		schemaJSON, schemaErr = json.Marshal(s)
	})
	return schemaJSON, schemaErr
}

// ControlSchemaVersion is the content hash of the control schema.
func ControlSchemaVersion() string {
	_, _ = ControlSchemaJSON()
	return schemaVer
}

func limitsOf(l wusp.Limits) SchemaLimits {
	return SchemaLimits{Enum: l.Enums, Min: l.Min, Max: l.Max, MinF: l.MinF, MaxF: l.MaxF, MinLength: l.MinLength, MaxLength: l.MaxLength, Pattern: l.Pattern}
}

func argsOf(defs []wusp.OLTArgDef) []SchemaArg {
	out := make([]SchemaArg, 0, len(defs))
	for _, a := range defs {
		out = append(out, SchemaArg{Name: a.Name, Path: a.Path, Type: string(a.Type), Required: a.Required, Help: a.Description, SchemaLimits: limitsOf(a.Limits)})
	}
	return out
}

// defaultPlacement derives Group/Section from a relative path when the
// declaration leaves them empty: first segment / second segment, "System"
// for root leaves.
func defaultPlacement(rel string) (group, section string) {
	parts := strings.Split(strings.TrimSuffix(rel, "."), ".")
	if len(parts) <= 1 {
		return "System", ""
	}
	group = parts[0]
	if len(parts) > 2 && parts[1] != "{i}" {
		section = parts[1]
	}
	return group, section
}

func lastSegment(path string) string {
	path = strings.TrimSuffix(strings.TrimSuffix(path, "."), ".{i}")
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}

// tableForParam returns the table def whose object prefixes the param.
func tableForParam(path string) *wusp.OLTTableDef {
	var best *wusp.OLTTableDef
	for i := range wusp.WUSPOLTTableDefs {
		t := &wusp.WUSPOLTTableDefs[i]
		if strings.HasPrefix(path, t.Path) && (best == nil || len(t.Path) > len(best.Path)) {
			best = t
		}
	}
	return best
}

// settable reports whether the agent implements a write for the path.
func settable(path string) bool {
	rel := strings.TrimPrefix(path, wusp.WUSPOLTPrefix)
	if b, ok := bindingByLf[rel]; ok {
		return b.Set != nil
	}
	for obj, t := range tableByObj {
		leafPrefix := obj + ".{i}."
		if strings.HasPrefix(rel, leafPrefix) {
			leaf := strings.TrimPrefix(rel, leafPrefix)
			for _, col := range t.Columns {
				if col.Leaf == leaf {
					return col.Set != nil
				}
			}
		}
	}
	return false
}

// BuildControlSchema assembles the schema from declarations + bindings.
func BuildControlSchema() ControlSchema {
	buildIndex()
	s := ControlSchema{Format: ControlSchemaFormat, Root: wusp.WUSPOLTPrefix}
	for _, d := range wusp.WUSPOLTAllParamDefs {
		rel := strings.TrimPrefix(d.Path, wusp.WUSPOLTPrefix)
		p := SchemaParam{
			Path: d.Path, Name: lastSegment(d.Path), Label: d.UI.Label, Type: string(d.Type), Access: string(d.Access),
			Settable: d.Access != wusp.ReadOnly && settable(d.Path), Effect: string(d.Effect),
			Group: d.UI.Group, Section: d.UI.Section, Page: d.UI.Page, Units: d.UI.Units,
			Help: d.Description, SchemaLimits: limitsOf(d.Limits),
		}
		if d.UI.Help != "" {
			p.Help = d.UI.Help
		}
		p.EnumLabels = d.UI.EnumLabels
		if t := tableForParam(d.Path); t != nil {
			p.Table = t.Path
			if p.Group == "" {
				p.Group, p.Section = t.UI.Group, t.UI.Section
			}
		}
		if p.Group == "" {
			p.Group, p.Section = defaultPlacement(rel)
		}
		if p.Label == "" {
			p.Label = p.Name
		}
		s.Params = append(s.Params, p)
	}
	for _, t := range wusp.WUSPOLTTableDefs {
		rel := strings.TrimSuffix(strings.TrimPrefix(t.Path, wusp.WUSPOLTPrefix), ".{i}.")
		bound := tableByObj[rel]
		st := SchemaTable{
			Path: t.Path, Label: t.UI.Label, Group: t.UI.Group, Section: t.UI.Section, Page: t.UI.Page, Help: t.UI.Help,
			Key: t.Key, CountParam: t.CountParam,
			Addable: t.Addable && bound != nil && bound.Add != nil, Deletable: t.Deletable && bound != nil && bound.Delete != nil,
			AddArgs: argsOf(t.AddArgs), AddCommand: t.AddCommand, DeleteCommand: t.DeleteCommand,
		}
		if st.Help == "" {
			for _, o := range wusp.WUSPOLTObjects {
				if o.Path == t.Path {
					st.Help = o.Description
				}
			}
		}
		if st.Group == "" {
			st.Group, st.Section = defaultPlacement(rel + ".{i}")
		}
		if st.Label == "" {
			st.Label = lastSegment(t.Path)
		}
		s.Tables = append(s.Tables, st)
	}
	for _, c := range wusp.WUSPOLTCommands {
		_, bound := opByCommand[c.Path]
		sc := SchemaCommand{
			Path: c.Path, Label: c.UI.Label, Effect: string(c.Effect),
			Confirm: c.Effect == wusp.OLTEffectDisruptive || c.Effect == wusp.OLTEffectDestructive,
			Group:   c.UI.Group, Section: c.UI.Section, Page: c.UI.Page, Help: c.Description,
			Supported: bound, Inputs: argsOf(c.Inputs), Outputs: argsOf(c.Outputs),
		}
		if sc.Group == "" {
			sc.Group, sc.Section = defaultPlacement(strings.TrimPrefix(c.Path, wusp.WUSPOLTPrefix))
		}
		if sc.Label == "" {
			sc.Label = strings.TrimSuffix(lastSegment(c.Path), "()")
		}
		s.Operations = append(s.Operations, sc)
	}
	for _, p := range wusp.OLTUnsupportedPages() {
		s.Unsupported = append(s.Unsupported, SchemaUnsupported{Route: p.Route, Title: p.Title, Reason: p.Unsupported})
	}
	return s
}
