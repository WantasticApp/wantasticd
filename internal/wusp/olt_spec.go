package wusp

// Declarative OLT web-UI page specs.
//
// Every page of the FOS web UI is described once as an OLTPage: the goform
// getter(s) it reads, its scalar form fields, its tables and its buttons.
// This package derives the Device.WUSP_OLT parameters, objects, table defs
// and commands from the specs (schema + console metadata); the fiberolt
// package interprets the same specs into getters, setters, Add/Delete and
// Operate handlers. Adding a control = adding one OLTField (or OLTTable /
// OLTAction) to the page it lives on.
//
// Paths: Device.WUSP_OLT.<Form.Object|Table.Object>.<Field.Leaf>. Objects
// are relative, CamelCase, two or three segments ("Switching.IGMP",
// "PON.Optical"), and must not collide with the hand-written legacy paths
// in olt.go (ONU, PONPort, ProvisionedONU, LineProfile, Syslog, Network).

import (
	"sort"
	"strings"
)

// OLTCall is one goform getter: GET <Path>?<Params> (POST {} also works).
type OLTCall struct {
	// Path is the goform path with leading slash, e.g. "/goform/getIgmpSnoopEn".
	Path   string
	Params map[string]string
}

// Body building for an OLTWrite (see fiberolt/pages.go):
//
//	body = {f: current[f] for f in Body}          // current form / row values
//	       ("set=get" entries rename: body[set] = current[get], for setters
//	       whose keys differ from the getter's, e.g. "vlanRemark=remark")
//	body[changedField] = new value (encoded by the field Codec)
//	body += Extra                                  // constants, e.g. "action":"edit"
//	Origin "row"   -> body.originData = copy of the current form/row
//	Origin "empty" -> body.originData = {}
//	Port  "name"   -> body.port = [row.portName]   ("num": [row.portNum])
//	PortScalar     -> body.port = row value (not an array)
//
// OLTBodyKey splits a Body entry "set=get" into the posted key and the
// getter key (both equal when there is no "=").
func OLTBodyKey(k string) (set, get string) {
	if a, b, ok := strings.Cut(k, "="); ok {
		return a, b
	}
	return k, k
}

// A table Add posts {f: initial[f] for f in Body} + Extra; a table Delete
// posts {"list":[row + Extra]}.
type OLTWrite struct {
	Path   string
	Body   []string
	Extra  map[string]any
	Origin string
	Port   string
	// PortScalar sends port as a plain string instead of a one-element array.
	PortScalar bool
	// PortName also adds "portName": row.portName (row edits that do so).
	PortName bool
	// OK lists success errCodes besides "0" (e.g. "6" for reboot).
	OK []string
	// NoVerify skips the re-read confirmation (write-only or async pages).
	NoVerify bool
	// Guard names a safety check run before the write (see fiberolt/guards.go).
	Guard string
}

// OLTField is one control: a parameter and how it maps onto the vendor form.
type OLTField struct {
	Leaf   string // WUSP leaf, CamelCase
	Vendor string // getter response key and form key
	// SetKey overrides the form key on write when it differs from Vendor.
	SetKey string
	Type   ParamType // default string
	Write  bool      // readWrite (needs the form/table write)
	// Codec converts vendor <-> WUSP values:
	//   ""        string as-is
	//   "bool01"  boolean <-> "1"/"0"
	//   "bool"    boolean <-> JSON true/false (checkbox forms)
	//   "uint"    unsignedInt <-> decimal string
	//   "int"     int <-> decimal string
	//   "decimal" decimal <-> string
	//   "base64"  string, base64-encoded on write (and decoded on read when valid)
	//   "list"    comma-joined string of a JSON array (read), array on write
	Codec string
	// Enum: allowed vendor values; EnumLabels: matching display labels.
	Enum       []string
	EnumLabels []string
	Min, Max   *int64
	MaxLength  int
	Units      string
	Label      string
	Help       string
	Effect     OLTEffect // default: none (RO) / config (RW)
	// Required marks mandatory Add initial fields and action inputs.
	Required bool
	// Set overrides the form/table write for this field only (pages that
	// post one toggle immediately, e.g. {dhcpSnoopEn}).
	Set *OLTWrite
}

// OLTForm is a scalar settings form backed by one getter.
type OLTForm struct {
	Object string // relative, e.g. "Switching.IGMP"
	Get    OLTCall
	Set    *OLTWrite // whole-form write for Write fields; nil = read-only
	Fields []OLTField
}

// OLTTable is a list getter rendered as Device.WUSP_OLT.<Object>.{i}.
type OLTTable struct {
	Object string // relative, e.g. "Switching.Port.Basic"
	Get    OLTCall
	List   string   // response key of the rows (default "list")
	Key    []string // vendor fields forming the stable row key
	// Count is the NumberOfEntries leaf (default <Object last segment>NumberOfEntries
	// next to the table).
	Columns []OLTField
	Edit    *OLTWrite // row edit for Write columns
	Add     *OLTWrite // USP Add (initial fields by Leaf, posted by Vendor)
	Delete  *OLTWrite // USP Delete
	Label   string
	Help    string
	// DeleteEffect classifies Delete (default destructive).
	DeleteEffect OLTEffect
}

// OLTAction is a button: Device.WUSP_OLT.<Command> Operate.
type OLTAction struct {
	Command string // relative, e.g. "Switching.MAC.Flush()"
	Write   OLTWrite
	Inputs  []OLTField // Leaf = input name, Vendor = body key
	Effect  OLTEffect
	Label   string
	Help    string
	// Result returns the vendor reply (JSON) in <Command base>Result.
	Result bool
	// Read pre-fills the body (Write.Body fields) from the current form, so
	// inputs left empty keep their value (whole-form pages).
	Read *OLTCall
	// Rows: the command acts on table rows selected by an "Index" input
	// (comma-separated vendor keys) and posts {"list":[rows]} - e.g. ONU
	// Active/Deactive/Reboot.
	Rows *OLTTable
}

// OLTPage groups the controls of one web-UI page.
type OLTPage struct {
	Route   string // web UI route, e.g. "/switch/igmp/global"
	Title   string
	Group   string // console group (first path segment)
	Section string
	Forms   []OLTForm
	Tables  []OLTTable
	Actions []OLTAction
	// Unsupported lists the page in metadata only, with the reason.
	Unsupported string
}

// OLTPages is every web-UI page spec. The per-section files fill the
// variables below.
var OLTPages = concatOLTPages(
	oltPagesCore,
	oltPagesBasics,
	oltPagesPON,
	oltPagesProfile,
	oltPagesSwitching,
	oltPagesSwitching2,
	oltPagesRouting,
	oltPagesQoS,
	oltPagesSecurity,
	oltPagesDevice,
)

func concatOLTPages(groups ...[]OLTPage) []OLTPage {
	var out []OLTPage
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

func i64(v int64) *int64 { return &v }

// OLTRange is a helper for Min/Max in page specs.
func OLTRange(min, max int64) (*int64, *int64) { return i64(min), i64(max) }

// ---- derivation: specs -> schema ------------------------------------------

func (f OLTField) paramType() ParamType {
	if f.Type != "" {
		return f.Type
	}
	switch f.Codec {
	case "bool01", "bool":
		return TypeBoolean
	case "uint":
		return TypeUnsignedInt
	case "int":
		return TypeInt
	case "decimal":
		return TypeDecimal
	}
	return TypeString
}

func (f OLTField) def(path, group, section string) OLTParamDef {
	access := ReadOnly
	if f.Write {
		access = ReadWrite
	}
	desc := f.Help
	if desc == "" {
		desc = f.Label
	}
	if desc == "" {
		desc = f.Leaf
	}
	limits := Limits{Min: f.Min, Max: f.Max, MaxLength: f.MaxLength}
	if f.paramType() == TypeString && len(f.Enum) > 0 {
		limits.Enums = append([]string{""}, f.Enum...)
	}
	d := OLTParamDef{
		Param: Param{Path: WUSPOLTPrefix + path, Type: f.paramType(), Access: access, SinceVersion: "1.1", Description: desc, Limits: limits},
		UI:    OLTUI{Label: f.Label, Group: group, Section: section, Units: f.Units, EnumLabels: f.EnumLabels},
	}
	d.Effect = f.Effect
	if d.Effect == "" {
		if f.Write {
			d.Effect = OLTEffectConfig
		} else {
			d.Effect = OLTEffectNone
		}
	}
	if !f.Write {
		d.Effect = OLTEffectNone
	}
	return d
}

// TableCountLeaf is the NumberOfEntries leaf of a spec table.
func (t OLTTable) TableCountLeaf() string {
	obj := strings.TrimSuffix(t.Object, ".")
	return obj + "NumberOfEntries"
}

func pageSection(p OLTPage, obj string) (string, string) {
	group, section := p.Group, p.Section
	if group == "" {
		parts := strings.Split(obj, ".")
		group = parts[0]
		if section == "" && len(parts) > 1 {
			section = parts[1]
		}
	}
	return group, section
}

func oltPageParamDefs() []OLTParamDef {
	var out []OLTParamDef
	for _, p := range OLTPages {
		if p.Unsupported != "" {
			continue
		}
		for _, f := range p.Forms {
			g, s := pageSection(p, f.Object)
			for _, fl := range f.Fields {
				d := fl.def(f.Object+"."+fl.Leaf, g, s)
				d.UI.Page = p.Route
				out = append(out, d)
			}
		}
		for _, t := range p.Tables {
			g, s := pageSection(p, t.Object)
			for _, fl := range t.Columns {
				d := fl.def(t.Object+".{i}."+fl.Leaf, g, s)
				d.UI.Page = p.Route
				out = append(out, d)
			}
			cnt := OLTParamDef{Param: Param{Path: WUSPOLTPrefix + t.TableCountLeaf(), Type: TypeUnsignedInt, Access: ReadOnly, SinceVersion: "1.1",
				Description: "Number of entries in Device.WUSP_OLT." + t.Object + ".{i}.", Limits: Limits{Min: i64(0)}}, Effect: OLTEffectNone,
				UI: OLTUI{Group: g, Section: s, Page: p.Route}}
			out = append(out, cnt)
		}
		for _, a := range p.Actions {
			if a.Result {
				g, s := pageSection(p, a.Command)
				out = append(out, OLTParamDef{Param: Param{Path: WUSPOLTPrefix + OLTActionResultLeaf(a.Command), Type: TypeString, Access: ReadOnly, SinceVersion: "1.1",
					Description: "Result of " + a.Command + " (vendor reply JSON).", Limits: Limits{MaxLength: 1 << 20}}, Effect: OLTEffectNone,
					UI: OLTUI{Group: g, Section: s, Page: p.Route}})
			}
		}
	}
	return out
}

// OLTActionResultLeaf is the result parameter of a Result action:
// "Device.Diagnostics.Ping()" -> "Device.Diagnostics.PingResult".
func OLTActionResultLeaf(command string) string {
	return strings.TrimSuffix(command, "()") + "Result"
}

func oltPageObjects() ([]Object, []OLTTableDef) {
	var objs []Object
	var defs []OLTTableDef
	seen := map[string]bool{}
	addObj := func(path string, multi bool, desc string) {
		if seen[path] {
			return
		}
		seen[path] = true
		objs = append(objs, Object{Path: path, MultiInstance: multi, SinceVersion: "1.1", Description: desc})
	}
	for _, p := range OLTPages {
		if p.Unsupported != "" {
			continue
		}
		parents := func(obj string) {
			parts := strings.Split(obj, ".")
			for i := 1; i < len(parts); i++ {
				addObj(WUSPOLTPrefix+strings.Join(parts[:i], ".")+".", false, p.Title)
			}
		}
		for _, f := range p.Forms {
			parents(f.Object)
			addObj(WUSPOLTPrefix+f.Object+".", false, p.Title)
		}
		for _, t := range p.Tables {
			parents(t.Object)
			path := WUSPOLTPrefix + t.Object + ".{i}."
			desc := t.Help
			if desc == "" {
				desc = t.Label
			}
			if desc == "" {
				desc = p.Title
			}
			addObj(path, true, desc)
			g, s := pageSection(p, t.Object)
			key := ""
			if len(t.Key) > 0 {
				for _, c := range t.Columns {
					if c.Vendor == t.Key[0] {
						key = c.Leaf
					}
				}
			}
			td := OLTTableDef{Path: path, Key: key, CountParam: WUSPOLTPrefix + t.TableCountLeaf(),
				Addable: t.Add != nil, Deletable: t.Delete != nil, UI: OLTUI{Label: t.Label, Group: g, Section: s, Page: p.Route, Help: t.Help}}
			if t.Add != nil {
				for _, c := range t.Columns {
					key := c.Vendor
					if c.SetKey != "" {
						key = c.SetKey
					}
					for _, b := range t.Add.Body {
						if set, _ := OLTBodyKey(b); set == key || set == c.Vendor {
							td.AddArgs = append(td.AddArgs, OLTArgDef{Name: c.Leaf, Type: c.paramType(), Required: c.Required, Description: c.Label, Limits: Limits{Enums: c.Enum, Min: c.Min, Max: c.Max, MaxLength: c.MaxLength}})
						}
					}
				}
			}
			defs = append(defs, td)
		}
		for _, a := range p.Actions {
			parents(strings.TrimSuffix(a.Command, "()"))
		}
	}
	sort.SliceStable(objs, func(i, j int) bool { return objs[i].Path < objs[j].Path })
	return objs, defs
}

func oltPageCommands() []OLTCommandDef {
	var out []OLTCommandDef
	for _, p := range OLTPages {
		if p.Unsupported != "" {
			continue
		}
		for _, a := range p.Actions {
			g, s := pageSection(p, a.Command)
			c := OLTCommandDef{Path: WUSPOLTPrefix + a.Command, Description: a.Help, Effect: a.Effect,
				UI: OLTUI{Label: a.Label, Group: g, Section: s, Page: p.Route}}
			if c.Effect == "" {
				c.Effect = OLTEffectConfig
			}
			if c.Description == "" {
				c.Description = a.Label
			}
			if a.Rows != nil {
				c.Inputs = append(c.Inputs, OLTArgDef{Name: "Index", Type: TypeString, Required: true, Description: "Comma-separated row keys."})
			}
			for _, in := range a.Inputs {
				c.Inputs = append(c.Inputs, OLTArgDef{Name: in.Leaf, Type: in.paramType(), Required: in.Required, Description: in.Label, Limits: Limits{Enums: in.Enum, Min: in.Min, Max: in.Max, MaxLength: in.MaxLength}})
			}
			if a.Result {
				c.Outputs = append(c.Outputs, OLTArgDef{Name: "Result", Type: TypeString, Path: WUSPOLTPrefix + OLTActionResultLeaf(a.Command), Description: "Vendor reply JSON."})
			}
			out = append(out, c)
		}
	}
	return out
}

// OLTUnsupportedPages lists pages kept out of the data model, with reasons.
func OLTUnsupportedPages() []OLTPage {
	var out []OLTPage
	for _, p := range OLTPages {
		if p.Unsupported != "" {
			out = append(out, p)
		}
	}
	return out
}
