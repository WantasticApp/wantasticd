package wusp

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
)

// ParamType mirrors the BBF CWMP/USP primitive types and the small set of
// higher-level aliases WUSP validates specially.
type ParamType string

const (
	TypeString       ParamType = "string"
	TypeInt          ParamType = "int"
	TypeUnsignedInt  ParamType = "unsignedInt"
	TypeLong         ParamType = "long"
	TypeUnsignedLong ParamType = "unsignedLong"
	TypeBoolean      ParamType = "boolean"
	TypeDateTime     ParamType = "dateTime"
	TypeBase64       ParamType = "base64"
	TypeHexBinary    ParamType = "hexBinary"
	TypeDecimal      ParamType = "decimal"

	TypeIPv4Address  ParamType = "IPv4Address"
	TypeIPv6Address  ParamType = "IPv6Address"
	TypeIPv4Prefix   ParamType = "IPv4Prefix"
	TypeIPv6Prefix   ParamType = "IPv6Prefix"
	TypeMACAddress   ParamType = "MACAddress"
	TypeAlias        ParamType = "Alias"
	TypeStatsCounter ParamType = "StatsCounter"
	TypePathRef      ParamType = "PathRef"
	TypeList         ParamType = "list"
)

// Access describes who can mutate a parameter.
type Access string

const (
	ReadOnly  Access = "readOnly"
	ReadWrite Access = "readWrite"
	WriteOnly Access = "writeOnly"
)

// Limits constrains the legal value range for a parameter.
type Limits struct {
	Min  *int64   `json:"Min,omitempty"`
	Max  *int64   `json:"Max,omitempty"`
	MinF *float64 `json:"MinF,omitempty"`
	MaxF *float64 `json:"MaxF,omitempty"`

	MinLength int `json:"MinLength,omitempty"`
	MaxLength int `json:"MaxLength,omitempty"`

	Enums   []string `json:"Enums,omitempty"`
	Pattern string   `json:"Pattern,omitempty"`

	MinItems int `json:"MinItems,omitempty"`
	MaxItems int `json:"MaxItems,omitempty"`
}

// Param is one BBF or Wantastic parameter definition.
type Param struct {
	Path         string    `json:"path"`
	Type         ParamType `json:"type"`
	Access       Access    `json:"access"`
	SinceVersion string    `json:"since_version"`
	Description  string    `json:"description,omitempty"`
	Limits       Limits    `json:"limits,omitempty"`
}

// Object is one schema object node.
type Object struct {
	Path          string `json:"path"`
	MultiInstance bool   `json:"multi_instance,omitempty"`
	SinceVersion  string `json:"since_version"`
	Description   string `json:"description,omitempty"`
}

// Device is the canonical path-indexed model container for one root data model.
// Root is normalized to lower-case (for example "device.") so callers can use
// stable lookup/search logic without depending on the BBF source casing.
type Device struct {
	Root    string
	Summary ImportedModelSummary
	Objects []Object
	Params  []Param

	objectIndex map[string]int
	paramIndex  map[string]int
	pathCode    map[string]uint64
	codePath    map[uint64]string
}

// PathSelector is the compact reversible selector form used by the WUSP
// control transport. Code identifies the canonical schema path, while
// Instances carries concrete ordinal values for each {i} token. A value of 0
// means the corresponding token remains unresolved as {i}.
type PathSelector struct {
	Code      uint64
	Instances []uint64
}

// ImportedModelSummary describes one imported BBF full.xml file.
type ImportedModelSummary struct {
	ID           string `json:"id"`
	FileName     string `json:"file_name"`
	Name         string `json:"name"`
	ModelVersion string `json:"model_version"`
	Source       string `json:"source"`
	SourceURL    string `json:"source_url"`
	ObjectCount  int    `json:"object_count"`
	ParamCount   int    `json:"param_count"`
}

// ImportedModelCatalog is the parsed path catalog for one BBF full.xml file.
type ImportedModelCatalog struct {
	Summary ImportedModelSummary `json:"summary"`
	Objects []Object             `json:"objects"`
	Params  []Param              `json:"params"`
}

func NewDevice(summary ImportedModelSummary, objects []Object, params []Param) *Device {
	d := &Device{
		Root:        detectDeviceRoot(objects, params),
		Summary:     summary,
		Objects:     cloneObjects(objects),
		Params:      cloneParams(params),
		objectIndex: make(map[string]int, len(objects)),
		paramIndex:  make(map[string]int, len(params)),
		pathCode:    make(map[string]uint64, len(objects)+len(params)),
		codePath:    make(map[uint64]string, len(objects)+len(params)),
	}
	for i, object := range d.Objects {
		d.objectIndex[normalizeDeviceLookupPath(object.Path)] = i
	}
	for i, param := range d.Params {
		d.paramIndex[normalizeDeviceLookupPath(param.Path)] = i
	}
	d.buildPathCodes()
	return d
}

func (d *Device) Clone() *Device {
	if d == nil {
		return nil
	}
	return NewDevice(d.Summary, d.Objects, d.Params)
}

func (d *Device) GetParam(path string) (Param, bool) {
	if d == nil {
		return Param{}, false
	}
	idx, ok := d.paramIndex[normalizeDeviceLookupPath(path)]
	if !ok {
		idx, ok = d.paramIndex[normalizeCanonicalDeviceLookupPath(path)]
	}
	if !ok {
		return Param{}, false
	}
	return cloneParam(d.Params[idx]), true
}

func (d *Device) GetObject(path string) (Object, bool) {
	if d == nil {
		return Object{}, false
	}
	idx, ok := d.objectIndex[normalizeDeviceLookupPath(path)]
	if !ok {
		idx, ok = d.objectIndex[normalizeCanonicalDeviceLookupPath(path)]
	}
	if !ok {
		return Object{}, false
	}
	return d.Objects[idx], true
}

// Search returns a subset Device containing only params and objects whose
// paths start with the requested prefix.
func (d *Device) Search(prefix string) *Device {
	if d == nil {
		return nil
	}
	prefix = normalizeDeviceLookupPath(prefix)
	if prefix == "" {
		return d.Clone()
	}

	objects := make([]Object, 0)
	for _, object := range d.Objects {
		if strings.HasPrefix(normalizeDeviceLookupPath(object.Path), prefix) {
			objects = append(objects, object)
		}
	}
	params := make([]Param, 0)
	for _, param := range d.Params {
		if strings.HasPrefix(normalizeDeviceLookupPath(param.Path), prefix) {
			params = append(params, cloneParam(param))
		}
	}

	summary := d.Summary
	summary.ObjectCount = len(objects)
	summary.ParamCount = len(params)
	return NewDevice(summary, objects, params)
}

// Paths returns a stable sorted list of all object and parameter paths.
func (d *Device) Paths() []string {
	if d == nil {
		return nil
	}
	out := make([]string, 0, len(d.Objects)+len(d.Params))
	for _, object := range d.Objects {
		out = append(out, object.Path)
	}
	for _, param := range d.Params {
		out = append(out, param.Path)
	}
	sort.Strings(out)
	return out
}

func (d *Device) PathCode(path string) (uint64, bool) {
	if d == nil {
		return 0, false
	}
	code, ok := d.pathCode[normalizeDeviceLookupPath(path)]
	if !ok {
		code, ok = d.pathCode[normalizeCanonicalDeviceLookupPath(path)]
	}
	return code, ok
}

func (d *Device) PathByCode(code uint64) (string, bool) {
	if d == nil || code == 0 {
		return "", false
	}
	path, ok := d.codePath[code]
	return path, ok
}

func (d *Device) GetParamByCode(code uint64) (Param, bool) {
	path, ok := d.PathByCode(code)
	if !ok {
		return Param{}, false
	}
	return d.GetParam(path)
}

func (d *Device) GetObjectByCode(code uint64) (Object, bool) {
	path, ok := d.PathByCode(code)
	if !ok {
		return Object{}, false
	}
	return d.GetObject(path)
}

func (d *Device) BatchGetParams(paths ...string) []Param {
	if d == nil || len(paths) == 0 {
		return nil
	}
	out := make([]Param, 0, len(paths))
	for _, path := range paths {
		if param, ok := d.GetParam(path); ok {
			out = append(out, param)
		}
	}
	return out
}

func (d *Device) BatchGetParamsByCode(codes ...uint64) []Param {
	if d == nil || len(codes) == 0 {
		return nil
	}
	out := make([]Param, 0, len(codes))
	for _, code := range codes {
		if param, ok := d.GetParamByCode(code); ok {
			out = append(out, param)
		}
	}
	return out
}

func (d *Device) BatchGetObjects(paths ...string) []Object {
	if d == nil || len(paths) == 0 {
		return nil
	}
	out := make([]Object, 0, len(paths))
	for _, path := range paths {
		if object, ok := d.GetObject(path); ok {
			out = append(out, object)
		}
	}
	return out
}

func (d *Device) BatchGetObjectsByCode(codes ...uint64) []Object {
	if d == nil || len(codes) == 0 {
		return nil
	}
	out := make([]Object, 0, len(codes))
	for _, code := range codes {
		if object, ok := d.GetObjectByCode(code); ok {
			out = append(out, object)
		}
	}
	return out
}

func (d *Device) BatchPathCodes(paths ...string) []uint64 {
	if d == nil || len(paths) == 0 {
		return nil
	}
	out := make([]uint64, 0, len(paths))
	for _, path := range paths {
		if code, ok := d.PathCode(path); ok {
			out = append(out, code)
		}
	}
	return out
}

func (d *Device) BatchPathsByCode(codes ...uint64) []string {
	if d == nil || len(codes) == 0 {
		return nil
	}
	out := make([]string, 0, len(codes))
	for _, code := range codes {
		if path, ok := d.PathByCode(code); ok {
			out = append(out, path)
		}
	}
	return out
}

func (d *Device) SelectorForPath(path string) (PathSelector, bool) {
	if d == nil {
		return PathSelector{}, false
	}
	canonical, ok := d.CanonicalPath(path)
	if !ok {
		return PathSelector{}, false
	}
	code, ok := d.PathCode(canonical)
	if !ok || code == 0 {
		return PathSelector{}, false
	}
	instances, ok := selectorInstancesFromPath(path, canonical)
	if !ok {
		return PathSelector{}, false
	}
	return PathSelector{Code: code, Instances: instances}, true
}

func (d *Device) PathForSelector(selector PathSelector) (string, bool) {
	if d == nil || selector.Code == 0 {
		return "", false
	}
	canonical, ok := d.PathByCode(selector.Code)
	if !ok {
		return "", false
	}
	return applySelectorInstances(canonical, selector.Instances)
}

func (d *Device) BatchSelectors(paths ...string) []PathSelector {
	if d == nil || len(paths) == 0 {
		return nil
	}
	out := make([]PathSelector, 0, len(paths))
	for _, path := range paths {
		if selector, ok := d.SelectorForPath(path); ok {
			out = append(out, selector)
		}
	}
	return out
}

func (d *Device) CanonicalPath(path string) (string, bool) {
	if d == nil {
		return "", false
	}
	if _, ok := d.paramIndex[normalizeDeviceLookupPath(path)]; ok {
		return path, true
	}
	if _, ok := d.objectIndex[normalizeDeviceLookupPath(path)]; ok {
		return path, true
	}
	canonical := canonicalParamPath(strings.TrimSpace(path))
	key := normalizeDeviceLookupPath(canonical)
	if _, ok := d.paramIndex[key]; ok {
		return canonical, true
	}
	if _, ok := d.objectIndex[key]; ok {
		return canonical, true
	}
	return "", false
}

func (d *Device) BatchSetParams(params ...Param) {
	for _, param := range params {
		d.SetParam(param)
	}
}

func (d *Device) BatchAddObjects(objects ...Object) {
	for _, object := range objects {
		d.SetObject(object)
	}
}

// SetParam upserts one parameter definition by path.
func (d *Device) SetParam(param Param) {
	if d == nil || strings.TrimSpace(param.Path) == "" {
		return
	}
	key := normalizeDeviceLookupPath(param.Path)
	if idx, ok := d.paramIndex[key]; ok {
		d.Params[idx] = cloneParam(param)
		return
	}
	d.paramIndex[key] = len(d.Params)
	d.assignPathCode(key, param.Path)
	d.Params = append(d.Params, cloneParam(param))
}

// SetObject upserts one object definition by path.
func (d *Device) SetObject(object Object) {
	if d == nil || strings.TrimSpace(object.Path) == "" {
		return
	}
	key := normalizeDeviceLookupPath(object.Path)
	if idx, ok := d.objectIndex[key]; ok {
		d.Objects[idx] = object
		return
	}
	d.objectIndex[key] = len(d.Objects)
	d.assignPathCode(key, object.Path)
	d.Objects = append(d.Objects, object)
}

func paramsWithPrefix(params []Param, prefix string) []Param {
	if prefix == "" {
		return cloneParams(params)
	}
	out := make([]Param, 0)
	for _, param := range params {
		if strings.HasPrefix(param.Path, prefix) {
			out = append(out, cloneParam(param))
		}
	}
	return out
}

func directParamsUnder(params []Param, parent string) []Param {
	out := make([]Param, 0)
	for _, param := range params {
		if !strings.HasPrefix(param.Path, parent) {
			continue
		}
		if strings.Contains(strings.TrimPrefix(param.Path, parent), ".") {
			continue
		}
		out = append(out, cloneParam(param))
	}
	return out
}

func paramsWithPrefixExcludingDirect(params []Param, prefix string) []Param {
	out := make([]Param, 0)
	for _, param := range params {
		if !strings.HasPrefix(param.Path, prefix) {
			continue
		}
		if !strings.Contains(strings.TrimPrefix(param.Path, prefix), ".") {
			continue
		}
		out = append(out, cloneParam(param))
	}
	return out
}

func objectsWithPrefix(objects []Object, prefix string) []Object {
	if prefix == "" {
		return cloneObjects(objects)
	}
	out := make([]Object, 0)
	for _, object := range objects {
		if strings.HasPrefix(object.Path, prefix) {
			out = append(out, object)
		}
	}
	return out
}

func objectsWithPrefixExcluding(objects []Object, prefix string, excluded ...string) []Object {
	blocked := make(map[string]struct{}, len(excluded))
	for _, path := range excluded {
		blocked[path] = struct{}{}
	}
	out := make([]Object, 0)
	for _, object := range objects {
		if !strings.HasPrefix(object.Path, prefix) {
			continue
		}
		if _, ok := blocked[object.Path]; ok {
			continue
		}
		out = append(out, object)
	}
	return out
}

func cloneParam(in Param) Param {
	out := in
	if len(in.Limits.Enums) > 0 {
		out.Limits.Enums = append([]string(nil), in.Limits.Enums...)
	}
	return out
}

func cloneParams(in []Param) []Param {
	out := make([]Param, len(in))
	for i := range in {
		out[i] = cloneParam(in[i])
	}
	return out
}

func paramsWithoutPrefix(params []Param, prefix string) []Param {
	out := make([]Param, 0, len(params))
	for _, param := range params {
		if strings.HasPrefix(param.Path, prefix) {
			continue
		}
		out = append(out, cloneParam(param))
	}
	return out
}

func concatUniqueParams(slices ...[]Param) []Param {
	total := 0
	for _, slice := range slices {
		total += len(slice)
	}
	out := make([]Param, 0, total)
	seen := make(map[string]int, total)
	for _, slice := range slices {
		for _, param := range slice {
			if idx, ok := seen[param.Path]; ok {
				out[idx] = cloneParam(param)
				continue
			}
			seen[param.Path] = len(out)
			out = append(out, cloneParam(param))
		}
	}
	return out
}

func objectsWithoutPrefix(objects []Object, prefix string) []Object {
	out := make([]Object, 0, len(objects))
	for _, object := range objects {
		if strings.HasPrefix(object.Path, prefix) {
			continue
		}
		out = append(out, object)
	}
	return out
}

func cloneObjects(in []Object) []Object {
	out := make([]Object, len(in))
	copy(out, in)
	return out
}

func (d *Device) buildPathCodes() {
	if d == nil {
		return
	}
	paths := d.Paths()
	for _, path := range paths {
		key := normalizeDeviceLookupPath(path)
		if _, ok := d.pathCode[key]; ok {
			continue
		}
		d.assignPathCode(key, path)
	}
}

func (d *Device) assignPathCode(key, path string) {
	if d == nil || key == "" {
		return
	}
	if _, ok := d.pathCode[key]; ok {
		return
	}
	code := EncodePathCode(path)
	if code == 0 {
		return
	}
	if existing, ok := d.codePath[code]; ok && normalizeDeviceLookupPath(existing) != key {
		panic(fmt.Sprintf("wusp: path code collision for %q and %q", existing, path))
	}
	d.pathCode[key] = code
	d.codePath[code] = path
}

func detectDeviceRoot(objects []Object, params []Param) string {
	for _, object := range objects {
		if root := rootFromPath(object.Path); root != "" {
			return root
		}
	}
	for _, param := range params {
		if root := rootFromPath(param.Path); root != "" {
			return root
		}
	}
	return "device."
}

func rootFromPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	parts := strings.Split(path, ".")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	return strings.ToLower(parts[0]) + "."
}

func normalizeDeviceLookupPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return strings.ToLower(path)
}

func normalizeCanonicalDeviceLookupPath(path string) string {
	return normalizeDeviceLookupPath(canonicalParamPath(path))
}

// EncodePathCode returns the stable uint64 selector code for a WUSP path.
// Instance paths such as Device.WiFi.SSID.1.Enable are canonicalized to their
// schema form before hashing, so controllers and agents can derive the same
// code without exchanging the full path string.
func EncodePathCode(path string) uint64 {
	path = normalizeCanonicalDeviceLookupPath(path)
	if path == "" {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(path))
	code := h.Sum64()
	if code == 0 {
		return 1
	}
	return code
}

func selectorInstancesFromPath(path, canonical string) ([]uint64, bool) {
	path = strings.TrimSpace(path)
	canonical = strings.TrimSpace(canonical)
	if path == "" || canonical == "" {
		return nil, false
	}
	pathParts := strings.Split(path, ".")
	canonicalParts := strings.Split(canonical, ".")
	if len(pathParts) != len(canonicalParts) {
		return nil, false
	}
	instances := make([]uint64, 0, strings.Count(canonical, "{i}"))
	hasConcrete := false
	for i := 0; i < len(canonicalParts); i++ {
		switch canonicalParts[i] {
		case "{i}":
			switch {
			case pathParts[i] == "{i}":
				instances = append(instances, 0)
			case isNumericPathSegment(pathParts[i]):
				value, err := strconv.ParseUint(pathParts[i], 10, 64)
				if err != nil || value == 0 {
					return nil, false
				}
				hasConcrete = true
				instances = append(instances, value)
			default:
				return nil, false
			}
		default:
			if !strings.EqualFold(pathParts[i], canonicalParts[i]) {
				return nil, false
			}
		}
	}
	if !hasConcrete {
		return nil, true
	}
	return instances, true
}

func applySelectorInstances(canonical string, instances []uint64) (string, bool) {
	if canonical == "" {
		return "", false
	}
	tokenCount := strings.Count(canonical, "{i}")
	if tokenCount == 0 {
		return canonical, len(instances) == 0
	}
	if len(instances) == 0 {
		return canonical, true
	}
	if len(instances) != tokenCount {
		return "", false
	}
	parts := strings.Split(canonical, ".")
	index := 0
	for i := 0; i < len(parts); i++ {
		if parts[i] != "{i}" {
			continue
		}
		if instances[index] != 0 {
			parts[i] = strconv.FormatUint(instances[index], 10)
		}
		index++
	}
	return strings.Join(parts, "."), true
}
