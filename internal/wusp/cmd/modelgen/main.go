package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type paramType string

const (
	typeString       paramType = "string"
	typeInt          paramType = "int"
	typeUnsignedInt  paramType = "unsignedInt"
	typeLong         paramType = "long"
	typeUnsignedLong paramType = "unsignedLong"
	typeBoolean      paramType = "boolean"
	typeDateTime     paramType = "dateTime"
	typeBase64       paramType = "base64"
	typeHexBinary    paramType = "hexBinary"
	typeDecimal      paramType = "decimal"
	typeIPv4Address  paramType = "IPv4Address"
	typeIPv6Address  paramType = "IPv6Address"
	typeIPv4Prefix   paramType = "IPv4Prefix"
	typeIPv6Prefix   paramType = "IPv6Prefix"
	typeMACAddress   paramType = "MACAddress"
	typeAlias        paramType = "Alias"
	typeStatsCounter paramType = "StatsCounter"
	typePathRef      paramType = "PathRef"
	typeList         paramType = "list"
)

type access string

const (
	readOnly  access = "readOnly"
	readWrite access = "readWrite"
	writeOnly access = "writeOnly"
)

type limits struct {
	Min       *int64   `json:",omitempty"`
	Max       *int64   `json:",omitempty"`
	MinF      *float64 `json:",omitempty"`
	MaxF      *float64 `json:",omitempty"`
	MinLength int      `json:",omitempty"`
	MaxLength int      `json:",omitempty"`
	Enums     []string `json:",omitempty"`
	Pattern   string   `json:",omitempty"`
	MinItems  int      `json:",omitempty"`
	MaxItems  int      `json:",omitempty"`
}

type param struct {
	Path         string    `json:"path"`
	Type         paramType `json:"type"`
	Access       access    `json:"access"`
	SinceVersion string    `json:"since_version"`
	Description  string    `json:"description,omitempty"`
	Limits       limits    `json:"limits,omitempty"`
}

type object struct {
	Path          string `json:"path"`
	MultiInstance bool   `json:"multi_instance,omitempty"`
	SinceVersion  string `json:"since_version"`
	Description   string `json:"description,omitempty"`
}

type xmlDocument struct {
	XMLName   xml.Name      `xml:"document"`
	DataTypes []xmlDataType `xml:"dataType"`
	Models    []xmlModel    `xml:"model"`
}

type xmlModel struct {
	Name    string      `xml:"name,attr"`
	Objects []xmlObject `xml:"object"`
}

type xmlObject struct {
	Name        string         `xml:"name,attr"`
	Access      string         `xml:"access,attr"`
	Version     string         `xml:"version,attr"`
	MaxEntries  string         `xml:"maxEntries,attr"`
	Description string         `xml:"description"`
	Parameters  []xmlParameter `xml:"parameter"`
	Objects     []xmlObject    `xml:"object"`
}

type xmlParameter struct {
	Name        string    `xml:"name,attr"`
	Access      string    `xml:"access,attr"`
	Version     string    `xml:"version,attr"`
	Description string    `xml:"description"`
	Syntax      xmlSyntax `xml:"syntax"`
}

type xmlDataType struct {
	Name        string    `xml:"name,attr"`
	Base        string    `xml:"base,attr"`
	Description string    `xml:"description"`
	Syntax      xmlSyntax `xml:"syntax"`
}

type xmlSyntax struct {
	Hidden       string             `xml:"hidden,attr"`
	DataType     *xmlDataTypeSyntax `xml:"dataType"`
	String       *xmlStringSyntax   `xml:"string"`
	Int          *xmlNumericSyntax  `xml:"int"`
	UnsignedInt  *xmlNumericSyntax  `xml:"unsignedInt"`
	Long         *xmlNumericSyntax  `xml:"long"`
	UnsignedLong *xmlNumericSyntax  `xml:"unsignedLong"`
	Boolean      *xmlBoolSyntax     `xml:"boolean"`
	DateTime     *xmlDateTimeSyntax `xml:"dateTime"`
	Base64       *xmlBinarySyntax   `xml:"base64"`
	HexBinary    *xmlBinarySyntax   `xml:"hexBinary"`
	Decimal      *xmlDecimalSyntax  `xml:"decimal"`
	List         *xmlListSyntax     `xml:"list"`
}

type xmlDataTypeSyntax struct {
	Ref            string              `xml:"ref,attr"`
	Units          *xmlUnits           `xml:"units"`
	Range          *xmlRange           `xml:"range"`
	Size           *xmlSize            `xml:"size"`
	Enumerations   []xmlEnumeration    `xml:"enumeration"`
	EnumerationRef []xmlEnumerationRef `xml:"enumerationRef"`
	Patterns       []xmlPattern        `xml:"pattern"`
	PathRef        *xmlPathRef         `xml:"pathRef"`
}

type xmlStringSyntax struct {
	Size           *xmlSize            `xml:"size"`
	Enumerations   []xmlEnumeration    `xml:"enumeration"`
	EnumerationRef []xmlEnumerationRef `xml:"enumerationRef"`
	Patterns       []xmlPattern        `xml:"pattern"`
	PathRef        *xmlPathRef         `xml:"pathRef"`
	Units          *xmlUnits           `xml:"units"`
}

type xmlBinarySyntax struct {
	Size *xmlSize `xml:"size"`
}

type xmlNumericSyntax struct {
	Range *xmlRange `xml:"range"`
	Units *xmlUnits `xml:"units"`
}

type xmlDecimalSyntax struct {
	Range *xmlRange `xml:"range"`
	Units *xmlUnits `xml:"units"`
}

type xmlBoolSyntax struct{}
type xmlDateTimeSyntax struct{}

type xmlListSyntax struct {
	MinItems       string              `xml:"minItems,attr"`
	MaxItems       string              `xml:"maxItems,attr"`
	Size           *xmlSize            `xml:"size"`
	Enumerations   []xmlEnumeration    `xml:"enumeration"`
	EnumerationRef []xmlEnumerationRef `xml:"enumerationRef"`
	PathRef        *xmlPathRef         `xml:"pathRef"`
}

type xmlRange struct {
	MinInclusive string `xml:"minInclusive,attr"`
	MaxInclusive string `xml:"maxInclusive,attr"`
}

type xmlSize struct {
	MinLength string `xml:"minLength,attr"`
	MaxLength string `xml:"maxLength,attr"`
}

type xmlEnumeration struct {
	Value string `xml:"value,attr"`
}

type xmlEnumerationRef struct {
	TargetParam string `xml:"targetParam,attr"`
	NullValue   string `xml:"nullValue,attr"`
}

type xmlPattern struct {
	Value string `xml:"value,attr"`
}

type xmlPathRef struct {
	TargetType string `xml:"targetType,attr"`
	TargetPath string `xml:"targetParent,attr"`
	RefType    string `xml:"refType,attr"`
}

type xmlUnits struct {
	Value string `xml:"value,attr"`
}

type resolvedSyntax struct {
	Type    paramType
	Limits  limits
	PathRef bool
}

type modelParser struct {
	dataTypes map[string]xmlDataType
	cache     map[string]resolvedSyntax
}

// fileVersionPattern matches both -cwmp and -usp suffixed full.xml files.
var fileVersionPattern = regexp.MustCompile(`-(\d+)-(\d+)-(\d+)(?:-(?:cwmp|usp))?-full\.xml$`)

func main() {
	sourcePath := flag.String("source", "", "path to a USP full.xml file")
	out := flag.String("out", "", "path to write the generated Go source file")
	pkg := flag.String("pkg", "wusp", "Go package name")
	flag.Parse()

	if strings.TrimSpace(*sourcePath) == "" {
		fatalf("missing -source")
	}
	if strings.TrimSpace(*out) == "" {
		fatalf("missing -out")
	}

	objects, params, err := parseModelFile(*sourcePath)
	if err != nil {
		fatalf("parse %s: %v", *sourcePath, err)
	}

	src, err := generateGoSource(*pkg, *sourcePath, objects, params)
	if err != nil {
		fatalf("generate Go source: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		fatalf("write %s: %v", *out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d objects, %d params)\n", *out, len(objects), len(params))
}

func parseModelFile(path string) ([]object, []param, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var doc xmlDocument
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	if len(doc.Models) == 0 {
		return nil, nil, errors.New("missing model element")
	}

	parser := modelParser{
		dataTypes: make(map[string]xmlDataType, len(doc.DataTypes)),
		cache:     make(map[string]resolvedSyntax, len(doc.DataTypes)),
	}
	for _, dataType := range doc.DataTypes {
		if strings.TrimSpace(dataType.Name) == "" {
			continue
		}
		parser.dataTypes[dataType.Name] = dataType
	}

	model := doc.Models[0]
	var objects []object
	var params []param
	for _, objectNode := range model.Objects {
		walkObject(model, objectNode, &parser, &objects, &params)
	}
	return objects, params, nil
}

func walkObject(model xmlModel, node xmlObject, parser *modelParser, objects *[]object, params *[]param) {
	name := strings.TrimSpace(node.Name)
	if name == "" {
		return
	}

	objectVersion := coalesceVersion(node.Version, modelVersionFromName(model.Name))
	objectDescription := cleanDescription(node.Description)
	*objects = append(*objects, object{
		Path:          name,
		MultiInstance: strings.Contains(name, "{i}.") || strings.EqualFold(strings.TrimSpace(node.MaxEntries), "unbounded"),
		SinceVersion:  objectVersion,
		Description:   objectDescription,
	})

	for _, parameterNode := range node.Parameters {
		paramName := strings.TrimSpace(parameterNode.Name)
		if paramName == "" {
			continue
		}

		resolved := parser.resolveParamSyntax(parameterNode.Syntax)
		fullPath := name + paramName
		paramVersion := coalesceVersion(parameterNode.Version, objectVersion, modelVersionFromName(model.Name))
		paramDescription := cleanDescription(parameterNode.Description)
		paramAccess := normalizeAccess(parameterNode.Access, parameterNode.Syntax.Hidden)

		*params = append(*params, param{
			Path:         fullPath,
			Type:         resolved.Type,
			Access:       paramAccess,
			SinceVersion: paramVersion,
			Description:  paramDescription,
			Limits:       resolved.Limits,
		})
	}

	for _, child := range node.Objects {
		walkObject(model, child, parser, objects, params)
	}
}

func (p *modelParser) resolveParamSyntax(s xmlSyntax) resolvedSyntax {
	switch {
	case s.List != nil:
		out := resolvedSyntax{
			Type:    typeList,
			Limits:  limitsFromListSyntax(*s.List),
			PathRef: s.List.PathRef != nil,
		}
		switch {
		case s.String != nil:
			overlayListElementConstraints(&out, resolvedSyntax{
				Type:    choosePrimitiveStringType(*s.String),
				Limits:  limitsFromStringSyntax(*s.String),
				PathRef: s.String.PathRef != nil,
			})
		case s.DataType != nil:
			item := p.resolveDataType(strings.TrimSpace(s.DataType.Ref))
			p.overlayDataTypeSyntax(&item, *s.DataType)
			overlayListElementConstraints(&out, item)
		}
		return finalizeResolvedSyntax(out)
	case s.DataType != nil:
		out := p.resolveDataType(strings.TrimSpace(s.DataType.Ref))
		p.overlayDataTypeSyntax(&out, *s.DataType)
		return finalizeResolvedSyntax(out)
	case s.String != nil:
		return finalizeResolvedSyntax(resolvedSyntax{
			Type:    choosePrimitiveStringType(*s.String),
			Limits:  limitsFromStringSyntax(*s.String),
			PathRef: s.String.PathRef != nil,
		})
	case s.Int != nil:
		return finalizeResolvedSyntax(resolvedSyntax{Type: typeInt, Limits: limitsFromIntegerRange(s.Int.Range)})
	case s.UnsignedInt != nil:
		return finalizeResolvedSyntax(resolvedSyntax{Type: typeUnsignedInt, Limits: limitsFromIntegerRange(s.UnsignedInt.Range)})
	case s.Long != nil:
		return finalizeResolvedSyntax(resolvedSyntax{Type: typeLong, Limits: limitsFromIntegerRange(s.Long.Range)})
	case s.UnsignedLong != nil:
		return finalizeResolvedSyntax(resolvedSyntax{Type: typeUnsignedLong, Limits: limitsFromIntegerRange(s.UnsignedLong.Range)})
	case s.Boolean != nil:
		return resolvedSyntax{Type: typeBoolean}
	case s.DateTime != nil:
		return resolvedSyntax{Type: typeDateTime}
	case s.Base64 != nil:
		return finalizeResolvedSyntax(resolvedSyntax{Type: typeBase64, Limits: limitsFromBinarySyntax(*s.Base64)})
	case s.HexBinary != nil:
		return finalizeResolvedSyntax(resolvedSyntax{Type: typeHexBinary, Limits: limitsFromBinarySyntax(*s.HexBinary)})
	case s.Decimal != nil:
		return finalizeResolvedSyntax(resolvedSyntax{Type: typeDecimal, Limits: limitsFromDecimalRange(s.Decimal.Range)})
	default:
		return resolvedSyntax{Type: typeString}
	}
}

func (p *modelParser) resolveDataType(name string) resolvedSyntax {
	name = strings.TrimSpace(name)
	if name == "" {
		return resolvedSyntax{Type: typeString}
	}
	if cached, ok := p.cache[name]; ok {
		return cached
	}

	dataType, ok := p.dataTypes[name]
	if !ok {
		out := finalizeResolvedSyntax(resolvedSyntax{Type: specialTypeForDataType(name, typeString)})
		p.cache[name] = out
		return out
	}

	out := resolvedSyntax{}
	if base := strings.TrimSpace(dataType.Base); base != "" {
		baseResolved := p.resolveDataType(base)
		out = mergeResolvedSyntax(out, baseResolved)
	}
	if syntax := dataType.Syntax; !isZeroSyntax(syntax) {
		out = mergeResolvedSyntax(out, p.resolveParamSyntax(syntax))
	}
	if out.Type == "" {
		out.Type = specialTypeForDataType(dataType.Name, typeString)
	}
	out.Type = specialTypeForDataType(dataType.Name, out.Type)
	out = finalizeResolvedSyntax(out)
	p.cache[name] = out
	return out
}

func (p *modelParser) overlayDataTypeSyntax(out *resolvedSyntax, dt xmlDataTypeSyntax) {
	if out == nil {
		return
	}
	overlay := resolvedSyntax{
		Limits:  limitsFromDataTypeSyntax(dt),
		PathRef: dt.PathRef != nil,
	}
	*out = mergeResolvedSyntax(*out, overlay)
}

func mergeResolvedSyntax(base, overlay resolvedSyntax) resolvedSyntax {
	out := base
	if overlay.Type != "" {
		out.Type = overlay.Type
	}
	out.PathRef = out.PathRef || overlay.PathRef
	out.Limits = mergeLimits(out.Limits, overlay.Limits)
	return out
}

func mergeLimits(base, overlay limits) limits {
	out := base
	if overlay.Min != nil {
		out.Min = overlay.Min
	}
	if overlay.Max != nil {
		out.Max = overlay.Max
	}
	if overlay.MinF != nil {
		out.MinF = overlay.MinF
	}
	if overlay.MaxF != nil {
		out.MaxF = overlay.MaxF
	}
	if overlay.MinLength != 0 {
		out.MinLength = overlay.MinLength
	}
	if overlay.MaxLength != 0 {
		out.MaxLength = overlay.MaxLength
	}
	if len(overlay.Enums) > 0 {
		out.Enums = append([]string(nil), overlay.Enums...)
	}
	if overlay.Pattern != "" {
		out.Pattern = overlay.Pattern
	}
	if overlay.MinItems != 0 {
		out.MinItems = overlay.MinItems
	}
	if overlay.MaxItems != 0 {
		out.MaxItems = overlay.MaxItems
	}
	return out
}

func finalizeResolvedSyntax(in resolvedSyntax) resolvedSyntax {
	if in.PathRef && in.Type != typeList {
		in.Type = typePathRef
	}
	if in.Type == "" {
		in.Type = typeString
	}
	return in
}

func overlayListElementConstraints(out *resolvedSyntax, item resolvedSyntax) {
	if out == nil {
		return
	}
	out.PathRef = out.PathRef || item.PathRef || item.Type == typePathRef
	if len(item.Limits.Enums) > 0 {
		out.Limits.Enums = append([]string(nil), item.Limits.Enums...)
	}
	if item.Limits.Pattern != "" {
		out.Limits.Pattern = item.Limits.Pattern
	}
}

func limitsFromStringSyntax(s xmlStringSyntax) limits {
	out := limits{}
	if s.Size != nil {
		out.MinLength = atoiDefault(s.Size.MinLength, 0)
		out.MaxLength = atoiDefault(s.Size.MaxLength, 0)
	}
	if len(s.Enumerations) > 0 {
		out.Enums = enumValues(s.Enumerations)
	}
	if len(s.Patterns) > 0 {
		out.Pattern = joinPatterns(s.Patterns)
	}
	return out
}

func limitsFromListSyntax(s xmlListSyntax) limits {
	out := limits{
		MinItems: atoiDefault(s.MinItems, 0),
		MaxItems: atoiDefault(s.MaxItems, 0),
	}
	if s.Size != nil {
		out.MinLength = atoiDefault(s.Size.MinLength, 0)
		out.MaxLength = atoiDefault(s.Size.MaxLength, 0)
	}
	if len(s.Enumerations) > 0 {
		out.Enums = enumValues(s.Enumerations)
	}
	return out
}

func limitsFromBinarySyntax(s xmlBinarySyntax) limits {
	if s.Size == nil {
		return limits{}
	}
	return limits{
		MinLength: atoiDefault(s.Size.MinLength, 0),
		MaxLength: atoiDefault(s.Size.MaxLength, 0),
	}
}

func limitsFromIntegerRange(r *xmlRange) limits {
	if r == nil {
		return limits{}
	}
	out := limits{}
	if value, ok := parseInt64(strings.TrimSpace(r.MinInclusive)); ok {
		out.Min = &value
	}
	if value, ok := parseInt64(strings.TrimSpace(r.MaxInclusive)); ok {
		out.Max = &value
	}
	return out
}

func limitsFromDecimalRange(r *xmlRange) limits {
	if r == nil {
		return limits{}
	}
	out := limits{}
	if value, ok := parseFloat64(strings.TrimSpace(r.MinInclusive)); ok {
		out.MinF = &value
	}
	if value, ok := parseFloat64(strings.TrimSpace(r.MaxInclusive)); ok {
		out.MaxF = &value
	}
	return out
}

func limitsFromDataTypeSyntax(dt xmlDataTypeSyntax) limits {
	out := limits{}
	if dt.Range != nil {
		merged := limitsFromIntegerRange(dt.Range)
		if merged.Min != nil || merged.Max != nil {
			out = mergeLimits(out, merged)
		} else {
			out = mergeLimits(out, limitsFromDecimalRange(dt.Range))
		}
	}
	if dt.Size != nil {
		out.MinLength = atoiDefault(dt.Size.MinLength, 0)
		out.MaxLength = atoiDefault(dt.Size.MaxLength, 0)
	}
	if len(dt.Enumerations) > 0 {
		out.Enums = enumValues(dt.Enumerations)
	}
	if len(dt.Patterns) > 0 {
		out.Pattern = joinPatterns(dt.Patterns)
	}
	return out
}

func joinPatterns(patterns []xmlPattern) string {
	if len(patterns) == 0 {
		return ""
	}
	parts := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		value := strings.TrimSpace(pattern.Value)
		if value == "" {
			continue
		}
		parts = append(parts, "(?:"+value+")")
	}
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(?:" + strings.Join(parts, "|") + ")"
}

func choosePrimitiveStringType(s xmlStringSyntax) paramType {
	if s.PathRef != nil {
		return typePathRef
	}
	return typeString
}

func specialTypeForDataType(name string, fallback paramType) paramType {
	switch strings.TrimSpace(name) {
	case "_AliasCommon", "_AliasCWMP", "_AliasUSP", "Alias":
		return typeAlias
	case "StatsCounter32", "StatsCounter64", "StatsCounter":
		return typeStatsCounter
	case "MACAddress", "PhysAddress":
		return typeMACAddress
	case "IPv4Address":
		return typeIPv4Address
	case "IPv6Address":
		return typeIPv6Address
	case "IPv4Prefix":
		return typeIPv4Prefix
	case "IPv6Prefix":
		return typeIPv6Prefix
	default:
		return fallback
	}
}

func normalizeAccess(raw, hidden string) access {
	switch strings.TrimSpace(raw) {
	case "readOnly":
		return readOnly
	case "writeOnly":
		return writeOnly
	case "readWrite":
		if strings.EqualFold(strings.TrimSpace(hidden), "true") {
			return writeOnly
		}
		return readWrite
	default:
		if strings.EqualFold(strings.TrimSpace(hidden), "true") {
			return writeOnly
		}
		return readOnly
	}
}

func modelVersionFromName(name string) string {
	parts := strings.Split(strings.TrimSpace(name), ":")
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func inferFileVersion(fileName string) string {
	m := fileVersionPattern.FindStringSubmatch(fileName)
	if len(m) != 4 {
		return ""
	}
	return m[1] + "." + m[2] + "." + m[3]
}

func cleanDescription(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	fields := strings.Fields(raw)
	return strings.Join(fields, " ")
}

func coalesceVersion(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(strings.TrimPrefix(value, "v"))
		if value != "" {
			return value
		}
	}
	return ""
}

func parseInt64(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseFloat64(value string) (float64, bool) {
	if value == "" {
		return 0, false
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func atoiDefault(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func enumValues(values []xmlEnumeration) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value.Value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isZeroSyntax(s xmlSyntax) bool {
	return s.DataType == nil &&
		s.String == nil &&
		s.Int == nil &&
		s.UnsignedInt == nil &&
		s.Long == nil &&
		s.UnsignedLong == nil &&
		s.Boolean == nil &&
		s.DateTime == nil &&
		s.Base64 == nil &&
		s.HexBinary == nil &&
		s.Decimal == nil &&
		s.List == nil &&
		s.Hidden == ""
}

// typeConstName maps a paramType to the Go constant name used in models.go.
func typeConstName(t paramType) string {
	switch t {
	case typeString:
		return "TypeString"
	case typeInt:
		return "TypeInt"
	case typeUnsignedInt:
		return "TypeUnsignedInt"
	case typeLong:
		return "TypeLong"
	case typeUnsignedLong:
		return "TypeUnsignedLong"
	case typeBoolean:
		return "TypeBoolean"
	case typeDateTime:
		return "TypeDateTime"
	case typeBase64:
		return "TypeBase64"
	case typeHexBinary:
		return "TypeHexBinary"
	case typeDecimal:
		return "TypeDecimal"
	case typeIPv4Address:
		return "TypeIPv4Address"
	case typeIPv6Address:
		return "TypeIPv6Address"
	case typeIPv4Prefix:
		return "TypeIPv4Prefix"
	case typeIPv6Prefix:
		return "TypeIPv6Prefix"
	case typeMACAddress:
		return "TypeMACAddress"
	case typeAlias:
		return "TypeAlias"
	case typeStatsCounter:
		return "TypeStatsCounter"
	case typePathRef:
		return "TypePathRef"
	case typeList:
		return "TypeList"
	default:
		return fmt.Sprintf("ParamType(%q)", string(t))
	}
}

// accessConstName maps an access value to the Go constant name.
func accessConstName(a access) string {
	switch a {
	case readOnly:
		return "ReadOnly"
	case readWrite:
		return "ReadWrite"
	case writeOnly:
		return "WriteOnly"
	default:
		return fmt.Sprintf("Access(%q)", string(a))
	}
}

// generateGoSource generates the Go source text for the model data.
func generateGoSource(pkg, sourcePath string, objects []object, params []param) ([]byte, error) {
	fileName := filepath.Base(sourcePath)
	modelVersion := inferFileVersion(fileName)

	var w bytes.Buffer

	fmt.Fprintf(&w, "// Code generated by cmd/modelgen; DO NOT EDIT.\n")
	fmt.Fprintf(&w, "//\n")
	fmt.Fprintf(&w, "// Source: BroadbandForum/usp-data-models %s\n", fileName)
	fmt.Fprintf(&w, "// URL: https://github.com/BroadbandForum/usp-data-models/blob/master/%s\n", fileName)
	if modelVersion != "" {
		fmt.Fprintf(&w, "// Model version: %s\n", modelVersion)
	}
	fmt.Fprintf(&w, "\n")
	fmt.Fprintf(&w, "package %s\n\n", pkg)

	// Objects slice
	fmt.Fprintf(&w, "var uspModelObjects = []Object{\n")
	for _, obj := range objects {
		fmt.Fprintf(&w, "\t{\n")
		fmt.Fprintf(&w, "\t\tPath: %s,\n", strconv.Quote(obj.Path))
		if obj.MultiInstance {
			fmt.Fprintf(&w, "\t\tMultiInstance: true,\n")
		}
		if obj.SinceVersion != "" {
			fmt.Fprintf(&w, "\t\tSinceVersion: %s,\n", strconv.Quote(obj.SinceVersion))
		}
		if obj.Description != "" {
			fmt.Fprintf(&w, "\t\tDescription: %s,\n", strconv.Quote(obj.Description))
		}
		fmt.Fprintf(&w, "\t},\n")
	}
	fmt.Fprintf(&w, "}\n\n")

	// Params slice
	fmt.Fprintf(&w, "var uspModelParams = []Param{\n")
	for _, p := range params {
		fmt.Fprintf(&w, "\t{\n")
		fmt.Fprintf(&w, "\t\tPath: %s,\n", strconv.Quote(p.Path))
		fmt.Fprintf(&w, "\t\tType: %s,\n", typeConstName(p.Type))
		fmt.Fprintf(&w, "\t\tAccess: %s,\n", accessConstName(p.Access))
		if p.SinceVersion != "" {
			fmt.Fprintf(&w, "\t\tSinceVersion: %s,\n", strconv.Quote(p.SinceVersion))
		}
		if p.Description != "" {
			fmt.Fprintf(&w, "\t\tDescription: %s,\n", strconv.Quote(p.Description))
		}
		if !isZeroLimits(p.Limits) {
			fmt.Fprintf(&w, "\t\tLimits: Limits{\n")
			if p.Limits.Min != nil {
				fmt.Fprintf(&w, "\t\t\tMin: iptr(%d),\n", *p.Limits.Min)
			}
			if p.Limits.Max != nil {
				fmt.Fprintf(&w, "\t\t\tMax: iptr(%d),\n", *p.Limits.Max)
			}
			if p.Limits.MinF != nil {
				fmt.Fprintf(&w, "\t\t\tMinF: fptr(%v),\n", *p.Limits.MinF)
			}
			if p.Limits.MaxF != nil {
				fmt.Fprintf(&w, "\t\t\tMaxF: fptr(%v),\n", *p.Limits.MaxF)
			}
			if p.Limits.MinLength != 0 {
				fmt.Fprintf(&w, "\t\t\tMinLength: %d,\n", p.Limits.MinLength)
			}
			if p.Limits.MaxLength != 0 {
				fmt.Fprintf(&w, "\t\t\tMaxLength: %d,\n", p.Limits.MaxLength)
			}
			if len(p.Limits.Enums) > 0 {
				fmt.Fprintf(&w, "\t\t\tEnums: []string{")
				for i, e := range p.Limits.Enums {
					if i > 0 {
						fmt.Fprintf(&w, ", ")
					}
					fmt.Fprintf(&w, "%s", strconv.Quote(e))
				}
				fmt.Fprintf(&w, "},\n")
			}
			if p.Limits.Pattern != "" {
				fmt.Fprintf(&w, "\t\t\tPattern: %s,\n", strconv.Quote(p.Limits.Pattern))
			}
			if p.Limits.MinItems != 0 {
				fmt.Fprintf(&w, "\t\t\tMinItems: %d,\n", p.Limits.MinItems)
			}
			if p.Limits.MaxItems != 0 {
				fmt.Fprintf(&w, "\t\t\tMaxItems: %d,\n", p.Limits.MaxItems)
			}
			fmt.Fprintf(&w, "\t\t},\n")
		}
		fmt.Fprintf(&w, "\t},\n")
	}
	fmt.Fprintf(&w, "}\n")

	formatted, err := format.Source(w.Bytes())
	if err != nil {
		// Return the unformatted source alongside the error so the caller can
		// write it for debugging.
		return w.Bytes(), fmt.Errorf("gofmt: %w", err)
	}
	return formatted, nil
}

func isZeroLimits(l limits) bool {
	return l.Min == nil &&
		l.Max == nil &&
		l.MinF == nil &&
		l.MaxF == nil &&
		l.MinLength == 0 &&
		l.MaxLength == 0 &&
		len(l.Enums) == 0 &&
		l.Pattern == "" &&
		l.MinItems == 0 &&
		l.MaxItems == 0
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
