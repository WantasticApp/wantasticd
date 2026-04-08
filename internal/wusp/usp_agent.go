package wusp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

var (
	ErrUSPPathNotFound        = errors.New("wusp: path not found")
	ErrUSPTransferUnsupported = errors.New("wusp: transfer handler not configured")
)

// USPTransferRequest describes a transport-neutral upload/download request.
// The future WireGuard control-plane can use this for command metadata while
// leaving large/bulk transfer policy to a pluggable handler.
type USPTransferRequest struct {
	Path        string
	URI         string
	Filename    string
	ContentType string
	Payload     []byte
	Metadata    map[string]string
}

// USPTransferResult reports the outcome of a delegated upload/download action.
type USPTransferResult struct {
	Path     string
	URI      string
	Bytes    int64
	Metadata map[string]string
}

type USPTransferHandler func(context.Context, USPTransferRequest) (USPTransferResult, error)

// USPAgentOptions configures a transport-agnostic USPAgent state machine.
type USPAgentOptions struct {
	FillProfile     FillProfile
	UploadHandler   USPTransferHandler
	DownloadHandler USPTransferHandler
	Collector       DataCollector
	Setter          DataSetter
}

// USPAgent is a transport-agnostic in-process USP state surface.
// It intentionally does not assume stream semantics. Control operations are
// modelled as discrete requests over parameter paths, which maps cleanly onto
// both USP Records and WireGuard's packet-oriented transport.
type USPAgent struct {
	mu              sync.RWMutex
	fillProfile     FillProfile
	uploadHandler   USPTransferHandler
	downloadHandler USPTransferHandler
	collector       DataCollector
	setter          DataSetter
	values          map[string]Field
}

func NewUSPAgent(opts USPAgentOptions) *USPAgent {
	return &USPAgent{
		fillProfile:     normalizeFillProfile(opts.FillProfile),
		uploadHandler:   opts.UploadHandler,
		downloadHandler: opts.DownloadHandler,
		collector:       opts.Collector,
		setter:          opts.Setter,
		values:          make(map[string]Field),
	}
}

// Bootstrap seeds the agent with schema-derived values for every known param.
func (a *USPAgent) Bootstrap(opts FillOptions) error {
	msg, err := BuildFilledMessage(FillOptions{
		Profile:   coalesceFillProfile(opts.Profile, a.fillProfile),
		DeviceID:  opts.DeviceID,
		Timestamp: opts.Timestamp,
	})
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if opts.Overwrite {
		a.values = make(map[string]Field, len(msg.Fields))
	}

	for _, field := range msg.Fields {
		a.values[field.Path] = cloneField(field)
	}

	return nil
}

// Snapshot returns the stored state as a stable, path-sorted message.
func (a *USPAgent) Snapshot() *Message {
	values := a.snapshotValues()
	if a.collector != nil {
		if msg, err := a.collector.Collect(context.Background()); err == nil {
			mergeMessageFields(values, msg)
		}
	}
	return buildSnapshotMessage(values)
}

// Get returns stored values for the requested parameter or object paths.
// Param paths return a single field, while object paths ending with "." return
// all stored descendant params beneath that object instance/pattern.
func (a *USPAgent) Get(paths ...string) (*Message, error) {
	values := a.snapshotValues()
	if a.collector != nil {
		msg, err := a.collector.Collect(context.Background(), paths...)
		if err != nil {
			return nil, err
		}
		mergeMessageFields(values, msg)
	}

	if len(paths) == 0 {
		return buildSnapshotMessage(values), nil
	}

	return filterValuesForPaths(values, paths...)
}

// Set validates and stores one parameter value.
func (a *USPAgent) Set(path string, value Value) error {
	path = strings.TrimSpace(path)
	field := Field{Path: path, Val: value}
	if err := ValidateFieldFast(field); err != nil {
		return err
	}

	if id, ok := globalRegistry.IDFor(path); ok {
		field.id = id
	}

	if a.setter != nil {
		if err := a.setter.Set(context.Background(), path, cloneValue(value)); err != nil && !errors.Is(err, ErrUSPPathUnsupported) {
			return err
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.values[path] = cloneField(field)
	return nil
}

// Delete removes stored params or object subtrees from the agent state.
func (a *USPAgent) Delete(paths ...string) error {
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			return &ValidationError{Reason: "empty delete path"}
		}

		handledBySetter := false
		if a.setter != nil {
			err := a.setter.Delete(context.Background(), path)
			switch {
			case err == nil:
				handledBySetter = true
			case errors.Is(err, ErrUSPPathUnsupported):
			default:
				return err
			}
		}

		a.mu.Lock()
		removed := deletePathLocked(a.values, path)
		a.mu.Unlock()
		if !removed && !handledBySetter {
			return fmt.Errorf("%w: %s", ErrUSPPathNotFound, path)
		}
	}

	return nil
}

func (a *USPAgent) snapshotValues() map[string]Field {
	a.mu.RLock()
	defer a.mu.RUnlock()

	values := make(map[string]Field, len(a.values))
	for path, field := range a.values {
		values[path] = cloneField(field)
	}
	return values
}

// Upload delegates transfer execution to the configured upload handler.
func (a *USPAgent) Upload(ctx context.Context, req USPTransferRequest) (USPTransferResult, error) {
	if err := validateTransferRequest(req); err != nil {
		return USPTransferResult{}, err
	}
	if a.uploadHandler == nil {
		return USPTransferResult{}, ErrUSPTransferUnsupported
	}
	return a.uploadHandler(ctx, cloneTransferRequest(req))
}

// Download delegates transfer execution to the configured download handler.
func (a *USPAgent) Download(ctx context.Context, req USPTransferRequest) (USPTransferResult, error) {
	if err := validateTransferRequest(req); err != nil {
		return USPTransferResult{}, err
	}
	if a.downloadHandler == nil {
		return USPTransferResult{}, ErrUSPTransferUnsupported
	}
	return a.downloadHandler(ctx, cloneTransferRequest(req))
}

func coalesceFillProfile(primary, fallback FillProfile) FillProfile {
	if normalizeFillProfile(primary) != FillProfileRealistic || primary == FillProfileMaxCompressible {
		return normalizeFillProfile(primary)
	}
	if primary == "" {
		return normalizeFillProfile(fallback)
	}
	return normalizeFillProfile(primary)
}

func buildSnapshotMessage(values map[string]Field) *Message {
	fields := sortedStoredFields(values)
	msg := &Message{
		Fields: make([]Field, 0, len(fields)),
	}
	for _, field := range fields {
		msg.Fields = append(msg.Fields, cloneField(field))
	}
	return msg
}

func filterValuesForPaths(values map[string]Field, paths ...string) (*Message, error) {
	out := &Message{Fields: make([]Field, 0)}
	seen := make(map[string]struct{})

	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			return nil, &ValidationError{Reason: "empty get path"}
		}

		if isObjectPath(path) {
			matched := false
			for _, field := range sortedStoredFields(values) {
				if strings.HasPrefix(field.Path, path) {
					if _, ok := seen[field.Path]; ok {
						continue
					}
					out.Fields = append(out.Fields, cloneField(field))
					seen[field.Path] = struct{}{}
					matched = true
				}
			}
			if !matched {
				return nil, fmt.Errorf("%w: %s", ErrUSPPathNotFound, path)
			}
			continue
		}

		field, ok := values[path]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUSPPathNotFound, path)
		}
		if _, ok := seen[path]; ok {
			continue
		}
		out.Fields = append(out.Fields, cloneField(field))
		seen[path] = struct{}{}
	}

	sort.Slice(out.Fields, func(i, j int) bool {
		return out.Fields[i].Path < out.Fields[j].Path
	})
	return out, nil
}

func mergeMessageFields(values map[string]Field, msg *Message) {
	if msg == nil {
		return
	}
	for _, field := range msg.Fields {
		values[field.Path] = cloneField(field)
	}
}

func deletePathLocked(values map[string]Field, path string) bool {
	if isObjectPath(path) {
		removed := false
		for key := range values {
			if strings.HasPrefix(key, path) {
				delete(values, key)
				removed = true
			}
		}
		return removed
	}

	if _, ok := values[path]; !ok {
		return false
	}
	delete(values, path)
	return true
}

func sortedStoredFields(values map[string]Field) []Field {
	fields := make([]Field, 0, len(values))
	for _, field := range values {
		fields = append(fields, field)
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Path < fields[j].Path
	})
	return fields
}

func cloneField(field Field) Field {
	cloned := Field{
		id:   field.id,
		Path: field.Path,
		Val:  cloneValue(field.Val),
	}
	return cloned
}

func cloneValue(value Value) Value {
	cloned := Value{
		Tag:  value.Tag,
		ival: value.ival,
		fval: value.fval,
	}
	if len(value.blob) > 0 {
		cloned.blob = append([]byte(nil), value.blob...)
	}
	if len(value.list) > 0 {
		cloned.list = make([]Value, len(value.list))
		for i := range value.list {
			cloned.list[i] = cloneValue(value.list[i])
		}
	}
	return cloned
}

func cloneTransferRequest(req USPTransferRequest) USPTransferRequest {
	cloned := req
	if len(req.Payload) > 0 {
		cloned.Payload = append([]byte(nil), req.Payload...)
	}
	if len(req.Metadata) > 0 {
		cloned.Metadata = make(map[string]string, len(req.Metadata))
		for key, value := range req.Metadata {
			cloned.Metadata[key] = value
		}
	}
	return cloned
}

func validateTransferRequest(req USPTransferRequest) error {
	if strings.TrimSpace(req.Path) == "" {
		return &ValidationError{Reason: "transfer path is required"}
	}

	if !isObjectPath(req.Path) {
		if _, _, ok := lookupSafeParam(req.Path); !ok {
			return &ValidationError{Path: req.Path, Reason: "unknown transfer path"}
		}
	}

	return nil
}

func isObjectPath(path string) bool {
	return strings.HasSuffix(strings.TrimSpace(path), ".")
}
