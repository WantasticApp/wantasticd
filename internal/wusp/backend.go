package wusp

import (
	"context"
	"errors"
)

var ErrUSPPathUnsupported = errors.New("wusp: path unsupported")

// DataCollector returns live device values for a subset of WUSP paths.
// Unsupported paths are ignored rather than treated as fatal errors so the
// caller can merge live fields with cached or synthetic values.
type DataCollector interface {
	Collect(context.Context, ...string) (*Message, error)
}

// DataSetter applies WUSP parameter changes onto a device backend.
// Unsupported paths should return ErrUSPPathUnsupported.
type DataSetter interface {
	Set(context.Context, string, Value) error
	Delete(context.Context, ...string) error
}

// DataBackend combines collection and mutation for a concrete platform.
type DataBackend interface {
	DataCollector
	DataSetter
}
