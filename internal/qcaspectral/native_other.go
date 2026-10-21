//go:build !(linux && cgo && qsdk)

package qcaspectral

// Supported reports whether this binary carries the native QCA backend.
// Build with CGO_ENABLED=1 -tags qsdk on Linux to enable it.
const Supported = false

type unsupportedDriver struct{}

func newDriver() driver { return unsupportedDriver{} }

func (unsupportedDriver) Probe(string) (Caps, error)         { return Caps{}, ErrUnsupported }
func (unsupportedDriver) IsActive(string, int) (bool, error) { return false, ErrUnsupported }
func (unsupportedDriver) SetScan(string, int, bool) error    { return ErrUnsupported }
func (unsupportedDriver) OpenSamples() (sampleSource, error) { return nil, ErrUnsupported }
