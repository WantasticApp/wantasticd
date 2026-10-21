//go:build !linux

package qcaspectral

// Supported reports whether this binary carries the native QCA backend.
// QCA radios only exist on Linux targets.
const Supported = false

type unsupportedDriver struct{}

func newDriver() driver { return unsupportedDriver{} }

func (unsupportedDriver) Probe(string) (Caps, error)          { return Caps{}, ErrUnsupported }
func (unsupportedDriver) IsActive(string, Caps) (bool, error) { return false, ErrUnsupported }
func (unsupportedDriver) SetScan(string, Caps, bool) error    { return ErrUnsupported }
func (unsupportedDriver) OpenSamples() (sampleSource, error)  { return nil, ErrUnsupported }
