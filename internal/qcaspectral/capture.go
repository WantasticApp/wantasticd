package qcaspectral

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrUnsupported = errors.New("qcaspectral: native QCA spectral support is not available on this platform")
	// ErrNoRadioNetdev means the host has no QCA radio netdev (wifiN) at all,
	// which is the only case reported as Unsupported at the model root.
	ErrNoRadioNetdev = errors.New("no QCA radio netdev (wifiN) found")
)

// Caps is the driver spectral capability report.
type Caps struct {
	PhyDiag  bool
	Radar    bool
	Spectral bool
	Advanced bool
	// HardwareGeneration is only reported by cmn_dev drivers; 0 when unknown.
	HardwareGeneration uint32
	// ControlPath is ControlPathVendor or ControlPathIoctl.
	ControlPath string
	// IoctlBase is the DFS_LAST_IOCTL value the ath_diag path answered on.
	IoctlBase int
	// VendorTarget is the netdev the nl80211 vendor command answered on.
	VendorTarget string
	// DataTransport is TransportNetlink, TransportRelay, or "" when the driver
	// does not report it.
	DataTransport string
}

// Radio is a QCA radio netdev. ProbeError is set, and Caps.Spectral false,
// when no control path accepted the spectral capability probe.
type Radio struct {
	Interface  string
	MAC        net.HardwareAddr
	Caps       Caps
	ProbeError string
}

// Result is one capture window on one radio.
type Result struct {
	Layout  Layout
	Passive bool
	Samples []Sample
	// Dropped counts datagrams attributed to this radio that could not be
	// decoded, or whose bin count disagreed with the first accepted sample.
	Dropped   int
	LastError string
	Started   time.Time
	Completed time.Time
}

type driver interface {
	Probe(ifname string) (Caps, error)
	IsActive(ifname string, caps Caps) (bool, error)
	SetScan(ifname string, caps Caps, start bool) error
	OpenSamples() (sampleSource, error)
}

type sampleSource interface {
	Recv(timeoutMillis int) ([]byte, error)
	Close() error
}

// decodeCaps validates the ath_spectral_caps / spectral_caps prefix. The four
// leading u8 flags are booleans in every release, so anything else means the
// ioctl ID landed on a different command.
func decodeCaps(raw []byte, base int) (Caps, bool) {
	if len(raw) < 4 {
		return Caps{}, false
	}
	for _, b := range raw[:4] {
		if b > 1 {
			return Caps{}, false
		}
	}
	caps := Caps{
		PhyDiag:     raw[0] == 1,
		Radar:       raw[1] == 1,
		Spectral:    raw[2] == 1,
		Advanced:    raw[3] == 1,
		ControlPath: ControlPathIoctl,
		IoctlBase:   base,
	}
	if !caps.Spectral {
		return Caps{}, false
	}
	if base >= 29 && len(raw) >= 8 {
		caps.HardwareGeneration = nativeUint32(raw[4:8])
	}
	return caps, true
}

var qcaRadioName = regexp.MustCompile(`^wifi[0-9]+$`)

// DiscoverRadios probes every QCA radio netdev (wifiN) under netClassDir and
// returns a row for each one, including radios whose probe failed, so the
// failure reason is visible to the controller. VAPs (athN) are only used as
// vendor-command targets for their parent radio, never probed on their own.
func DiscoverRadios(netClassDir string) ([]Radio, error) {
	if !Supported {
		return nil, ErrUnsupported
	}
	return discoverRadios(newDriver(), netClassDir)
}

func discoverRadios(d driver, netClassDir string) ([]Radio, error) {
	if strings.TrimSpace(netClassDir) == "" {
		netClassDir = "/sys/class/net"
	}
	entries, err := os.ReadDir(netClassDir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if qcaRadioName.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w under %s", ErrNoRadioNetdev, netClassDir)
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})
	radios := make([]Radio, 0, len(names))
	for _, name := range names {
		mac, _ := net.ParseMAC(strings.TrimSpace(readFile(filepath.Join(netClassDir, name, "address"))))
		radio := Radio{Interface: name, MAC: mac}
		caps, err := d.Probe(name)
		if err != nil {
			radio.Caps = Caps{ControlPath: ControlPathNone}
			radio.ProbeError = err.Error()
		} else {
			radio.Caps = caps
		}
		radios = append(radios, radio)
	}
	return radios, nil
}

// CaptureOptions bounds one capture window.
type CaptureOptions struct {
	Window     time.Duration
	MaxSamples int
	// KnownMACs are the MACs of every discovered radio. A sample whose MAC is
	// not in this set is unattributable; it is accepted only when this capture
	// started the scan itself, since only this radio is then known to scan.
	KnownMACs []net.HardwareAddr
	Now       func() time.Time
}

// Capture collects samples for one radio. If spectral scan is already active
// (athssd, ICM or EACS own it), the capture only listens and leaves the scan
// state alone; otherwise it starts the scan and always stops it afterwards.
func Capture(ctx context.Context, radio Radio, opts CaptureOptions) (Result, error) {
	if !Supported {
		return Result{}, ErrUnsupported
	}
	return capture(ctx, newDriver(), radio, opts)
}

func capture(ctx context.Context, d driver, radio Radio, opts CaptureOptions) (result Result, err error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if opts.Window <= 0 {
		opts.Window = time.Second
	}
	if opts.MaxSamples <= 0 {
		opts.MaxSamples = 64
	}
	result = Result{Layout: LayoutUnknown, Started: now().UTC()}
	defer func() {
		result.Completed = now().UTC()
		if err != nil && result.LastError == "" {
			result.LastError = err.Error()
		}
	}()
	if !radio.Caps.Spectral {
		return result, fmt.Errorf("radio %s has no usable spectral control path", radio.Interface)
	}

	// Open the receiver before starting the scan so the first reports are
	// not lost.
	src, err := d.OpenSamples()
	if err != nil {
		return result, err
	}
	defer src.Close()

	active, err := d.IsActive(radio.Interface, radio.Caps)
	if err != nil {
		return result, err
	}
	result.Passive = active
	if active && radio.Caps.DataTransport == TransportRelay {
		return result, errors.New("another consumer owns the scan with relay (debugfs) transport; netlink samples are not available")
	}
	if !active {
		if err := d.SetScan(radio.Interface, radio.Caps, true); err != nil {
			return result, err
		}
		defer func() {
			if stopErr := d.SetScan(radio.Interface, radio.Caps, false); stopErr != nil && result.LastError == "" {
				result.LastError = stopErr.Error()
			}
		}()
	}

	deadline := now().Add(opts.Window)
	binCount := 0
	for len(result.Samples) < opts.MaxSamples {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			break
		}
		wait := remaining
		if wait > 200*time.Millisecond {
			wait = 200 * time.Millisecond
		}
		datagram, err := src.Recv(int(wait / time.Millisecond))
		if err != nil {
			return result, err
		}
		if len(datagram) == 0 {
			continue
		}
		sample, err := ParseNetlink(datagram, binary.NativeEndian)
		if errors.Is(err, ErrNotSpectral) {
			continue
		}
		if err != nil {
			// Undecodable messages cannot be attributed by MAC; count them
			// only when this capture is the sole scan owner.
			if !result.Passive {
				result.Dropped++
				result.LastError = err.Error()
			}
			continue
		}
		if !attributable(sample.MAC, radio.MAC, opts.KnownMACs, result.Passive) {
			continue
		}
		if binCount == 0 {
			binCount = len(sample.Bins)
		}
		if len(sample.Bins) != binCount {
			result.Dropped++
			continue
		}
		result.Layout = sample.Layout
		result.Samples = append(result.Samples, sample)
	}
	if len(result.Samples) == 0 && result.LastError == "" {
		result.LastError = "no spectral SAMP messages arrived on NETLINK_ATHEROS group 1 during the capture window"
	}
	return result, nil
}

func attributable(sampleMAC, radioMAC net.HardwareAddr, known []net.HardwareAddr, passive bool) bool {
	if len(radioMAC) == 6 && bytes.Equal(sampleMAC, radioMAC) {
		return true
	}
	for _, mac := range known {
		if bytes.Equal(sampleMAC, mac) {
			return false
		}
	}
	return !passive
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func nativeUint32(b []byte) uint32 { return binary.NativeEndian.Uint32(b) }
func nativeUint64(b []byte) uint64 { return binary.NativeEndian.Uint64(b) }
