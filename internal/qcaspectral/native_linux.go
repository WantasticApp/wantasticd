//go:build linux

package qcaspectral

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Supported reports whether this binary carries the native QCA backend. The
// backend is pure Go (ioctl + netlink), so every Linux build has it.
const Supported = true

const (
	// NETLINK_ATHEROS / SPECTRAL_NETLINK = NETLINK_GENERIC + 1 in both
	// qca-wifi 10.x spectral_data.h and cmn_dev os_if_spectral_netlink.h.
	netlinkAtheros   = unix.NETLINK_GENERIC + 1
	siocgathphyerr   = unix.SIOCDEVPRIVATE + 5 // if_athioctl.h, Linux
	athDiagDyn       = 0x8000
	vendorCmdTimeout = 3 * time.Second

	// Spectral ioctl sub-commands as offsets from DFS_LAST_IOCTL.
	ioctlActivateScan = 6
	ioctlStopScan     = 7
	ioctlIsActive     = 9
	ioctlGetCaps      = 16
)

// Spectral ioctl IDs are offsets from DFS_LAST_IOCTL, which moved from 22
// (qca-wifi 10.2) to 29 (cmn_dev). Probing the newer base first is safe: on a
// legacy driver 29+16 is an undefined spectral command, and 22+16 on a cmn
// driver is the read-only IS_ACTIVE, which fails capability validation.
var dfsLastIoctlCandidates = []int{29, 22}

type vendorScan struct {
	cookie       uint64
	haveCookie   bool
	restoreRelay bool
}

type nativeDriver struct {
	netClassDir string
	mu          sync.Mutex
	scans       map[string]vendorScan
}

// One driver instance keeps the START cookie between Capture's start and
// stop calls.
var sharedDriver = &nativeDriver{netClassDir: "/sys/class/net", scans: make(map[string]vendorScan)}

func newDriver() driver { return sharedDriver }

// Probe tries the cfg80211 vendor path first (QSDK 11/12 default, and safe
// for 32-bit userland on 64-bit kernels), then the ath_diag ioctl path used by
// qca-wifi 10.x. The returned error names every attempt.
func (d *nativeDriver) Probe(ifname string) (Caps, error) {
	var attempts []string
	caps, err := d.probeVendor(ifname)
	if err == nil {
		return caps, nil
	}
	attempts = append(attempts, ControlPathVendor+": "+err.Error())
	caps, err = probeIoctl(ifname)
	if err == nil {
		return caps, nil
	}
	attempts = append(attempts, ControlPathIoctl+": "+err.Error())
	return Caps{}, errors.New(strings.Join(attempts, "; "))
}

func (d *nativeDriver) IsActive(ifname string, caps Caps) (bool, error) {
	if caps.ControlPath == ControlPathVendor {
		attrs, err := vendorCommand(caps.VendorTarget, vendorSubcmdSpectralGetStatus, nil)
		if err != nil {
			return false, fmt.Errorf("spectral get_status on %s: %w", caps.VendorTarget, err)
		}
		return attrs.has(attrStatusIsActive), nil
	}
	out, err := athDiag(ifname, uint16(caps.IoctlBase+ioctlIsActive)|athDiagDyn, nil, 4)
	if err != nil {
		return false, fmt.Errorf("spectral is_active ioctl on %s: %w", ifname, err)
	}
	return nativeUint32(out) != 0, nil
}

func (d *nativeDriver) SetScan(ifname string, caps Caps, start bool) error {
	if caps.ControlPath == ControlPathVendor {
		if start {
			return d.vendorStart(ifname, caps)
		}
		return d.vendorStop(ifname, caps)
	}
	op := ioctlStopScan
	if start {
		op = ioctlActivateScan
	}
	if _, err := athDiag(ifname, uint16(caps.IoctlBase+op)|athDiagDyn, make([]byte, 4), 0); err != nil {
		return fmt.Errorf("spectral scan control ioctl on %s: %w", ifname, err)
	}
	return nil
}

func (d *nativeDriver) vendorStart(ifname string, caps Caps) error {
	// Only this agent's netlink transport is readable; switch a relay-mode
	// radio to netlink for the capture and restore relay afterwards.
	forceNetlink := caps.DataTransport == TransportRelay
	data, err := encodeStartRequest(forceNetlink)
	if err != nil {
		return err
	}
	attrs, err := vendorCommand(caps.VendorTarget, vendorSubcmdSpectralStart, data)
	if err != nil {
		if detail := vendorErrorDetail(attrs); detail != "" {
			err = fmt.Errorf("%w (%s)", err, detail)
		}
		return fmt.Errorf("spectral scan start on %s: %w", caps.VendorTarget, err)
	}
	scan := vendorScan{restoreRelay: forceNetlink}
	if cookie, ok := attrs.uint64(attrSpectralScanCookie); ok {
		scan.cookie, scan.haveCookie = cookie, true
	}
	d.mu.Lock()
	d.scans[ifname] = scan
	d.mu.Unlock()
	return nil
}

func (d *nativeDriver) vendorStop(ifname string, caps Caps) error {
	d.mu.Lock()
	scan := d.scans[ifname]
	delete(d.scans, ifname)
	d.mu.Unlock()
	data, err := encodeStopRequest(scan.cookie, scan.haveCookie)
	if err != nil {
		return err
	}
	if _, err := vendorCommand(caps.VendorTarget, vendorSubcmdSpectralStop, data); err != nil {
		return fmt.Errorf("spectral scan stop on %s: %w", caps.VendorTarget, err)
	}
	if scan.restoreRelay {
		// SPECTRAL_SCAN_START with REQUEST_TYPE_CONFIG only reconfigures.
		if data, err := encodeTransportConfig(transportRelay); err == nil {
			if _, err := vendorCommand(caps.VendorTarget, vendorSubcmdSpectralStart, data); err != nil {
				return fmt.Errorf("restore relay transport on %s: %w", caps.VendorTarget, err)
			}
		}
	}
	return nil
}

func (d *nativeDriver) probeVendor(ifname string) (Caps, error) {
	var failures []string
	for _, target := range d.vendorTargets(ifname) {
		attrs, err := vendorCommand(target, vendorSubcmdSpectralGetCaps, nil)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", target, err))
			continue
		}
		caps := capsFromVendor(attrs)
		if !caps.Spectral {
			failures = append(failures, fmt.Sprintf("%s: driver reports no spectral capability", target))
			continue
		}
		caps.VendorTarget = target
		if cfg, err := vendorCommand(target, vendorSubcmdSpectralGetConfig, nil); err == nil {
			caps.DataTransport = transportFromVendor(cfg)
		}
		return caps, nil
	}
	if len(failures) == 0 {
		return Caps{}, errors.New("no vendor command target")
	}
	return Caps{}, errors.New(strings.Join(failures, ", "))
}

// vendorTargets lists the radio netdev itself, then its VAPs. QSDK drivers
// register spectral vendor commands on the radio (wifiN), but some builds
// only accept them on a VAP whose sysfs "parent" names the radio.
func (d *nativeDriver) vendorTargets(radio string) []string {
	targets := []string{radio}
	entries, err := os.ReadDir(d.netClassDir)
	if err != nil {
		return targets
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == radio || qcaRadioName.MatchString(name) {
			continue
		}
		if strings.TrimSpace(readFile(filepath.Join(d.netClassDir, name, "parent"))) == radio {
			targets = append(targets, name)
		}
	}
	return targets
}

// vendorCommand sends NL80211_CMD_VENDOR (OUI_QCA, subcmd) to ifname and
// returns the attributes nested in the reply's NL80211_ATTR_VENDOR_DATA.
func vendorCommand(ifname string, subcmd uint32, data []byte) (vendorAttrs, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("dial generic netlink: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(vendorCmdTimeout))
	family, err := conn.GetFamily("nl80211")
	if err != nil {
		return nil, fmt.Errorf("resolve nl80211 family: %w", err)
	}
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
	ae.Uint32(unix.NL80211_ATTR_VENDOR_ID, ouiQCA)
	ae.Uint32(unix.NL80211_ATTR_VENDOR_SUBCMD, subcmd)
	if data != nil {
		ae.Bytes(unix.NL80211_ATTR_VENDOR_DATA, data)
	}
	body, err := ae.Encode()
	if err != nil {
		return nil, err
	}
	replies, err := conn.Execute(genetlink.Message{
		Header: genetlink.Header{Command: unix.NL80211_CMD_VENDOR},
		Data:   body,
	}, family.ID, netlink.Request|netlink.Acknowledge)
	if err != nil {
		return nil, err
	}
	out := make(vendorAttrs)
	for _, reply := range replies {
		top, err := decodeVendorAttrs(reply.Data)
		if err != nil {
			return nil, err
		}
		if nested, ok := top[unix.NL80211_ATTR_VENDOR_DATA]; ok {
			inner, err := decodeVendorAttrs(nested)
			if err != nil {
				return nil, err
			}
			for k, v := range inner {
				out[k] = v
			}
		}
	}
	return out, nil
}

func probeIoctl(ifname string) (Caps, error) {
	var lastErr error
	for _, base := range dfsLastIoctlCandidates {
		out, err := athDiag(ifname, uint16(base+ioctlGetCaps)|athDiagDyn, nil, 128)
		if err != nil {
			lastErr = fmt.Errorf("caps ioctl (DFS_LAST_IOCTL=%d): %w", base, err)
			continue
		}
		if caps, ok := decodeCaps(out, base); ok {
			return caps, nil
		}
		lastErr = fmt.Errorf("caps ioctl (DFS_LAST_IOCTL=%d) returned no spectral capability", base)
	}
	return Caps{}, lastErr
}

// athDiag issues SIOCGATHPHYERR with struct ath_diag (if_athioctl.h):
//
//	char ad_name[IFNAMSIZ]; u16 ad_id; u16 ad_in_size;
//	void *ad_in_data; void *ad_out_data; u_int ad_out_size;
//
// The struct has natural alignment and pointer-sized buffers, so its layout
// is computed for the running ABI. ifreq, ath_diag and both buffers live in
// one heap allocation; Go's heap is non-moving, and the allocation is kept
// alive until the ioctl returns.
func athDiag(ifname string, id uint16, in []byte, outLen int) ([]byte, error) {
	if len(ifname) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name %q too long", ifname)
	}
	ptr := int(unsafe.Sizeof(uintptr(0)))
	inDataOff := alignUp(20, ptr)
	outDataOff := inDataOff + ptr
	outSizeOff := outDataOff + ptr
	diagSize := alignUp(outSizeOff+4, ptr)

	const ifreqOff, diagOff = 0, 64 // struct ifreq is 32 or 40 bytes
	inOff := alignUp(diagOff+diagSize, 8)
	outOff := alignUp(inOff+len(in), 8)
	buf := make([]byte, outOff+outLen+8)

	copy(buf[ifreqOff:ifreqOff+unix.IFNAMSIZ], ifname)
	copy(buf[diagOff:diagOff+unix.IFNAMSIZ], ifname)
	*(*uint16)(unsafe.Pointer(&buf[diagOff+16])) = id
	*(*uint16)(unsafe.Pointer(&buf[diagOff+18])) = uint16(len(in))
	if len(in) > 0 {
		copy(buf[inOff:], in)
		*(*uintptr)(unsafe.Pointer(&buf[diagOff+inDataOff])) = uintptr(unsafe.Pointer(&buf[inOff]))
	}
	if outLen > 0 {
		*(*uintptr)(unsafe.Pointer(&buf[diagOff+outDataOff])) = uintptr(unsafe.Pointer(&buf[outOff]))
		*(*uint32)(unsafe.Pointer(&buf[diagOff+outSizeOff])) = uint32(outLen)
	}
	// ifr_data sits right after ifr_name in the ifreq union.
	*(*uintptr)(unsafe.Pointer(&buf[ifreqOff+unix.IFNAMSIZ])) = uintptr(unsafe.Pointer(&buf[diagOff]))

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(siocgathphyerr), uintptr(unsafe.Pointer(&buf[0])))
	runtime.KeepAlive(buf)
	if errno != 0 {
		return nil, errno
	}
	return append([]byte(nil), buf[outOff:outOff+outLen]...), nil
}

func alignUp(v, a int) int { return (v + a - 1) / a * a }

func (d *nativeDriver) OpenSamples() (sampleSource, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, netlinkAtheros)
	if err != nil {
		return nil, fmt.Errorf("open NETLINK_ATHEROS (%d): %w; the spectral module is not loaded or delivers samples another way", netlinkAtheros, err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 512*1024)
	// Pid 0 lets the kernel assign a port id; getpid() collides with any
	// other netlink socket in this process.
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind NETLINK_ATHEROS group 1: %w", err)
	}
	return &netlinkSource{fd: fd, buf: make([]byte, 8192)}, nil
}

type netlinkSource struct {
	fd  int
	buf []byte
}

// Recv returns one raw datagram (nlmsghdr included), or nil on timeout. The
// raw datagram is kept whole because the optimized SAMP layout carries bins
// beyond nlmsg_len.
func (s *netlinkSource) Recv(timeoutMillis int) ([]byte, error) {
	fds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, timeoutMillis)
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return nil, nil
		}
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	read, _, err := unix.Recvfrom(s.fd, s.buf, unix.MSG_DONTWAIT)
	if err != nil {
		// ENOBUFS reports an overrun; later samples are still valid.
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOBUFS) {
			return nil, nil
		}
		return nil, err
	}
	return s.buf[:read], nil
}

func (s *netlinkSource) Close() error { return unix.Close(s.fd) }
