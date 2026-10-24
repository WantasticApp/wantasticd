//go:build linux

package iwinfo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Vendor (non-mac80211) station collection for Atheros/Qualcomm drivers:
// MadWifi and the QSDK qca-wifi stack. Both keep their own net80211 node
// table and answer nl80211 station dumps with an empty list (or not at all),
// so the agent asks the driver directly, exactly like wlanconfig(8) and
// 80211stats(8) do:
//
//	IEEE80211_IOCTL_STA_INFO  (SIOCDEVPRIVATE+6)  station table
//	IEEE80211_IOCTL_STA_STATS (SIOCDEVPRIVATE+5)  per-station counters
//
// The MadWifi record layout is decoded natively and validated record by
// record (isi_len must equal the fixed part plus isi_ie_len rounded to 4).
// qca-wifi changed the record layout between releases without a version
// marker, so when validation rejects the buffer the agent falls back to the
// driver's own decoder, `wlanconfig <vap> list sta`.

const (
	ioctlStaStats = unix.SIOCDEVPRIVATE + 5
	ioctlStaInfo  = unix.SIOCDEVPRIVATE + 6
	// IEEE80211_IOCTL_GETCHANINFO (SIOCIWFIRSTPRIV+13), as wlanconfig's
	// "list chan" issues it.
	ioctlGetChanInfo = 0x8BE0 + 13

	staInfoBufferSize = 24 * 1024 // wlanconfig.c list_stations

	wlanconfigTimeout = 3 * time.Second
)

var wlanconfigPaths = []string{"/usr/sbin/wlanconfig", "/sbin/wlanconfig", "/usr/bin/wlanconfig", "/bin/wlanconfig"}

// VendorAssocList returns the stations of an Atheros/QCA VAP (athN) using
// the driver ioctl, falling back to wlanconfig when the ioctl layout is not
// recognised. Noise is taken from /proc/net/wireless so SNR-style RSSI can be
// converted to dBm.
func VendorAssocList(ifname string) ([]AssocEntry, error) {
	if !validIfName(ifname) {
		return nil, fmt.Errorf("invalid interface name %q", ifname)
	}
	noise, noiseKnown := WirelessNoise(ifname)
	if !noiseKnown {
		noise = nominalNoiseFloor
	}
	// The qca nl80211 vendor path (QCAVendorStationRecords) is deliberately
	// not used here: it is a SET_WIFI_CONFIGURATION command whose generic
	// command numbering is driver-build specific, and an unverified number
	// must never be sent to a production radio on every poll.
	buf, err := vendorStaInfo(ifname)
	if err == nil {
		entries, decodeErr := decodeMadwifiStaInfo(buf, noise, noiseKnown)
		if decodeErr == nil {
			for i := range entries {
				madwifiStaStats(ifname, &entries[i])
			}
			return entries, nil
		}
		err = decodeErr
	}
	// qca-wifi: decode with offsets learned from an earlier wlanconfig run,
	// so routine polls need no fork.
	if buf != nil {
		if layout, ok := staLayouts.get(ifname); ok {
			if entries, ok := decodeCalibratedStaInfo(buf, layout, noise, noiseKnown); ok {
				return entries, nil
			}
			staLayouts.drop(ifname)
		}
	}
	entries, cliErr := wlanconfigStations(ifname, noise, noiseKnown)
	if cliErr == nil {
		if buf != nil {
			if layout, ok := calibrateStaLayout(buf, entries, noise); ok {
				staLayouts.put(ifname, layout)
			}
		}
		return entries, nil
	}
	return nil, fmt.Errorf("sta_info ioctl: %v; wlanconfig: %v", err, cliErr)
}

// staLayoutTTL bounds how long a learned layout is trusted before it is
// checked against wlanconfig again (driver reloads, firmware updates).
const staLayoutTTL = 10 * time.Minute

type staLayoutCache struct {
	mu      sync.Mutex
	entries map[string]staLayoutEntry
}

type staLayoutEntry struct {
	layout vendorStaLayout
	at     time.Time
}

var staLayouts = &staLayoutCache{entries: map[string]staLayoutEntry{}}

func (c *staLayoutCache) get(ifname string) (vendorStaLayout, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[ifname]
	if !ok || time.Since(e.at) > staLayoutTTL {
		return vendorStaLayout{}, false
	}
	return e.layout, true
}

func (c *staLayoutCache) put(ifname string, l vendorStaLayout) {
	c.mu.Lock()
	c.entries[ifname] = staLayoutEntry{layout: l, at: time.Now()}
	c.mu.Unlock()
}

func (c *staLayoutCache) drop(ifname string) {
	c.mu.Lock()
	delete(c.entries, ifname)
	c.mu.Unlock()
}

func vendorStaInfo(ifname string) ([]byte, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	buf := make([]byte, staInfoBufferSize)
	n, err := iwreqData(fd, ifname, ioctlStaInfo, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// iwreqData issues a wireless-extensions style private ioctl whose payload is
// described by iwreq.u.data {pointer, length, flags} and returns the length
// the driver wrote back.
func iwreqData(fd int, ifname string, request uintptr, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, fmt.Errorf("empty iwreq buffer")
	}
	// struct iwreq: char ifr_name[16]; union iwreq_data u (16 bytes).
	var req [32]byte
	copy(req[:unix.IFNAMSIZ-1], ifname)
	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	if 16+ptrSize+4 > len(req) {
		return 0, fmt.Errorf("unsupported pointer size %d", ptrSize)
	}
	// The driver writes through a pointer stored inside the request, which
	// the compiler cannot see; pinning keeps buf at a fixed heap address
	// (a small buffer could otherwise live on a movable goroutine stack).
	var pinner runtime.Pinner
	pinner.Pin(&buf[0])
	defer pinner.Unpin()
	pointer := uintptr(unsafe.Pointer(&buf[0]))
	if ptrSize == 8 {
		binary.NativeEndian.PutUint64(req[16:], uint64(pointer))
	} else {
		binary.NativeEndian.PutUint32(req[16:], uint32(pointer))
	}
	if len(buf) > 0xffff {
		return 0, fmt.Errorf("iwreq buffer too large")
	}
	binary.NativeEndian.PutUint16(req[16+ptrSize:], uint16(len(buf)))
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(&req[0])))
	runtime.KeepAlive(buf)
	if errno != 0 {
		return 0, errno
	}
	n := int(binary.NativeEndian.Uint16(req[16+ptrSize:]))
	if n > len(buf) {
		n = len(buf)
	}
	return n, nil
}

// madwifiStaStats fills packet and byte counters from STA_STATS. Failures are
// ignored: the station row is still valid without counters.
func madwifiStaStats(ifname string, entry *AssocEntry) {
	rxData, rxBytes, txData, txBytes, size := madwifiNodeStatsLayout()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	buf := make([]byte, size)
	copy(buf, entry.MAC)
	n, err := iwreqData(fd, ifname, ioctlStaStats, buf)
	if err != nil || n < size {
		return
	}
	ne := binary.NativeEndian
	entry.RxPackets, entry.RxPacketsKnown = ne.Uint32(buf[rxData:]), true
	entry.TxPackets, entry.TxPacketsKnown = ne.Uint32(buf[txData:]), true
	entry.RxBytes, entry.RxBytesKnown = ne.Uint64(buf[rxBytes:]), true
	entry.TxBytes, entry.TxBytesKnown = ne.Uint64(buf[txBytes:]), true
}

func findWlanconfig() string {
	for _, path := range wlanconfigPaths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return path
		}
	}
	return ""
}

func wlanconfigStations(ifname string, noise int, noiseKnown bool) ([]AssocEntry, error) {
	bin := findWlanconfig()
	if bin == "" {
		return nil, errors.New("wlanconfig not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), wlanconfigTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, ifname, "list", "sta")
	var stdout bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, remaining: 1 << 20}
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return ParseWlanconfigStations(stdout.String(), noise, noiseKnown), nil
}

type limitedWriter struct {
	w         *bytes.Buffer
	remaining int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.remaining <= 0 {
		return len(p), nil
	}
	n := len(p)
	if n > l.remaining {
		p = p[:l.remaining]
	}
	l.remaining -= len(p)
	l.w.Write(p)
	return n, nil
}

// WirelessNoise reads the wireless-extensions noise level for ifname from
// /proc/net/wireless (dBm, "-95." style). qca-wifi and MadWifi both fill it.
func WirelessNoise(ifname string) (int, bool) {
	data, err := os.ReadFile("/proc/net/wireless")
	if err != nil {
		return 0, false
	}
	return parseProcNetWirelessNoise(string(data), ifname)
}

// VendorRadioParent returns the radio netdev (wifiN) that owns a qca-wifi or
// MadWifi VAP, from /sys/class/net/<vap>/parent.
func VendorRadioParent(netClassDir, ifname string) string {
	if netClassDir == "" {
		netClassDir = "/sys/class/net"
	}
	data, err := os.ReadFile(filepath.Join(netClassDir, ifname, "parent"))
	if err != nil {
		return ""
	}
	parent := strings.TrimSpace(string(data))
	if !validIfName(parent) {
		return ""
	}
	return parent
}

// VendorConfiguredDistance reads the ACK-timing distance configured on a
// MadWifi radio: /proc/sys/dev/<radio>/distance when the driver exposes it,
// else derived from slottime as athctrl sets it (slottime = 9 µs + 1 µs per
// started 300 m).
func VendorConfiguredDistance(radio string) (int, string, bool) {
	if !validIfName(radio) {
		return 0, "", false
	}
	base := filepath.Join("/proc/sys/dev", radio)
	if v, ok := readProcInt(filepath.Join(base, "distance")); ok && v > 0 {
		return v, "driver-distance", true
	}
	if v, ok := readProcInt(filepath.Join(base, "slottime")); ok && v > 9 {
		return (v - 9) * 300, "slottime", true
	}
	return 0, "", false
}

func readProcInt(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	return v, err == nil
}

const (
	siocgiwfreq  = 0x8B05
	siocgiwtxpow = 0x8B27
)

func iwreqScalar(ifname string, request uintptr) ([16]byte, error) {
	var out [16]byte
	if !validIfName(ifname) {
		return out, fmt.Errorf("invalid interface name %q", ifname)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return out, err
	}
	defer unix.Close(fd)
	var req [32]byte
	copy(req[:unix.IFNAMSIZ-1], ifname)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		return out, errno
	}
	copy(out[:], req[16:])
	return out, nil
}

// WextFrequency returns the operating frequency in MHz through the wireless
// extensions SIOCGIWFREQ ioctl, which qca-wifi and MadWifi VAPs implement
// even when they are invisible to nl80211.
func WextFrequency(ifname string) (int, bool) {
	u, err := iwreqScalar(ifname, siocgiwfreq)
	if err != nil {
		return 0, false
	}
	ne := binary.NativeEndian
	m := int64(int32(ne.Uint32(u[0:])))
	e := int(int16(ne.Uint16(u[4:])))
	if e == 0 && m > 0 && m < 1000 {
		// A channel number, not a frequency.
		return 0, false
	}
	hz := float64(m)
	for ; e > 0; e-- {
		hz *= 10
	}
	mhz := int(hz / 1e6)
	if mhz < 2300 || mhz > 7300 {
		return 0, false
	}
	return mhz, true
}

// WextTxPower returns the transmit power in dBm via SIOCGIWTXPOW.
func WextTxPower(ifname string) (int, bool) {
	u, err := iwreqScalar(ifname, siocgiwtxpow)
	if err != nil {
		return 0, false
	}
	ne := binary.NativeEndian
	value := int(int32(ne.Uint32(u[0:])))
	disabled := u[5] != 0
	flags := ne.Uint16(u[6:])
	if disabled {
		return 0, false
	}
	switch flags & 0x00ff { // IW_TXPOW_TYPE
	case 0: // IW_TXPOW_DBM
	case 1: // IW_TXPOW_MWATT
		if value <= 0 {
			return 0, false
		}
		value = int(10*math.Log10(float64(value)) + 0.5)
	default:
		return 0, false
	}
	if value <= 0 || value > 40 {
		return 0, false
	}
	return value, true
}

// VendorWiphy reads the regulatory channel table of a madwifi/qca-wifi VAP
// (wlanconfig athN list chan) for radios that do not answer nl80211.
func VendorWiphy(ifname string) (*Wiphy, error) {
	if !validIfName(ifname) {
		return nil, fmt.Errorf("invalid interface name %q", ifname)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	buf := make([]byte, 32*1024)
	n, err := iwreqData(fd, ifname, ioctlGetChanInfo, buf)
	if err != nil {
		return nil, err
	}
	if n <= 0 || n > len(buf) {
		n = len(buf)
	}
	channels := decodeVendorChanInfo(buf[:n])
	if len(channels) == 0 {
		return nil, fmt.Errorf("unrecognised channel table from %s", ifname)
	}
	return wiphyFromChannels(channels), nil
}
