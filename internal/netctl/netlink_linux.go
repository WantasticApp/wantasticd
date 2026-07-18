//go:build linux
// +build linux

// Shared pure-Go netlink and sysfs helpers for all Linux builds.
// Both the pure-Go controller and the CGo controller use these.

package netctl

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// linuxController implements Controller using raw netlink + sysfs. No CGo.
type linuxController struct{}

func (c *linuxController) Close() error { return nil }

// ── Link management ─────────────────────────────────────────────────────────

func (c *linuxController) LinkSetUp(ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	return netlinkSetLink(iface.Index, true)
}

func (c *linuxController) LinkSetDown(ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	return netlinkSetLink(iface.Index, false)
}

// ── Address management ──────────────────────────────────────────────────────

func (c *linuxController) AddrAdd(ifname string, addr netip.Prefix) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	err = netlinkAddrAdd(iface.Index, addr)
	if err != nil && os.IsExist(err) {
		return nil
	}
	return err
}

func (c *linuxController) AddrDel(ifname string, addr netip.Prefix) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	return netlinkAddrDel(iface.Index, addr)
}

// ── Route management ────────────────────────────────────────────────────────

func (c *linuxController) RouteReplace(ifname string, dst netip.Prefix) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	return netlinkRouteReplace(iface.Index, dst)
}

func (c *linuxController) RouteDel(ifname string, dst netip.Prefix) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	return netlinkRouteDel(iface.Index, dst)
}

func (c *linuxController) RouteGetDefault() (string, netip.Addr, error) {
	return routeGetDefaultFromProc()
}

// ── WiFi (sysfs fallback) ───────────────────────────────────────────────────

func (c *linuxController) WiFiGetCapabilities(ifname string) (*WiFiCapabilities, error) {
	return wifiCapsFromSysfs(ifname)
}

func (c *linuxController) WiFiGetStations(ifname string) ([]WiFiStationInfo, error) {
	return wifiStationsFromDebugfs(ifname)
}

// ── Firewall ────────────────────────────────────────────────────────────────

func (c *linuxController) FirewallEnsureRule(rule FirewallRule) error {
	bin := findIptablesBinary()
	return iptablesEnsure(bin, rule)
}

func (c *linuxController) FirewallDeleteRule(rule FirewallRule) error {
	bin := findIptablesBinary()
	return iptablesDelete(bin, rule)
}

func (c *linuxController) IPForwardingSet(enabled bool) error {
	val := "0"
	if enabled {
		val = "1"
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(val), 0644); err != nil {
		return err
	}
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte(val), 0644)
	return nil
}

// ── sysfs WiFi capability parsing ───────────────────────────────────────────

func wifiCapsFromSysfs(ifname string) (*WiFiCapabilities, error) {
	base := "/sys/class/net/" + ifname
	if _, err := os.Stat(base); err != nil {
		return nil, fmt.Errorf("interface %s not found", ifname)
	}

	caps := &WiFiCapabilities{}

	if data, err := os.ReadFile(base + "/phy80211/name"); err == nil {
		caps.PHYName = strings.TrimSpace(string(data))
	}

	if data, err := os.ReadFile(base + "/cfg80211_htcaps"); err == nil {
		htcaps := strings.ToUpper(string(data))
		if len(strings.TrimSpace(htcaps)) > 0 {
			caps.HT = true
			caps.SupportedHTModes = append(caps.SupportedHTModes, "HT20")
			if strings.Contains(htcaps, "40") || strings.Contains(htcaps, "DSSS_CCK") {
				caps.SupportedHTModes = append(caps.SupportedHTModes, "HT40")
			}
			for i := 1; i <= 4; i++ {
				if strings.Contains(htcaps, fmt.Sprintf("RX-STBC-%d", i)) {
					caps.MaxRxStreams = max(caps.MaxRxStreams, i)
				}
			}
		}
	}

	if data, err := os.ReadFile(base + "/cfg80211_vhtcaps"); err == nil {
		vhtcaps := strings.ToUpper(string(data))
		if len(strings.TrimSpace(vhtcaps)) > 0 {
			caps.VHT = true
			caps.SupportedHTModes = append(caps.SupportedHTModes, "VHT20", "VHT40", "VHT80")
			if strings.Contains(vhtcaps, "VHT160") || strings.Contains(vhtcaps, "SHORT-GI-160") {
				caps.SupportedHTModes = append(caps.SupportedHTModes, "VHT160")
			}
			for i := 1; i <= 8; i++ {
				if strings.Contains(vhtcaps, fmt.Sprintf("SOUNDING-DIMENSION-%d", i)) {
					caps.MaxTxStreams = max(caps.MaxTxStreams, i)
				}
			}
		}
	}

	if data, err := os.ReadFile(base + "/cfg80211_hecaps"); err == nil && len(data) > 0 {
		caps.HE = true
		caps.SupportedHTModes = append(caps.SupportedHTModes, "HE20", "HE40", "HE80")
		if hasMode(caps.SupportedHTModes, "VHT160") {
			caps.SupportedHTModes = append(caps.SupportedHTModes, "HE160")
		}
	}

	if data, err := os.ReadFile(base + "/cfg80211_ehtcaps"); err == nil && len(data) > 0 {
		caps.EHT = true
		caps.SupportedHTModes = append(caps.SupportedHTModes, "EHT20", "EHT40", "EHT80", "EHT160", "EHT320")
	}

	if len(caps.SupportedHTModes) == 0 {
		return nil, fmt.Errorf("no WiFi capabilities for %s", ifname)
	}
	return caps, nil
}

func wifiStationsFromDebugfs(ifname string) ([]WiFiStationInfo, error) {
	phyData, err := os.ReadFile("/sys/class/net/" + ifname + "/phy80211/name")
	if err != nil {
		return nil, nil
	}
	phyName := strings.TrimSpace(string(phyData))
	stationsDir := "/sys/kernel/debug/ieee80211/" + phyName + "/netdev:" + ifname + "/stations"

	entries, err := os.ReadDir(stationsDir)
	if err != nil {
		return nil, nil // debugfs not mounted
	}

	var stations []WiFiStationInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sta := WiFiStationInfo{MAC: entry.Name()}
		d := stationsDir + "/" + entry.Name()
		if v, err := readSysfsInt(d + "/last_signal"); err == nil {
			sta.Signal = v
		}
		if v, err := readSysfsUint64(d + "/rx_bytes"); err == nil {
			sta.RxBytes = v
		}
		if v, err := readSysfsUint64(d + "/tx_bytes"); err == nil {
			sta.TxBytes = v
		}
		if v, err := readSysfsInt(d + "/connected_time"); err == nil {
			sta.ConnectedSecs = uint32(v)
		}
		if v, err := readSysfsInt(d + "/inactive_ms"); err == nil {
			sta.Inactive = uint32(v)
		}
		stations = append(stations, sta)
	}
	return stations, nil
}

// ── Raw netlink ─────────────────────────────────────────────────────────────

const (
	_RTM_NEWROUTE  = 24
	_RTM_DELROUTE  = 25
	_RTM_NEWADDR   = 20
	_RTM_DELADDR   = 21
	_RTM_NEWLINK   = 16
	_NLM_F_REQUEST = 0x1
	_NLM_F_ACK     = 0x4
	_NLM_F_CREATE  = 0x400
	_NLM_F_REPLACE = 0x100
	_RTA_DST       = 1
	_RTA_OIF       = 4
	_IFA_ADDRESS   = 1
	_IFA_LOCAL     = 2
	_RTPROT_BOOT   = 3
	_RT_SCOPE_LINK = 253
	_RT_TABLE_MAIN = 254
	_RTN_UNICAST   = 1
)

type nlMsgHdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}
type rtMsg struct {
	Family, DstLen, SrcLen, TOS, Table, Protocol, Scope, Type uint8
	Flags                                                     uint32
}
type ifAddrMsg struct {
	Family, Prefixlen, Flags, Scope uint8
	Index                           uint32
}
type ifInfoMsg struct {
	Family        uint8
	_             uint8
	Type          uint16
	Index         int32
	Flags, Change uint32
}

func nlAlign(l int) int { return (l + 3) &^ 3 }

func putAttr(buf []byte, off int, typ uint16, data []byte) int {
	l := 4 + len(data)
	binary.LittleEndian.PutUint16(buf[off:], uint16(l))
	binary.LittleEndian.PutUint16(buf[off+2:], typ)
	copy(buf[off+4:], data)
	return off + nlAlign(l)
}

func netlinkExec(msg []byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return err
	}
	if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
		return err
	}
	rbuf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, rbuf, 0)
	if err != nil {
		return err
	}
	if n >= int(unsafe.Sizeof(nlMsgHdr{}))+4 {
		if binary.LittleEndian.Uint16(rbuf[4:6]) == 0x2 {
			errno := int32(binary.LittleEndian.Uint32(rbuf[16:20]))
			if errno < 0 {
				return syscall.Errno(-errno)
			}
		}
	}
	return nil
}

func prefixToIP(p netip.Prefix) (uint8, []byte) {
	a := p.Addr()
	if a.Is4() {
		r := a.As4()
		return syscall.AF_INET, r[:]
	}
	r := a.As16()
	return syscall.AF_INET6, r[:]
}

func buildRouteMsg(msgType, flags uint16, ifindex int, prefix netip.Prefix) []byte {
	family, dst := prefixToIP(prefix)
	buf := make([]byte, 256)
	off := int(unsafe.Sizeof(nlMsgHdr{}))
	buf[off] = family
	buf[off+1] = uint8(prefix.Bits())
	buf[off+4] = _RT_TABLE_MAIN
	buf[off+5] = _RTPROT_BOOT
	buf[off+6] = _RT_SCOPE_LINK
	buf[off+7] = _RTN_UNICAST
	off += int(unsafe.Sizeof(rtMsg{}))
	off = putAttr(buf, off, _RTA_DST, dst)
	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(ifindex))
	off = putAttr(buf, off, _RTA_OIF, oif)
	binary.LittleEndian.PutUint32(buf[0:], uint32(off))
	binary.LittleEndian.PutUint16(buf[4:], msgType)
	binary.LittleEndian.PutUint16(buf[6:], flags)
	binary.LittleEndian.PutUint32(buf[8:], 1)
	return buf[:off]
}

func netlinkRouteReplace(idx int, p netip.Prefix) error {
	return netlinkExec(buildRouteMsg(_RTM_NEWROUTE, _NLM_F_REQUEST|_NLM_F_ACK|_NLM_F_CREATE|_NLM_F_REPLACE, idx, p))
}
func netlinkRouteDel(idx int, p netip.Prefix) error {
	return netlinkExec(buildRouteMsg(_RTM_DELROUTE, _NLM_F_REQUEST|_NLM_F_ACK, idx, p))
}

func netlinkAddrOp(t, f uint16, idx int, p netip.Prefix) error {
	family, ip := prefixToIP(p)
	buf := make([]byte, 256)
	off := int(unsafe.Sizeof(nlMsgHdr{}))
	buf[off] = family
	buf[off+1] = uint8(p.Bits())
	binary.LittleEndian.PutUint32(buf[off+4:], uint32(idx))
	off += int(unsafe.Sizeof(ifAddrMsg{}))
	off = putAttr(buf, off, _IFA_LOCAL, ip)
	off = putAttr(buf, off, _IFA_ADDRESS, ip)
	binary.LittleEndian.PutUint32(buf[0:], uint32(off))
	binary.LittleEndian.PutUint16(buf[4:], t)
	binary.LittleEndian.PutUint16(buf[6:], f)
	binary.LittleEndian.PutUint32(buf[8:], 1)
	return netlinkExec(buf[:off])
}
func netlinkAddrAdd(idx int, p netip.Prefix) error {
	return netlinkAddrOp(_RTM_NEWADDR, _NLM_F_REQUEST|_NLM_F_ACK|_NLM_F_CREATE, idx, p)
}
func netlinkAddrDel(idx int, p netip.Prefix) error {
	return netlinkAddrOp(_RTM_DELADDR, _NLM_F_REQUEST|_NLM_F_ACK, idx, p)
}

func netlinkSetLink(idx int, up bool) error {
	buf := make([]byte, 256)
	off := int(unsafe.Sizeof(nlMsgHdr{}))
	buf[off] = syscall.AF_UNSPEC
	binary.LittleEndian.PutUint32(buf[off+4:], uint32(idx))
	var flags uint32
	if up {
		flags = syscall.IFF_UP
	}
	binary.LittleEndian.PutUint32(buf[off+8:], flags)
	binary.LittleEndian.PutUint32(buf[off+12:], syscall.IFF_UP)
	off += int(unsafe.Sizeof(ifInfoMsg{}))
	binary.LittleEndian.PutUint32(buf[0:], uint32(off))
	binary.LittleEndian.PutUint16(buf[4:], _RTM_NEWLINK)
	binary.LittleEndian.PutUint16(buf[6:], _NLM_F_REQUEST|_NLM_F_ACK)
	binary.LittleEndian.PutUint32(buf[8:], 1)
	return netlinkExec(buf[:off])
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func readSysfsInt(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var v int
	_, err = fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &v)
	return v, err
}

func readSysfsUint64(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var v uint64
	_, err = fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &v)
	return v, err
}

func hasMode(modes []string, val string) bool {
	for _, m := range modes {
		if m == val {
			return true
		}
	}
	return false
}

func routeGetDefaultFromProc() (string, netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", netip.Addr{}, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[1] != "00000000" {
			continue
		}
		var gwHex uint32
		fmt.Sscanf(fields[2], "%X", &gwHex)
		gw := netip.AddrFrom4([4]byte{byte(gwHex), byte(gwHex >> 8), byte(gwHex >> 16), byte(gwHex >> 24)})
		return fields[0], gw, nil
	}
	return "", netip.Addr{}, fmt.Errorf("no default route")
}

func findIptablesBinary() string {
	for _, p := range []string{"/usr/sbin/iptables", "/sbin/iptables", "/usr/sbin/iptables-nft", "/sbin/iptables-nft"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "iptables"
}

func iptablesEnsure(binary string, rule FirewallRule) error {
	// Check quietly: iptables prints "Bad rule" for an ordinary missing-rule
	// result, which is expected before the first add.
	args := append([]string{"-t", rule.Table, "-C", rule.Chain}, rule.Args...)
	if exec.Command(binary, args...).Run() == nil {
		return nil
	}
	args[2] = "-A"
	return forkExecWait(binary, args...)
}

func iptablesDelete(binary string, rule FirewallRule) error {
	check := append([]string{"-t", rule.Table, "-C", rule.Chain}, rule.Args...)
	if exec.Command(binary, check...).Run() != nil {
		return nil
	}
	args := append([]string{"-t", rule.Table, "-D", rule.Chain}, rule.Args...)
	return forkExecWait(binary, args...)
}

func forkExecWait(name string, args ...string) error {
	argv := append([]string{name}, args...)
	pid, err := syscall.ForkExec(name, argv, &syscall.ProcAttr{
		Files: []uintptr{uintptr(syscall.Stdin), uintptr(syscall.Stdout), uintptr(syscall.Stderr)},
	})
	if err != nil {
		return err
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return err
	}
	if ws.ExitStatus() != 0 {
		return fmt.Errorf("exit status %d", ws.ExitStatus())
	}
	return nil
}
