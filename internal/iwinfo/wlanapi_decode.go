package iwinfo

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Decoders for the wlanapi.dll structures the Windows backend reads. They
// live in a platform-neutral file so the layouts are tested on every OS.

const (
	wlanInterfaceInfoSize   = 16 + 512 + 4 // GUID, WCHAR[256], state
	wlanConnectionAttrsSize = 4 + 4 + 512 + 68
	wlanAssocOffset         = 4 + 4 + 512 // isState, mode, strProfileName
)

// DOT11_PHY_TYPE values that map to 802.11 generations.
const (
	dot11PhyOFDM  = 4  // 802.11a
	dot11PhyHRDSS = 5  // 802.11b
	dot11PhyERP   = 6  // 802.11g
	dot11PhyHT    = 7  // 802.11n
	dot11PhyVHT   = 8  // 802.11ac
	dot11PhyHE    = 10 // 802.11ax
	dot11PhyEHT   = 11 // 802.11be
)

type wlanInterface struct {
	guid        [16]byte
	description string
	state       uint32
}

func utf16String(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

// decodeWlanInterfaceList reads WLAN_INTERFACE_INFO_LIST.
func decodeWlanInterfaceList(b []byte) []wlanInterface {
	if len(b) < 8 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(b))
	var out []wlanInterface
	for i := 0; i < count && i < 64; i++ {
		off := 8 + i*wlanInterfaceInfoSize
		if off+wlanInterfaceInfoSize > len(b) {
			break
		}
		var iface wlanInterface
		copy(iface.guid[:], b[off:off+16])
		iface.description = utf16String(b[off+16 : off+16+512])
		iface.state = binary.LittleEndian.Uint32(b[off+528:])
		out = append(out, iface)
	}
	return out
}

// applyWlanConnection fills info from WLAN_CONNECTION_ATTRIBUTES.
func applyWlanConnection(b []byte, info *InterfaceInfo) {
	if len(b) < wlanConnectionAttrsSize {
		return
	}
	a := b[wlanAssocOffset:]
	if n := int(binary.LittleEndian.Uint32(a)); n > 0 && n <= 32 {
		info.SSID = string(a[4 : 4+n])
	}
	info.BSSID = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", a[40], a[41], a[42], a[43], a[44], a[45])
	info.HardwareName = dot11PhyName(binary.LittleEndian.Uint32(a[48:]))
	quality := int(binary.LittleEndian.Uint32(a[56:]))
	info.Quality, info.QualityMax = quality, 100
	if info.Signal == 0 {
		info.Signal = quality/2 - 100 // Windows' documented quality↔dBm mapping
	}
	info.Bitrate = int(binary.LittleEndian.Uint32(a[60:])) // kbit/s
	info.Mode = 3
}

// decodeWlanPhyTypes reads WLAN_INTERFACE_CAPABILITY's supported PHY list.
func decodeWlanPhyTypes(b []byte) *HWModes {
	if len(b) < 20 {
		return nil
	}
	modes := &HWModes{}
	count := int(binary.LittleEndian.Uint32(b[16:]))
	for i := 0; i < count && i < 64 && 20+4*i+4 <= len(b); i++ {
		switch binary.LittleEndian.Uint32(b[20+4*i:]) {
		case dot11PhyOFDM:
			modes.A = true
		case dot11PhyHRDSS:
			modes.B = true
		case dot11PhyERP:
			modes.G = true
		case dot11PhyHT:
			modes.N = true
		case dot11PhyVHT:
			modes.AC = true
		case dot11PhyHE:
			modes.AX = true
		case dot11PhyEHT:
			modes.BE = true
		}
	}
	return modes
}

func dot11PhyName(phy uint32) string {
	switch phy {
	case dot11PhyOFDM:
		return "802.11a"
	case dot11PhyHRDSS:
		return "802.11b"
	case dot11PhyERP:
		return "802.11g"
	case dot11PhyHT:
		return "802.11n"
	case dot11PhyVHT:
		return "802.11ac"
	case dot11PhyHE:
		return "802.11ax"
	case dot11PhyEHT:
		return "802.11be"
	}
	return ""
}

// channelFrequency maps a Windows-reported channel to MHz (2.4/5 GHz; the
// API does not say when a channel number is a 6 GHz one).
func channelFrequency(channel int) int {
	switch {
	case channel == 14:
		return 2484
	case channel >= 1 && channel <= 13:
		return 2407 + 5*channel
	case channel >= 32 && channel <= 177:
		return 5000 + 5*channel
	}
	return 0
}
