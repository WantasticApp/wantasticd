//go:build linux

package platforms

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Native firewall counter readers. They ask the kernel directly, the same
// way nft and iptables-save do, so a telemetry sample costs one netlink dump
// or a couple of getsockopt calls instead of forking a CLI and parsing text.

// readNativeFirewallRuleCounters returns rule counters from legacy iptables
// when that has rules, else from nftables.
func readNativeFirewallRuleCounters() ([]firewallRuleCounter, string, error) {
	if rules, err := readIPTablesCounters(); err == nil && len(rules) > 0 {
		return rules, "iptables", nil
	}
	rules, err := readNFTCounters()
	if err != nil {
		return nil, "", err
	}
	if len(rules) == 0 {
		return nil, "", fmt.Errorf("no counted firewall rules")
	}
	return rules, "nftables", nil
}

// ── nftables (netfilter netlink) ────────────────────────────────────────────

// Netfilter verdicts (linux/netfilter.h).
const (
	nfDrop   = 0
	nfAccept = 1
	nfQueue  = 3
	nfRepeat = 4
)

var nftFamilyNames = map[uint8]string{1: "inet", 2: "ip", 3: "arp", 5: "netdev", 7: "bridge", 10: "ip6"}

func readNFTCounters() ([]firewallRuleCounter, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETRULE),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: []byte{unix.AF_UNSPEC, unix.NFNETLINK_V0, 0, 0},
	})
	if err != nil {
		return nil, fmt.Errorf("nftables rule dump: %w", err)
	}
	var out []firewallRuleCounter
	ordinal := map[string]int{}
	for _, msg := range msgs {
		rule, ok := decodeNFTRule(msg.Data)
		if !ok {
			continue
		}
		ordinal[rule.Table+"/"+rule.Chain]++
		rule.Name = cleanFirewallRuleName(rule.Name, rule.Chain, ordinal[rule.Table+"/"+rule.Chain])
		out = append(out, rule)
	}
	return out, nil
}

// decodeNFTRule maps one NFT_MSG_NEWRULE payload (nfgenmsg + attributes)
// into a counter row. Rules without a counter expression are skipped, as
// nft -j output has no packets/bytes for them either.
func decodeNFTRule(data []byte) (firewallRuleCounter, bool) {
	if len(data) < 4 {
		return firewallRuleCounter{}, false
	}
	family := nftFamilyNames[data[0]]
	ad, err := netlink.NewAttributeDecoder(data[4:])
	if err != nil {
		return firewallRuleCounter{}, false
	}
	ad.ByteOrder = binary.BigEndian
	var table, chain, comment, target string
	var handle uint64
	var packets, bytesCount uint64
	counted := false
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RULE_TABLE:
			table = ad.String()
		case unix.NFTA_RULE_CHAIN:
			chain = ad.String()
		case unix.NFTA_RULE_HANDLE:
			handle = ad.Uint64()
		case unix.NFTA_RULE_USERDATA:
			comment = nftRuleComment(ad.Bytes())
		case unix.NFTA_RULE_EXPRESSIONS:
			ad.Nested(func(list *netlink.AttributeDecoder) error {
				for list.Next() {
					list.Nested(func(expr *netlink.AttributeDecoder) error {
						expr.ByteOrder = binary.BigEndian
						name := ""
						var payload []byte
						for expr.Next() {
							switch expr.Type() {
							case unix.NFTA_EXPR_NAME:
								name = expr.String()
							case unix.NFTA_EXPR_DATA:
								payload = expr.Bytes()
							}
						}
						switch name {
						case "counter":
							packets, bytesCount, counted = nftCounter(payload)
						case "immediate":
							if verdict := nftImmediateVerdict(payload); verdict != "" {
								target = verdict
							}
						case "reject":
							target = "REJECT"
						case "masq":
							target = "MASQUERADE"
						case "redir":
							target = "REDIRECT"
						case "nat":
							target = nftNATType(payload)
						}
						return nil
					})
				}
				return nil
			})
		}
	}
	if !counted || chain == "" {
		return firewallRuleCounter{}, false
	}
	tableName := strings.TrimSpace(family + " " + table)
	return firewallRuleCounter{
		Key:     firewallRuleKey(tableName, chain, comment, strconv.FormatUint(handle, 10)),
		Table:   tableName,
		Chain:   chain,
		Name:    comment,
		Target:  target,
		Packets: packets,
		Bytes:   bytesCount,
	}, true
}

func nftCounter(payload []byte) (uint64, uint64, bool) {
	ad, err := netlink.NewAttributeDecoder(payload)
	if err != nil {
		return 0, 0, false
	}
	ad.ByteOrder = binary.BigEndian
	var packets, byteCount uint64
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_COUNTER_PACKETS:
			packets = ad.Uint64()
		case unix.NFTA_COUNTER_BYTES:
			byteCount = ad.Uint64()
		}
	}
	return packets, byteCount, true
}

func nftImmediateVerdict(payload []byte) string {
	ad, err := netlink.NewAttributeDecoder(payload)
	if err != nil {
		return ""
	}
	ad.ByteOrder = binary.BigEndian
	verdict := ""
	for ad.Next() {
		if ad.Type() != unix.NFTA_IMMEDIATE_DATA {
			continue
		}
		ad.Nested(func(data *netlink.AttributeDecoder) error {
			data.ByteOrder = binary.BigEndian
			for data.Next() {
				if data.Type() != unix.NFTA_DATA_VERDICT {
					continue
				}
				data.Nested(func(v *netlink.AttributeDecoder) error {
					v.ByteOrder = binary.BigEndian
					code, chain := int32(0), ""
					hasCode := false
					for v.Next() {
						switch v.Type() {
						case unix.NFTA_VERDICT_CODE:
							code, hasCode = int32(v.Uint32()), true
						case unix.NFTA_VERDICT_CHAIN:
							chain = v.String()
						}
					}
					switch {
					case chain != "":
						verdict = chain
					case !hasCode:
					case code == nfAccept:
						verdict = "ACCEPT"
					case code == nfDrop:
						verdict = "DROP"
					case code == unix.NFT_RETURN:
						verdict = "RETURN"
					}
					return nil
				})
			}
			return nil
		})
	}
	return verdict
}

func nftNATType(payload []byte) string {
	ad, err := netlink.NewAttributeDecoder(payload)
	if err != nil {
		return ""
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		if ad.Type() == unix.NFTA_NAT_TYPE {
			if ad.Uint32() == unix.NFT_NAT_DNAT {
				return "DNAT"
			}
			return "SNAT"
		}
	}
	return ""
}

// nftRuleComment extracts the comment from libnftnl rule userdata, a list of
// {type u8, len u8, value} records where type 0 is the comment.
func nftRuleComment(udata []byte) string {
	for len(udata) >= 2 {
		kind, size := udata[0], int(udata[1])
		if len(udata) < 2+size {
			return ""
		}
		if kind == 0 {
			return strings.TrimRight(string(udata[2:2+size]), "\x00")
		}
		udata = udata[2+size:]
	}
	return ""
}

// ── legacy iptables (IPT_SO_GET_INFO / IPT_SO_GET_ENTRIES) ──────────────────

const (
	iptSoGetInfo    = 64
	iptSoGetEntries = 65
	iptTableMaxName = 32
	// struct ipt_entry: ipt_ip(84) nfcache(4) target_offset(2) next_offset(2)
	// comefrom(4) counters{pcnt,bcnt u64}(16), then matches and target.
	iptEntrySize       = 112
	iptEntryTargetOff  = 88
	iptEntryNextOff    = 90
	iptEntryCounterOff = 96
	xtEntryHeaderSize  = 32 // u16 size + name[29] + revision
)

// iptGetEntriesHead is offsetof(struct ipt_get_entries, entrytable): name[32]
// and size, padded to the u64 alignment of ipt_entry (8, or 4 on i386).
var iptGetEntriesHead = (36 + int(unsafe.Alignof(uint64(0))) - 1) &^ (int(unsafe.Alignof(uint64(0))) - 1)

var iptHookChains = [5]string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}

func readIPTablesCounters() ([]firewallRuleCounter, error) {
	names, err := os.ReadFile("/proc/net/ip_tables_names")
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var out []firewallRuleCounter
	for _, table := range strings.Fields(string(names)) {
		rules, err := readIPTablesTable(fd, table)
		if err != nil {
			continue
		}
		out = append(out, rules...)
	}
	return out, nil
}

func readIPTablesTable(fd int, table string) ([]firewallRuleCounter, error) {
	if len(table) >= iptTableMaxName {
		return nil, fmt.Errorf("table name too long")
	}
	info := make([]byte, 84) // struct ipt_getinfo
	copy(info, table)
	if err := getsockoptBuffer(fd, unix.IPPROTO_IP, iptSoGetInfo, info); err != nil {
		return nil, err
	}
	ne := binary.NativeEndian
	validHooks := ne.Uint32(info[32:])
	var hookEntry, underflow [5]uint32
	for i := range 5 {
		hookEntry[i] = ne.Uint32(info[36+4*i:])
		underflow[i] = ne.Uint32(info[56+4*i:])
	}
	size := ne.Uint32(info[80:])
	if size == 0 || size > 64<<20 {
		return nil, fmt.Errorf("table %s size %d", table, size)
	}
	buf := make([]byte, iptGetEntriesHead+int(size))
	copy(buf, table)
	ne.PutUint32(buf[iptTableMaxName:], size)
	if err := getsockoptBuffer(fd, unix.IPPROTO_IP, iptSoGetEntries, buf); err != nil {
		return nil, err
	}
	return decodeIPTablesEntries(table, buf[iptGetEntriesHead:], validHooks, hookEntry, underflow), nil
}

type iptEntryView struct {
	offset   int
	data     []byte
	target   string
	verdict  int32
	errorTag string
}

// decodeIPTablesEntries walks a table blob the way iptables-save does: chain
// heads come from the hook offsets and ERROR entries, policies (underflows)
// and user-chain trailing RETURNs are not rules.
func decodeIPTablesEntries(table string, blob []byte, validHooks uint32, hookEntry, underflow [5]uint32) []firewallRuleCounter {
	ne := binary.NativeEndian
	var entries []iptEntryView
	for offset := 0; offset+iptEntrySize <= len(blob); {
		next := int(ne.Uint16(blob[offset+iptEntryNextOff:]))
		targetOff := int(ne.Uint16(blob[offset+iptEntryTargetOff:]))
		if next < iptEntrySize || offset+next > len(blob) || targetOff < iptEntrySize || targetOff+xtEntryHeaderSize > next {
			break
		}
		entry := iptEntryView{offset: offset, data: blob[offset : offset+next]}
		targetHead := entry.data[targetOff:]
		entry.target = cString(targetHead[2:31])
		payload := entry.data[targetOff+xtEntryHeaderSize:]
		switch entry.target {
		case "":
			if len(payload) >= 4 {
				entry.verdict = int32(ne.Uint32(payload))
			}
		case "ERROR":
			entry.errorTag = cString(payload)
		}
		entries = append(entries, entry)
		offset += next
	}

	chainAt := map[int]string{}
	underflows := map[int]bool{}
	for hook := range 5 {
		if validHooks&(1<<hook) != 0 {
			chainAt[int(hookEntry[hook])] = iptHookChains[hook]
			underflows[int(underflow[hook])] = true
		}
	}
	for i, entry := range entries {
		if entry.target == "ERROR" && entry.errorTag != "ERROR" && i+1 < len(entries) {
			chainAt[entries[i+1].offset] = entry.errorTag
		}
	}

	var out []firewallRuleCounter
	ordinal := map[string]int{}
	chain := ""
	for i, entry := range entries {
		if name, ok := chainAt[entry.offset]; ok {
			chain = name
		}
		if entry.target == "ERROR" || underflows[entry.offset] || chain == "" {
			continue
		}
		if entry.target == "" && entry.verdict == -nfRepeat-1 && i+1 < len(entries) && entries[i+1].target == "ERROR" {
			continue // a user chain's implicit RETURN
		}
		target := entry.target
		if target == "" {
			target = iptStandardVerdict(entry.verdict, chainAt)
		}
		comment := iptEntryComment(entry.data)
		ordinal[chain]++
		out = append(out, firewallRuleCounter{
			Key:     firewallRuleKey(table, chain, comment, iptEntryIdentity(entry.data)),
			Table:   table,
			Chain:   chain,
			Name:    cleanFirewallRuleName(comment, chain, ordinal[chain]),
			Target:  target,
			Packets: ne.Uint64(entry.data[iptEntryCounterOff:]),
			Bytes:   ne.Uint64(entry.data[iptEntryCounterOff+8:]),
		})
	}
	return out
}

func iptStandardVerdict(verdict int32, chainAt map[int]string) string {
	if verdict >= 0 {
		return chainAt[int(verdict)]
	}
	switch -verdict - 1 {
	case nfDrop:
		return "DROP"
	case nfAccept:
		return "ACCEPT"
	case nfQueue:
		return "QUEUE"
	case nfRepeat:
		return "RETURN"
	}
	return ""
}

// iptEntryComment returns the text of an xt_comment match.
func iptEntryComment(entry []byte) string {
	ne := binary.NativeEndian
	targetOff := int(ne.Uint16(entry[iptEntryTargetOff:]))
	for offset := iptEntrySize; offset+xtEntryHeaderSize <= targetOff; {
		size := int(ne.Uint16(entry[offset:]))
		if size < xtEntryHeaderSize || offset+size > targetOff {
			break
		}
		if cString(entry[offset+2:offset+31]) == "comment" {
			return cString(entry[offset+xtEntryHeaderSize : offset+size])
		}
		offset += size
	}
	return ""
}

// iptEntryIdentity fingerprints a rule's match and target bytes, leaving out
// the counters and kernel bookkeeping so it stays stable between samples.
func iptEntryIdentity(entry []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(entry[:84])
	_, _ = h.Write(entry[iptEntrySize:])
	return strconv.FormatUint(h.Sum64(), 16)
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func getsockoptBuffer(fd, level, name int, buf []byte) error {
	size := uint32(len(buf))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
