package neighbors

import (
	"net"
	"strconv"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func mac(t *testing.T, text string) net.HardwareAddr {
	t.Helper()
	parsed, err := net.ParseMAC(text)
	if err != nil {
		t.Fatalf("parse MAC %q: %v", text, err)
	}
	return parsed
}

func fieldValue(t *testing.T, msg *wusp.Message, path string) string {
	t.Helper()
	for _, field := range msg.Fields {
		if field.Path == path {
			return wusp.ValueToString(field.Val)
		}
	}
	t.Fatalf("field %s is missing", path)
	return ""
}

func hasField(msg *wusp.Message, path string) bool {
	for _, field := range msg.Fields {
		if field.Path == path {
			return true
		}
	}
	return false
}

// A dual-stack host is one host: its IPv4 address and every cached IPv6
// address belong to a single row keyed by (Interface, MACAddress).
func TestBuildMergesDualStackHostIntoOneRow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	snap := Snapshot{
		Interfaces: []Interface{{Name: "en0", GatewayAddress: "192.168.1.1"}},
		Entries: []Entry{
			{Interface: "en0", IP: net.ParseIP("192.168.1.24"), MAC: mac(t, "e0:5d:54:11:22:33"), State: StateStale},
			{Interface: "en0", IP: net.ParseIP("fe80::1234"), MAC: mac(t, "e0:5d:54:11:22:33"), State: StateReachable},
			{Interface: "en0", IP: net.ParseIP("2001:db8::9"), MAC: mac(t, "E0:5D:54:11:22:33"), State: StateStale},
		},
	}
	rows := Build(snap, now, NewFirstSeen())
	if len(rows) != 1 {
		t.Fatalf("expected one row for one dual-stack host, got %d: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.IPv4Address != "192.168.1.24" {
		t.Fatalf("IPv4Address = %q", row.IPv4Address)
	}
	if len(row.IPv6Addresses) != 2 {
		t.Fatalf("IPv6Addresses = %v, want both cached addresses", row.IPv6Addresses)
	}
	// The most informative cache state wins over a stale one.
	if row.State != StateReachable || !row.Reachable {
		t.Fatalf("State=%q Reachable=%v, want reachable", row.State, row.Reachable)
	}
	if row.OUI != "E05D54" {
		t.Fatalf("OUI = %q, want E05D54", row.OUI)
	}
}

// Rows the OS has no link-layer address for key on their address, so two
// incomplete entries stay two rows.
func TestBuildKeepsIncompleteEntriesApart(t *testing.T) {
	snap := Snapshot{Entries: []Entry{
		{Interface: "en0", IP: net.ParseIP("192.168.1.50"), State: StateIncomplete},
		{Interface: "en0", IP: net.ParseIP("192.168.1.51"), State: StateIncomplete},
	}}
	rows := Build(snap, time.Unix(100, 0), NewFirstSeen())
	if len(rows) != 2 {
		t.Fatalf("expected two incomplete rows, got %d", len(rows))
	}
	for _, row := range rows {
		if row.MACAddress != "" {
			t.Fatalf("incomplete row carries a MAC: %q", row.MACAddress)
		}
		if row.Reachable {
			t.Fatalf("an incomplete entry must not read as reachable")
		}
	}
}

// Reachable is read off the cache state and nothing else.
func TestReachableIsDerivedFromStateOnly(t *testing.T) {
	live := map[string]bool{
		StateReachable: true, StatePermanent: true,
		StateStale: false, StateDelay: false, StateProbe: false,
		StateIncomplete: false, StateFailed: false, "": false,
	}
	for state, want := range live {
		if got := Reachable(state); got != want {
			t.Fatalf("Reachable(%q) = %v, want %v", state, got, want)
		}
	}
}

// A randomized (locally administered) MAC belongs to no vendor.
func TestVendorAndOUI(t *testing.T) {
	if got := OUIFromMAC("E0:5D:54:11:22:33"); got != "E05D54" {
		t.Fatalf("OUIFromMAC = %q", got)
	}
	if got := OUIFromMAC("e0-5d-54-11-22-33"); got != "E05D54" {
		t.Fatalf("OUIFromMAC with dashes = %q", got)
	}
	if got := OUIFromMAC(""); got != "" {
		t.Fatalf("OUIFromMAC of an unknown MAC = %q, want empty", got)
	}
	if !LocallyAdministered("A2:11:22:33:44:55") {
		t.Fatalf("A2:... has the locally administered bit set")
	}
	if LocallyAdministered("E0:5D:54:11:22:33") {
		t.Fatalf("E0:... is a vendor OUI, not locally administered")
	}
	snap := Snapshot{Entries: []Entry{
		{Interface: "en0", IP: net.ParseIP("10.0.0.2"), MAC: mac(t, "a2:11:22:33:44:55"), State: StateReachable},
	}}
	rows := Build(snap, time.Unix(1, 0), NewFirstSeen())
	if rows[0].Vendor != "" {
		t.Fatalf("a randomized MAC reported vendor %q", rows[0].Vendor)
	}
	if rows[0].OUI != "A21122" {
		t.Fatalf("OUI = %q", rows[0].OUI)
	}
}

// Past the table cap the model reports the most recently seen neighbors and
// keeps the true count in TotalNeighbors.
func TestAppendCapsTableButKeepsTrueCount(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	snap := Snapshot{Interfaces: []Interface{{Name: "en0", Up: true}}}
	const total = wusp.WUSPNeighborsMaxNeighbors + 40
	for i := 0; i < total; i++ {
		snap.Entries = append(snap.Entries, Entry{
			Interface: "en0",
			IP:        net.IPv4(10, 0, byte(i/256), byte(i%256)),
			MAC:       net.HardwareAddr{0x02, 0x00, byte(i >> 8), byte(i), 0x00, 0x01},
			State:     StateStale,
			LastSeen:  now.Unix() - int64(total-i),
		})
	}
	msg := wusp.NewMessage()
	Append(msg, snap, true, true, now, NewFirstSeen())

	if got := fieldValue(t, msg, wusp.WUSPNeighborsPrefix+"TotalNeighbors"); got != strconv.Itoa(total) {
		t.Fatalf("TotalNeighbors = %s, want %d", got, total)
	}
	if got := fieldValue(t, msg, wusp.WUSPNeighborsPrefix+"NeighborNumberOfEntries"); got != strconv.Itoa(wusp.WUSPNeighborsMaxNeighbors) {
		t.Fatalf("NeighborNumberOfEntries = %s, want the cap", got)
	}
	// The newest entry survives the cap.
	if got := fieldValue(t, msg, wusp.WUSPNeighborsPrefix+"Neighbor.1.LastSeenTime"); got != strconv.FormatInt(now.Unix()-1, 10) {
		t.Fatalf("Neighbor.1.LastSeenTime = %s, want the most recently seen", got)
	}
	if hasField(msg, wusp.WUSPNeighborsPrefix+"Neighbor."+strconv.Itoa(wusp.WUSPNeighborsMaxNeighbors+1)+".Interface") {
		t.Fatalf("a row past the cap was reported")
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("the capped table does not validate against the schema: %v", err)
	}
}

// Off clears the tables: a disabled collection reports nothing rather than
// what an earlier one found.
func TestAppendDisabledClearsTables(t *testing.T) {
	snap := Snapshot{
		Platform:   PlatformMacOS,
		Interfaces: []Interface{{Name: "en0", Up: true}},
		Entries:    []Entry{{Interface: "en0", IP: net.ParseIP("10.0.0.5"), MAC: mac(t, "e0:5d:54:00:00:01"), State: StateReachable}},
	}
	msg := wusp.NewMessage()
	Append(msg, snap, true, false, time.Unix(10, 0), NewFirstSeen())

	if got := fieldValue(t, msg, wusp.WUSPNeighborsPrefix+"Status"); got != StatusDisabled {
		t.Fatalf("Status = %q, want %q", got, StatusDisabled)
	}
	for _, leaf := range []string{"NeighborNumberOfEntries", "InterfaceNumberOfEntries", "TotalNeighbors"} {
		if got := fieldValue(t, msg, wusp.WUSPNeighborsPrefix+leaf); got != "0" {
			t.Fatalf("%s = %s with the collection off, want 0", leaf, got)
		}
	}
	if hasField(msg, wusp.WUSPNeighborsPrefix+"Neighbor.1.Interface") {
		t.Fatalf("a neighbor row survived the collection being turned off")
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// An unsupported platform says so rather than reporting an empty but working
// collection.
func TestAppendNotInstalled(t *testing.T) {
	msg := wusp.NewMessage()
	Append(msg, Snapshot{}, false, true, time.Unix(10, 0), NewFirstSeen())
	if got := fieldValue(t, msg, wusp.WUSPNeighborsPrefix+"Status"); got != StatusNotInstalled {
		t.Fatalf("Status = %q, want %q", got, StatusNotInstalled)
	}
	if got := fieldValue(t, msg, wusp.WUSPNeighborsPrefix+"Installed"); got != "false" {
		t.Fatalf("Installed = %q", got)
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// A full reading validates against the registered schema, including every
// enum and length limit the hub declared.
func TestAppendFullReadingValidates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	long := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		long = append(long, "2001:db8:aaaa:bbbb:cccc:dddd:eeee:"+strconv.FormatInt(int64(i), 16))
	}
	snap := Snapshot{
		Platform: PlatformWindows,
		Status:   StatusOK,
		Interfaces: []Interface{{
			Name: "Ethernet", Alias: "Intel I225-V", Type: "ethernet",
			MACAddress: "E0:5D:54:AA:BB:CC", IPv4Address: "192.168.1.24/24",
			IPv6Addresses: long, GatewayAddress: "192.168.1.1", Up: true,
		}},
		Entries: []Entry{
			{Interface: "Ethernet", IP: net.ParseIP("192.168.1.1"), MAC: mac(t, "e0:5d:54:00:00:01"),
				State: StatePermanent, Static: true, IsRouter: true, HostName: "gateway", HostNameSource: "hosts", LastSeen: now.Unix() - 5},
			{Interface: "Ethernet", IP: net.ParseIP("192.168.1.90"), MAC: mac(t, "a2:00:00:00:00:02"),
				State: "something-the-model-does-not-know", HostNameSource: "wins"},
		},
	}
	msg := wusp.NewMessage()
	Append(msg, snap, true, true, now, NewFirstSeen())
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("a full reading must validate: %v", err)
	}
	// The gateway neighbor says so, from the interface's own default route.
	found := false
	for i := 1; i <= 2; i++ {
		base := wusp.WUSPNeighborsPrefix + "Neighbor." + strconv.Itoa(i) + "."
		if fieldValue(t, msg, base+"IPv4Address") != "192.168.1.1" {
			continue
		}
		found = true
		if fieldValue(t, msg, base+"IsGateway") != "true" {
			t.Fatalf("the default gateway neighbor does not report IsGateway")
		}
		if fieldValue(t, msg, base+"HostNameSource") != "hosts" {
			t.Fatalf("the hosts-file name source was lost")
		}
	}
	if !found {
		t.Fatalf("the gateway neighbor row is missing")
	}
	// An unknown state and an unknown name source degrade rather than fail.
	states := map[string]bool{}
	for i := 1; i <= 2; i++ {
		states[fieldValue(t, msg, wusp.WUSPNeighborsPrefix+"Neighbor."+strconv.Itoa(i)+".State")] = true
	}
	if !states[""] {
		t.Fatalf("an unknown cache state should be reported as empty, got %v", states)
	}
	// The joined IPv6 list fits the model's MaxLength without a cut address.
	joined := fieldValue(t, msg, wusp.WUSPNeighborsPrefix+"Interface.1.IPv6Addresses")
	if len(joined) > 512 {
		t.Fatalf("IPv6Addresses is %d bytes, over the 512 limit", len(joined))
	}
	if joined != "" && joined[len(joined)-1] == ':' {
		t.Fatalf("IPv6Addresses ends mid-address: %q", joined)
	}
}

// FirstSeenTime is 0 on the collection that first sees a neighbor and the
// original timestamp afterwards.
func TestFirstSeenMemory(t *testing.T) {
	tracker := NewFirstSeen()
	snap := Snapshot{Entries: []Entry{
		{Interface: "en0", IP: net.ParseIP("10.0.0.7"), MAC: mac(t, "e0:5d:54:00:00:07"), State: StateReachable},
	}}
	first := Build(snap, time.Unix(1000, 0), tracker)
	if first[0].FirstSeenTime != 0 {
		t.Fatalf("FirstSeenTime = %d on the first sighting, want 0", first[0].FirstSeenTime)
	}
	second := Build(snap, time.Unix(2000, 0), tracker)
	if second[0].FirstSeenTime != 1000 {
		t.Fatalf("FirstSeenTime = %d on the second sighting, want 1000", second[0].FirstSeenTime)
	}
}

func TestNormalizers(t *testing.T) {
	if got := NormalizeState("REACHABLE"); got != StateReachable {
		t.Fatalf("NormalizeState = %q", got)
	}
	if got := NormalizeState("static"); got != StatePermanent {
		t.Fatalf("NormalizeState(static) = %q", got)
	}
	if got := NormalizeState("bogus"); got != "" {
		t.Fatalf("NormalizeState(bogus) = %q, want empty", got)
	}
	if got := NormalizeHostNameSource("MDNS"); got != "mdns" {
		t.Fatalf("NormalizeHostNameSource = %q", got)
	}
	if got := NormalizeHostNameSource("wins"); got != "other" {
		t.Fatalf("an unknown name source should fold to other, got %q", got)
	}
	if got := NormalizeInterfaceType("Wi-Fi"); got != "other" {
		t.Fatalf("NormalizeInterfaceType = %q", got)
	}
	if got := NormalizeInterfaceType(""); got != "" {
		t.Fatalf("NormalizeInterfaceType of empty = %q", got)
	}
}

func TestParseHostsFile(t *testing.T) {
	hosts := ParseHostsFile(`
# a comment
127.0.0.1	localhost
192.168.1.1   gateway.lan gateway  # trailing comment
192.168.1.1   second-name-ignored
fe80::1       v6host
not-an-ip     nothing
`)
	if got := NameFor(hosts, net.ParseIP("192.168.1.1")); got != "gateway.lan" {
		t.Fatalf("NameFor = %q, want the first name on the first line", got)
	}
	if got := NameFor(hosts, net.ParseIP("fe80::1")); got != "v6host" {
		t.Fatalf("NameFor(v6) = %q", got)
	}
	if got := NameFor(hosts, net.ParseIP("10.9.9.9")); got != "" {
		t.Fatalf("NameFor of an address with no entry = %q, want empty", got)
	}
	if got := NameFor(nil, net.ParseIP("127.0.0.1")); got != "" {
		t.Fatalf("NameFor on an empty map = %q", got)
	}
}
