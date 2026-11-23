package osusers

import (
	"strconv"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

const usersDump = `AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2,SRP-RFC5054-4096-SHA512-PBKDF2>
GeneratedUID: 7A1B9C0D-1111-2222-3333-444455556666
NFSHomeDirectory: /Users/kimo
RealName: Kimo Dev
RecordName: kimo
UniqueID: 501
UserShell: /bin/zsh
accountPolicyData:
 <?xml version="1.0" encoding="UTF-8"?>
 <plist version="1.0">
 <dict>
 	<key>creationTime</key>
 	<real>1663000000.123456</real>
 	<key>failedLoginCount</key>
 	<integer>0</integer>
 	<key>passwordLastSetTime</key>
 	<real>1699999999.5</real>
 </dict>
 </plist>
-
AuthenticationAuthority: ;ShadowHash; ;DisabledUser;
GeneratedUID: 8B2C0D1E-5555-6666-7777-888899990000
NFSHomeDirectory: /Users/temp
RealName: Temp Account
RecordName: temp
UniqueID: 502
UserShell: /bin/bash
-
AuthenticationAuthority: ;basic;
GeneratedUID: 00000000-0000-0000-0000-000000000000
NFSHomeDirectory: /var/empty
RealName: Spotlight
RecordName: _spotlight
UniqueID: 89
UserShell: /usr/bin/false
-
`

const groupsDump = `GroupMembership: root kimo
GroupMembers: 7A1B9C0D-1111-2222-3333-444455556666
RecordName: admin
-
GroupMembership: kimo temp
RecordName: staff
-
RecordName: wheel
GroupMembership: root
-
`

func TestParseDSCLReadallAndUsers(t *testing.T) {
	records := ParseDSCLReadall(usersDump)
	if len(records) != 3 {
		t.Fatalf("expected three records, got %d", len(records))
	}
	users, generatedUIDs := MacUsersFromRecords(records)
	if len(users) != 3 {
		t.Fatalf("expected three accounts, got %d", len(users))
	}

	byName := map[string]User{}
	for _, user := range users {
		byName[user.Name] = user
	}

	kimo := byName["kimo"]
	if !kimo.Enabled {
		t.Fatalf("kimo should be enabled")
	}
	if kimo.FullName != "Kimo Dev" || kimo.UID != "501" || kimo.HomeDirectory != "/Users/kimo" || kimo.Shell != "/bin/zsh" {
		t.Fatalf("kimo = %+v", kimo)
	}
	if kimo.AccountType != AccountLocal || kimo.Hidden {
		t.Fatalf("kimo type=%q hidden=%v", kimo.AccountType, kimo.Hidden)
	}
	// The dates come from the embedded accountPolicyData plist, and are
	// reported as Auth*, not Password*, so the hub does not drop them.
	if kimo.AuthLastChangedTime != 1699999999 {
		t.Fatalf("AuthLastChangedTime = %d", kimo.AuthLastChangedTime)
	}
	if kimo.CreatedTime != 1663000000 {
		t.Fatalf("CreatedTime = %d", kimo.CreatedTime)
	}

	// A ";DisabledUser;" marker in AuthenticationAuthority is how macOS
	// records a disabled local account.
	if byName["temp"].Enabled {
		t.Fatalf("temp carries ;DisabledUser; and must read as disabled")
	}

	spotlight := byName["_spotlight"]
	if !spotlight.Hidden {
		t.Fatalf("_spotlight should be hidden from the login window")
	}
	if spotlight.AccountType != AccountService {
		t.Fatalf("_spotlight type = %q, want %q", spotlight.AccountType, AccountService)
	}

	if generatedUIDs["7A1B9C0D-1111-2222-3333-444455556666"] != "kimo" {
		t.Fatalf("GeneratedUID index = %v", generatedUIDs)
	}
}

func TestMacGroupsFromRecords(t *testing.T) {
	_, generatedUIDs := MacUsersFromRecords(ParseDSCLReadall(usersDump))
	groups := MacGroupsFromRecords(ParseDSCLReadall(groupsDump), generatedUIDs)

	if !containsFold(groups["kimo"], "admin") {
		t.Fatalf("kimo should be in admin: %v", groups["kimo"])
	}
	if !containsFold(groups["kimo"], "staff") {
		t.Fatalf("kimo should be in staff: %v", groups["kimo"])
	}
	if containsFold(groups["temp"], "admin") {
		t.Fatalf("temp is not an administrator: %v", groups["temp"])
	}
	// kimo is listed twice in admin, by name and by UUID; it stays one entry.
	count := 0
	for _, group := range groups["kimo"] {
		if group == "admin" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("admin appears %d times for kimo", count)
	}
}

func TestParseAdminMembership(t *testing.T) {
	members := ParseAdminMembership("RecordName: admin\nGroupMembership: root kimo\n")
	if len(members) != 2 || members[1] != "kimo" {
		t.Fatalf("ParseAdminMembership = %v", members)
	}
}

func TestParseWho(t *testing.T) {
	now := time.Date(2026, time.November, 23, 12, 0, 0, 0, time.UTC)
	sessions := ParseWho(`kimo     console  Nov 20 09:12   old     201
kimo     ttys000  Nov 23 10:04      .    4411
root     ttys001  Nov 23 10:05  00:35    4502 (10.0.0.5)
tech   + ttys002  Nov 23 11:00  01:00    4600 (laptop.lan)
`, now)
	if len(sessions) != 4 {
		t.Fatalf("expected four sessions, got %d: %+v", len(sessions), sessions)
	}

	console := sessions[0]
	if console.SessionID != "console" || console.Account != "kimo" || console.Type != SessionConsole {
		t.Fatalf("console session = %+v", console)
	}
	if console.State != SessionIdle {
		t.Fatalf("an \"old\" session is idle, got %q", console.State)
	}
	if console.LoginTime == 0 {
		t.Fatalf("the console session has no login time")
	}

	local := sessions[1]
	if local.Type != SessionOther {
		t.Fatalf("a local terminal with no remote host is other, got %q", local.Type)
	}
	if local.State != SessionActive || local.IdleSeconds != 0 {
		t.Fatalf("an idle marker of \".\" means active: %+v", local)
	}

	remote := sessions[2]
	if remote.Type != SessionSSH {
		t.Fatalf("a pty with a remote host arrived over ssh, got %q", remote.Type)
	}
	if remote.ClientAddress != "10.0.0.5" || remote.ClientName != "" {
		t.Fatalf("an IP host belongs in ClientAddress: %+v", remote)
	}
	if remote.IdleSeconds != 35*60 {
		t.Fatalf("IdleSeconds = %d, want %d", remote.IdleSeconds, 35*60)
	}

	named := sessions[3]
	if named.ClientName != "laptop.lan" || named.ClientAddress != "" {
		t.Fatalf("a named host belongs in ClientName: %+v", named)
	}
	if named.IdleSeconds != 3600 {
		t.Fatalf("IdleSeconds = %d, want 3600", named.IdleSeconds)
	}
}

// A login stamp printed without a year that would land in the future is read
// as last year's.
func TestParseWhoRollsBackAFutureDate(t *testing.T) {
	now := time.Date(2026, time.January, 5, 12, 0, 0, 0, time.UTC)
	sessions := ParseWho("kimo console Dec 28 23:00 .\n", now)
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions", len(sessions))
	}
	login := time.Unix(int64(sessions[0].LoginTime), 0).UTC()
	if login.Year() != 2025 || login.Month() != time.December {
		t.Fatalf("login time = %s, want December 2025", login)
	}
}

// What the macOS collector produces validates against the registered schema.
func TestMacSnapshotAppendValidates(t *testing.T) {
	users, generatedUIDs := MacUsersFromRecords(ParseDSCLReadall(usersDump))
	groups := MacGroupsFromRecords(ParseDSCLReadall(groupsDump), generatedUIDs)
	for i := range users {
		users[i].Groups = groups[users[i].Name]
		users[i].Administrator = containsFold(users[i].Groups, "admin")
	}
	snap := Snapshot{
		Platform:            PlatformMacOS,
		Status:              StatusOK,
		AgentAccount:        "root",
		AdministratorGroup:  "admin",
		SupportedOperations: []string{OpReboot, OpLogOffSession, OpEnableUser, OpDisableUser, OpGrantAdministrator, OpRevokeAdministrator, OpCreateUser, OpDeleteUser},
		Users:               users,
		Sessions:            ParseWho("kimo console Nov 20 09:12 .\n", time.Now()),
	}
	msg := wusp.NewMessage()
	Append(msg, snap, true, true, time.Unix(1_700_000_000, 0), NewRecorder())
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("a macOS reading must validate: %v", err)
	}

	// The account with a live console session says so, in both places.
	for i := 1; i <= len(users); i++ {
		base := wusp.WUSPOSUsersPrefix + "User." + strconv.Itoa(i) + "."
		if value(msg, base+"Name") != "kimo" {
			continue
		}
		if value(msg, base+"LoggedIn") != "true" {
			t.Fatalf("kimo has a console session but LoggedIn is %q", value(msg, base+"LoggedIn"))
		}
		if value(msg, base+"SessionType") != SessionSummaryConsole {
			t.Fatalf("SessionType = %q, want console", value(msg, base+"SessionType"))
		}
		if value(msg, base+"Administrator") != "true" {
			t.Fatalf("kimo is in admin but Administrator is %q", value(msg, base+"Administrator"))
		}
	}
	if got := value(msg, wusp.WUSPOSUsersPrefix+"AdministratorGroup"); got != "admin" {
		t.Fatalf("AdministratorGroup = %q", got)
	}
	if got := value(msg, wusp.WUSPOSUsersPrefix+"AgentAccount"); got != "root" {
		t.Fatalf("AgentAccount = %q", got)
	}
}

func value(msg *wusp.Message, path string) string {
	for _, field := range msg.Fields {
		if field.Path == path {
			return wusp.ValueToString(field.Val)
		}
	}
	return ""
}
