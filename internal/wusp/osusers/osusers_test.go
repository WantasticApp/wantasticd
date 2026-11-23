package osusers

import (
	"strconv"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func TestAppendDisabledClearsTablesAndOperations(t *testing.T) {
	snap := Snapshot{
		Platform:            PlatformWindows,
		SupportedOperations: []string{OpReboot},
		Users:               []User{{Name: "kimo", Enabled: true, Administrator: true}},
		Sessions:            []Session{{SessionID: "1", Account: "kimo", Type: SessionConsole}},
	}
	msg := wusp.NewMessage()
	Append(msg, snap, true, false, time.Unix(10, 0), NewRecorder())

	if got := value(msg, wusp.WUSPOSUsersPrefix+"Status"); got != StatusDisabled {
		t.Fatalf("Status = %q", got)
	}
	// Off clears the tables and advertises nothing, so the console offers
	// no action and the device refuses every command.
	if got := value(msg, wusp.WUSPOSUsersPrefix+"SupportedOperations"); got != "" {
		t.Fatalf("SupportedOperations = %q with the collection off", got)
	}
	for _, leaf := range []string{"UserNumberOfEntries", "SessionNumberOfEntries", "TotalUsers", "AdministratorCount", "LoggedInCount"} {
		if got := value(msg, wusp.WUSPOSUsersPrefix+leaf); got != "0" {
			t.Fatalf("%s = %s, want 0", leaf, got)
		}
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestAppendNotInstalled(t *testing.T) {
	msg := wusp.NewMessage()
	Append(msg, Snapshot{}, false, true, time.Unix(10, 0), NewRecorder())
	if got := value(msg, wusp.WUSPOSUsersPrefix+"Status"); got != StatusNotInstalled {
		t.Fatalf("Status = %q", got)
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// Past the cap the model reports the accounts it can and keeps the true count
// in TotalUsers; service and hidden accounts are dropped before people are.
func TestAppendCapsUsersAndSessions(t *testing.T) {
	snap := Snapshot{Platform: PlatformWindows, Status: StatusOK}
	for i := 0; i < wusp.WUSPOSUsersMaxUsers+20; i++ {
		snap.Users = append(snap.Users, User{
			Name:        "svc" + strconv.Itoa(i),
			Enabled:     true,
			AccountType: AccountService,
		})
	}
	snap.Users = append(snap.Users, User{Name: "person", Enabled: true, Administrator: true, AccountType: AccountLocal})
	for i := 0; i < wusp.WUSPOSUsersMaxSessions+5; i++ {
		snap.Sessions = append(snap.Sessions, Session{
			SessionID: strconv.Itoa(i), Account: "person", Type: SessionRDP, State: SessionActive,
		})
	}
	msg := wusp.NewMessage()
	Append(msg, snap, true, true, time.Unix(10, 0), NewRecorder())

	if got := value(msg, wusp.WUSPOSUsersPrefix+"TotalUsers"); got != strconv.Itoa(len(snap.Users)) {
		t.Fatalf("TotalUsers = %s, want %d", got, len(snap.Users))
	}
	if got := value(msg, wusp.WUSPOSUsersPrefix+"UserNumberOfEntries"); got != strconv.Itoa(wusp.WUSPOSUsersMaxUsers) {
		t.Fatalf("UserNumberOfEntries = %s, want the cap", got)
	}
	if got := value(msg, wusp.WUSPOSUsersPrefix+"SessionNumberOfEntries"); got != strconv.Itoa(wusp.WUSPOSUsersMaxSessions) {
		t.Fatalf("SessionNumberOfEntries = %s, want the cap", got)
	}
	// The real account outranks the service accounts, so the cap keeps it.
	if got := value(msg, wusp.WUSPOSUsersPrefix+"User.1.Name"); got != "person" {
		t.Fatalf("User.1.Name = %q, want the real account first", got)
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestSummarizeSessionTypes(t *testing.T) {
	cases := []struct {
		sessions []Session
		want     string
	}{
		{nil, SessionSummaryNone},
		{[]Session{{Type: SessionConsole}}, SessionSummaryConsole},
		{[]Session{{Type: SessionRDP}}, SessionSummaryRemote},
		{[]Session{{Type: SessionSSH}}, SessionSummaryRemote},
		{[]Session{{Type: SessionScreenSharing}}, SessionSummaryRemote},
		{[]Session{{Type: SessionOther}}, SessionSummaryService},
		// A console session wins over a remote one.
		{[]Session{{Type: SessionRDP}, {Type: SessionConsole}}, SessionSummaryConsole},
	}
	for _, tc := range cases {
		if got := SummarizeSessionTypes(tc.sessions); got != tc.want {
			t.Fatalf("SummarizeSessionTypes(%+v) = %q, want %q", tc.sessions, got, tc.want)
		}
	}
}

func TestNormalizersFoldUnknownValues(t *testing.T) {
	if got := NormalizeAccountType("Local"); got != AccountLocal {
		t.Fatalf("NormalizeAccountType = %q", got)
	}
	if got := NormalizeAccountType("microsoft"); got != "" {
		t.Fatalf("an unknown account type should be empty, got %q", got)
	}
	if got := NormalizeSessionType("Telnet"); got != SessionOther {
		t.Fatalf("NormalizeSessionType = %q", got)
	}
	if got := NormalizeSessionState("Connected"); got != "" {
		t.Fatalf("an unknown session state should be empty, got %q", got)
	}
}

// The latest command's outcome is what the next collection reports.
func TestRecorderFeedsLastOperationLeaves(t *testing.T) {
	recorder := NewRecorder()
	msg := wusp.NewMessage()
	Append(msg, Snapshot{Platform: PlatformMacOS, Status: StatusOK}, true, true, time.Unix(10, 0), recorder)
	if got := value(msg, wusp.WUSPOSUsersPrefix+"LastOperationStatus"); got != "" {
		t.Fatalf("before any command LastOperationStatus = %q, want empty", got)
	}

	recorder.Record(Result{Status: "Error", Code: CodeLastAdmin, Message: "kimo is the last enabled administrator"})
	msg = wusp.NewMessage()
	Append(msg, Snapshot{Platform: PlatformMacOS, Status: StatusOK}, true, true, time.Unix(20, 0), recorder)
	if got := value(msg, wusp.WUSPOSUsersPrefix+"LastOperationCode"); got != CodeLastAdmin {
		t.Fatalf("LastOperationCode = %q", got)
	}
	if got := value(msg, wusp.WUSPOSUsersPrefix+"LastOperationStatus"); got != "Error" {
		t.Fatalf("LastOperationStatus = %q", got)
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// A long group list and an over-long display name are clipped to the model's
// limits rather than failing validation.
func TestAppendRespectsModelLimits(t *testing.T) {
	long := ""
	for len(long) < 600 {
		long += "verylongname-"
	}
	groups := make([]string, 0, 80)
	for i := 0; i < 80; i++ {
		groups = append(groups, "group-with-a-long-name-"+strconv.Itoa(i))
	}
	snap := Snapshot{
		Platform: PlatformWindows,
		Status:   StatusOK,
		Users: []User{{
			Name: long, FullName: long, UID: long, HomeDirectory: long,
			Shell: long, Groups: groups, Enabled: true, AccountType: AccountLocal,
		}},
		Sessions:            []Session{{SessionID: long, Account: long, ClientName: long, ClientAddress: long, Type: SessionRDP, State: SessionActive}},
		AgentAccount:        long,
		AdministratorGroup:  long,
		SupportedOperations: groups,
	}
	msg := wusp.NewMessage()
	Append(msg, snap, true, true, time.Unix(10, 0), NewRecorder())
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("over-long values must be clipped, not rejected: %v", err)
	}
}
