package osusers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

// fakeBackend records what Operate asked it to do, so a test can prove that a
// refusal never reached the operating system.
type fakeBackend struct {
	snap       Snapshot
	collectErr error
	ops        []string
	err        error
	lastCreate CreateRequest
}

func (f *fakeBackend) Collect(context.Context) (Snapshot, error) {
	return f.snap, f.collectErr
}

func (f *fakeBackend) SupportedOperations() []string { return f.snap.SupportedOperations }

func (f *fakeBackend) SetUserEnabled(_ context.Context, name string, enabled bool) error {
	f.ops = append(f.ops, "SetUserEnabled:"+name+":"+boolText(enabled))
	return f.err
}

func (f *fakeBackend) SetAdministrator(_ context.Context, name string, admin bool) error {
	f.ops = append(f.ops, "SetAdministrator:"+name+":"+boolText(admin))
	return f.err
}

func (f *fakeBackend) CreateUser(_ context.Context, req CreateRequest) error {
	f.lastCreate = req
	f.ops = append(f.ops, "CreateUser:"+req.Name)
	return f.err
}

func (f *fakeBackend) DeleteUser(_ context.Context, name string, removeHome bool) error {
	f.ops = append(f.ops, "DeleteUser:"+name+":"+boolText(removeHome))
	return f.err
}

func (f *fakeBackend) LogOffSession(_ context.Context, id string) error {
	f.ops = append(f.ops, "LogOffSession:"+id)
	return f.err
}

func (f *fakeBackend) Reboot(_ context.Context, delay uint64, message string) error {
	f.ops = append(f.ops, "Reboot")
	return f.err
}

func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func allOperations() []string {
	return []string{OpReboot, OpLogOffSession, OpEnableUser, OpDisableUser,
		OpGrantAdministrator, OpRevokeAdministrator, OpCreateUser, OpDeleteUser}
}

// twoAdminDevice is a machine the agent runs as root on, with two enabled
// administrators and one standard user.
func twoAdminDevice() Snapshot {
	return Snapshot{
		Platform:            PlatformMacOS,
		AgentAccount:        "root",
		AdministratorGroup:  "admin",
		SupportedOperations: allOperations(),
		Users: []User{
			{Name: "root", Enabled: true, Administrator: true, AccountType: AccountSystem},
			{Name: "kimo", Enabled: true, Administrator: true, AccountType: AccountLocal},
			{Name: "guest", Enabled: true, AccountType: AccountLocal},
		},
		Sessions: []Session{
			{SessionID: "console", Account: "kimo", Type: SessionConsole, State: SessionActive},
		},
	}
}

func input(pairs ...string) *wusp.Message {
	msg := wusp.NewMessage()
	for i := 0; i+1 < len(pairs); i += 2 {
		msg.Set(wusp.WUSPOSUsersPrefix+pairs[i], wusp.String(pairs[i+1]))
	}
	return msg
}

func run(t *testing.T, backend *fakeBackend, enabled bool, cmd string, in *wusp.Message) Result {
	t.Helper()
	return Operate(context.Background(), backend, enabled, cmd, in)
}

// The agent never acts on the account it runs as.
func TestOperateRefusesSelfTarget(t *testing.T) {
	commands := map[string]string{
		"DisableUser":         wusp.WUSPOSUsersDisableUserCommand,
		"DeleteUser":          wusp.WUSPOSUsersDeleteUserCommand,
		"RevokeAdministrator": wusp.WUSPOSUsersRevokeAdministratorCommand,
		"EnableUser":          wusp.WUSPOSUsersEnableUserCommand,
		"GrantAdministrator":  wusp.WUSPOSUsersGrantAdministratorCommand,
	}
	for name, cmd := range commands {
		backend := &fakeBackend{snap: twoAdminDevice()}
		result := run(t, backend, true, cmd, input("Target", "root"))
		if result.Code != CodeSelfTarget {
			t.Fatalf("%s on the agent's own account: code = %q, want %q", name, result.Code, CodeSelfTarget)
		}
		if result.Status != "Error" {
			t.Fatalf("%s self-target status = %q, want Error", name, result.Status)
		}
		if len(backend.ops) != 0 {
			t.Fatalf("%s self-target reached the OS: %v", name, backend.ops)
		}
	}
}

// Logging the agent's own session off would cut the agent's own access, so it
// is refused the same way.
func TestOperateRefusesLogOffOfAgentSession(t *testing.T) {
	snap := twoAdminDevice()
	snap.Sessions = []Session{{SessionID: "console", Account: "root", Type: SessionConsole}}
	backend := &fakeBackend{snap: snap}
	result := run(t, backend, true, wusp.WUSPOSUsersLogOffSessionCommand, input("SessionID", "console"))
	if result.Code != CodeSelfTarget {
		t.Fatalf("code = %q, want %q", result.Code, CodeSelfTarget)
	}
	if len(backend.ops) != 0 {
		t.Fatalf("the refusal reached the OS: %v", backend.ops)
	}
}

// The last enabled administrator never loses its rights, is never disabled
// and is never deleted.
func TestOperateRefusesLastAdmin(t *testing.T) {
	soleAdmin := func() Snapshot {
		snap := twoAdminDevice()
		snap.AgentAccount = "wantasticd"
		snap.Users = []User{
			{Name: "kimo", Enabled: true, Administrator: true, AccountType: AccountLocal},
			{Name: "disabledadmin", Enabled: false, Administrator: true, AccountType: AccountLocal},
			{Name: "standard", Enabled: true, AccountType: AccountLocal},
		}
		snap.Sessions = nil
		return snap
	}
	for name, cmd := range map[string]string{
		"DisableUser":         wusp.WUSPOSUsersDisableUserCommand,
		"DeleteUser":          wusp.WUSPOSUsersDeleteUserCommand,
		"RevokeAdministrator": wusp.WUSPOSUsersRevokeAdministratorCommand,
	} {
		backend := &fakeBackend{snap: soleAdmin()}
		result := run(t, backend, true, cmd, input("Target", "kimo"))
		if result.Code != CodeLastAdmin {
			t.Fatalf("%s on the last enabled administrator: code = %q, want %q", name, result.Code, CodeLastAdmin)
		}
		if len(backend.ops) != 0 {
			t.Fatalf("%s last-admin refusal reached the OS: %v", name, backend.ops)
		}
	}
	// A disabled administrator does not count as an administrator that is
	// still there, but a second enabled one does.
	backend := &fakeBackend{snap: twoAdminDevice()}
	backend.snap.AgentAccount = "wantasticd"
	result := run(t, backend, true, wusp.WUSPOSUsersRevokeAdministratorCommand, input("Target", "kimo"))
	if result.Code != CodeOK {
		t.Fatalf("with a second enabled administrator, revoking is allowed: %+v", result)
	}
}

// A command the device does not advertise is refused rather than attempted.
func TestOperateRefusesUnadvertisedCommand(t *testing.T) {
	snap := twoAdminDevice()
	snap.SupportedOperations = []string{OpEnableUser} // no DeleteUser, no Reboot
	backend := &fakeBackend{snap: snap}

	for _, cmd := range []string{wusp.WUSPOSUsersDeleteUserCommand, wusp.WUSPOSUsersRebootCommand} {
		result := run(t, backend, true, cmd, input("Target", "guest"))
		if result.Code != CodeUnsupported {
			t.Fatalf("%s: code = %q, want %q", cmd, result.Code, CodeUnsupported)
		}
	}
	if len(backend.ops) != 0 {
		t.Fatalf("an unadvertised command reached the OS: %v", backend.ops)
	}
}

// With the collection off, every command is refused: the device is not
// offering them.
func TestOperateRefusedWhenDisabled(t *testing.T) {
	backend := &fakeBackend{snap: twoAdminDevice()}
	result := run(t, backend, false, wusp.WUSPOSUsersRebootCommand, nil)
	if result.Code != CodeUnsupported {
		t.Fatalf("code = %q, want %q", result.Code, CodeUnsupported)
	}
	if len(backend.ops) != 0 {
		t.Fatalf("a disabled backend ran %v", backend.ops)
	}
}

// A path that is not one of this model's commands is not this model's problem.
func TestOperateRejectsForeignCommand(t *testing.T) {
	backend := &fakeBackend{snap: twoAdminDevice()}
	result := run(t, backend, true, "Device.WUSP_OLT.Reboot()", nil)
	if result.Code != CodeUnsupported {
		t.Fatalf("code = %q, want %q", result.Code, CodeUnsupported)
	}
}

func TestOperateInputValidation(t *testing.T) {
	cases := []struct {
		name  string
		cmd   string
		input *wusp.Message
		code  string
	}{
		{"no target", wusp.WUSPOSUsersDisableUserCommand, nil, CodeInvalidInput},
		{"unknown account", wusp.WUSPOSUsersDisableUserCommand, input("Target", "nobody-here"), CodeNotFound},
		{"no session id", wusp.WUSPOSUsersLogOffSessionCommand, nil, CodeInvalidInput},
		{"unknown session", wusp.WUSPOSUsersLogOffSessionCommand, input("SessionID", "ttys999"), CodeSessionNotFound},
		{"no new name", wusp.WUSPOSUsersCreateUserCommand, nil, CodeInvalidInput},
		{"shell-special name", wusp.WUSPOSUsersCreateUserCommand, input("NewName", "a;rm -rf /"), CodeInvalidInput},
		{"path-special name", wusp.WUSPOSUsersCreateUserCommand, input("NewName", "../../etc/passwd"), CodeInvalidInput},
		{"existing name", wusp.WUSPOSUsersCreateUserCommand, input("NewName", "guest"), CodeExists},
		{"reboot delay not a number", wusp.WUSPOSUsersRebootCommand, input("RebootDelay", "soon"), CodeInvalidInput},
		{"reboot delay over the limit", wusp.WUSPOSUsersRebootCommand, input("RebootDelay", "7200"), CodeInvalidInput},
	}
	for _, tc := range cases {
		backend := &fakeBackend{snap: twoAdminDevice()}
		result := run(t, backend, true, tc.cmd, tc.input)
		if result.Code != tc.code {
			t.Fatalf("%s: code = %q, want %q (message %q)", tc.name, result.Code, tc.code, result.Message)
		}
		if len(backend.ops) != 0 {
			t.Fatalf("%s reached the OS: %v", tc.name, backend.ops)
		}
	}
}

// Deleting an account out from under a live session is refused as in_use.
func TestOperateRefusesDeletingLoggedInAccount(t *testing.T) {
	snap := twoAdminDevice()
	snap.AgentAccount = "wantasticd"
	snap.Sessions = []Session{{SessionID: "console", Account: "guest", Type: SessionConsole}}
	backend := &fakeBackend{snap: snap}
	result := run(t, backend, true, wusp.WUSPOSUsersDeleteUserCommand, input("Target", "guest"))
	if result.Code != CodeInUse {
		t.Fatalf("code = %q, want %q", result.Code, CodeInUse)
	}
	if len(backend.ops) != 0 {
		t.Fatalf("the refusal reached the OS: %v", backend.ops)
	}
}

func TestOperateHappyPaths(t *testing.T) {
	snap := twoAdminDevice()
	snap.AgentAccount = "wantasticd"
	snap.Sessions = []Session{{SessionID: "ttys001", Account: "guest", Type: SessionSSH}}

	cases := []struct {
		cmd   string
		input *wusp.Message
		op    string
	}{
		{wusp.WUSPOSUsersDisableUserCommand, input("Target", "guest"), "SetUserEnabled:guest:false"},
		{wusp.WUSPOSUsersGrantAdministratorCommand, input("Target", "guest"), "SetAdministrator:guest:true"},
		{wusp.WUSPOSUsersDeleteUserCommand, input("Target", "kimo", "RemoveHomeDirectory", "true"), "DeleteUser:kimo:true"},
		{wusp.WUSPOSUsersLogOffSessionCommand, input("SessionID", "ttys001"), "LogOffSession:ttys001"},
		{wusp.WUSPOSUsersRebootCommand, input("RebootDelay", "60"), "Reboot"},
		{wusp.WUSPOSUsersCreateUserCommand, input("NewName", "newtech", "Password", "s3cret", "NewAdministrator", "true"), "CreateUser:newtech"},
	}
	for _, tc := range cases {
		backend := &fakeBackend{snap: snap}
		result := run(t, backend, true, tc.cmd, tc.input)
		if result.Code != CodeOK || result.Status != "Success" {
			t.Fatalf("%s: %+v", tc.cmd, result)
		}
		if len(backend.ops) != 1 || backend.ops[0] != tc.op {
			t.Fatalf("%s ran %v, want [%s]", tc.cmd, backend.ops, tc.op)
		}
		// A result message never carries the credential that was sent.
		if strings.Contains(result.Message, "s3cret") {
			t.Fatalf("%s leaked the password into the result message: %q", tc.cmd, result.Message)
		}
	}
}

// The Password input reaches the backend and nowhere else.
func TestCreateUserPasswordStaysInTheRequest(t *testing.T) {
	snap := twoAdminDevice()
	snap.AgentAccount = "wantasticd"
	backend := &fakeBackend{snap: snap}
	result := run(t, backend, true, wusp.WUSPOSUsersCreateUserCommand,
		input("NewName", "newtech", "NewFullName", "New Tech", "Password", "s3cret"))
	if result.Code != CodeOK {
		t.Fatalf("%+v", result)
	}
	if backend.lastCreate.Password != "s3cret" {
		t.Fatalf("the backend did not receive the password")
	}
	if backend.lastCreate.FullName != "New Tech" {
		t.Fatalf("FullName = %q", backend.lastCreate.FullName)
	}
	msg := ResultMessage(result)
	for _, field := range msg.Fields {
		if strings.Contains(wusp.ValueToString(field.Val), "s3cret") {
			t.Fatalf("the Operate reply carries the credential at %s", field.Path)
		}
	}
	if err := wusp.ValidateMessageFast(msg); err != nil {
		t.Fatalf("the Operate reply does not validate: %v", err)
	}
}

// An OS failure is reported with the code the platform named, or one read off
// its own wording; never outside the closed vocabulary.
func TestOperateMapsBackendFailures(t *testing.T) {
	snap := twoAdminDevice()
	snap.AgentAccount = "wantasticd"

	coded := &fakeBackend{snap: snap, err: Coded(CodePolicyDenied, "an MDM profile manages this account")}
	result := run(t, coded, true, wusp.WUSPOSUsersDisableUserCommand, input("Target", "guest"))
	if result.Code != CodePolicyDenied {
		t.Fatalf("a coded backend error lost its code: %+v", result)
	}

	denied := &fakeBackend{snap: snap, err: errors.New("dseditgroup: Operation not permitted")}
	result = run(t, denied, true, wusp.WUSPOSUsersDisableUserCommand, input("Target", "guest"))
	if result.Code != CodePermissionDenied {
		t.Fatalf("code = %q, want %q", result.Code, CodePermissionDenied)
	}

	readFail := &fakeBackend{snap: snap, collectErr: errors.New("dscl: Permission denied")}
	result = run(t, readFail, true, wusp.WUSPOSUsersDisableUserCommand, input("Target", "guest"))
	if result.Code != CodePermissionDenied {
		t.Fatalf("a failed snapshot read: code = %q", result.Code)
	}
}

// Every code any path can report belongs to the model's closed vocabulary.
func TestEveryReportedCodeIsInTheClosedVocabulary(t *testing.T) {
	allowed := map[string]bool{}
	for _, code := range []string{CodeOK, CodeNotFound, CodeUnsupported, CodePermissionDenied,
		CodeLastAdmin, CodeSelfTarget, CodeSessionNotFound, CodeInUse, CodeInvalidInput,
		CodeExists, CodePolicyDenied} {
		allowed[code] = true
	}
	snap := twoAdminDevice()
	probes := []*wusp.Message{
		nil,
		input("Target", "root"),
		input("Target", "kimo"),
		input("Target", "nobody"),
		input("SessionID", "console"),
		input("SessionID", "nope"),
		input("NewName", "guest"),
		input("NewName", "!!bad!!"),
		input("RebootDelay", "99999"),
	}
	for _, cmd := range []string{
		wusp.WUSPOSUsersRebootCommand, wusp.WUSPOSUsersLogOffSessionCommand,
		wusp.WUSPOSUsersEnableUserCommand, wusp.WUSPOSUsersDisableUserCommand,
		wusp.WUSPOSUsersGrantAdministratorCommand, wusp.WUSPOSUsersRevokeAdministratorCommand,
		wusp.WUSPOSUsersCreateUserCommand, wusp.WUSPOSUsersDeleteUserCommand,
		"Device.Nothing()",
	} {
		for _, probe := range probes {
			for _, enabled := range []bool{true, false} {
				result := Operate(context.Background(), &fakeBackend{snap: snap}, enabled, cmd, probe)
				if !allowed[result.Code] {
					t.Fatalf("%s produced code %q, outside the closed vocabulary", cmd, result.Code)
				}
				if result.Status != "Success" && result.Status != "Error" {
					t.Fatalf("%s produced status %q", cmd, result.Status)
				}
				if msg := ResultMessage(result); wusp.ValidateMessageFast(msg) != nil {
					t.Fatalf("%s produced a reply that does not validate", cmd)
				}
			}
		}
	}
}

// A nil backend is an unsupported platform, not a crash.
func TestOperateWithNoBackend(t *testing.T) {
	result := Operate(context.Background(), nil, true, wusp.WUSPOSUsersRebootCommand, nil)
	if result.Code != CodeUnsupported {
		t.Fatalf("code = %q, want %q", result.Code, CodeUnsupported)
	}
}

func TestCommandOperation(t *testing.T) {
	if op, ok := CommandOperation(wusp.WUSPOSUsersCreateUserCommand); !ok || op != OpCreateUser {
		t.Fatalf("CommandOperation = %q, %v", op, ok)
	}
	if _, ok := CommandOperation("Device.Reboot()"); ok {
		t.Fatalf("Device.Reboot() is not a Device.WUSP_OSUsers command")
	}
}
