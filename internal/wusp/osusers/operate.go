package osusers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"wantastic-agent/internal/wusp"
)

// LastOperationCode is a closed vocabulary: the console shows the code, so a
// new one would be meaningless there. Every refusal and every failure maps
// onto one of these.
const (
	CodeOK               = "ok"
	CodeNotFound         = "not_found"
	CodeUnsupported      = "unsupported"
	CodePermissionDenied = "permission_denied"
	CodeLastAdmin        = "last_admin"
	CodeSelfTarget       = "self_target"
	CodeSessionNotFound  = "session_not_found"
	CodeInUse            = "in_use"
	CodeInvalidInput     = "invalid_input"
	CodeExists           = "exists"
	CodePolicyDenied     = "policy_denied"
)

// Operation names, as SupportedOperations spells them.
const (
	OpReboot               = "Reboot"
	OpLogOffSession        = "LogOffSession"
	OpEnableUser           = "EnableUser"
	OpDisableUser          = "DisableUser"
	OpGrantAdministrator   = "GrantAdministrator"
	OpRevokeAdministrator  = "RevokeAdministrator"
	OpCreateUser           = "CreateUser"
	OpDeleteUser           = "DeleteUser"
	maxRebootDelaySeconds  = 3600
	maxAccountNameLength   = 128
	maxNewPasswordLength   = 256
	maxRebootMessageLength = 256
)

// Result is the outcome of one Operate command, reported in
// LastOperationStatus / LastOperationCode / LastOperationMessage.
type Result struct {
	Status  string // "" before the first command, then "Success" or "Error"
	Code    string
	Message string
}

func ok(message string) Result { return Result{Status: "Success", Code: CodeOK, Message: message} }
func fail(code, format string, args ...any) Result {
	return Result{Status: "Error", Code: code, Message: fmt.Sprintf(format, args...)}
}

// CodedError lets a platform backend name the model code for a failure it
// understands better than this package can.
type CodedError struct {
	Code    string
	Message string
}

func (e *CodedError) Error() string { return e.Message }

// Coded builds a CodedError.
func Coded(code, format string, args ...any) error {
	return &CodedError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// CreateRequest carries the CreateUser inputs. Password is never logged,
// persisted or echoed into a result message.
type CreateRequest struct {
	Name          string
	FullName      string
	Administrator bool
	Password      string
}

// Backend is what a platform must implement for the account operations. Every
// method runs once, when the console asks; none of them is called on a timer.
type Backend interface {
	// Collect reads the accounts and sessions. Passive: it changes nothing.
	Collect(ctx context.Context) (Snapshot, error)
	// SupportedOperations lists what this device will accept.
	SupportedOperations() []string

	SetUserEnabled(ctx context.Context, name string, enabled bool) error
	SetAdministrator(ctx context.Context, name string, administrator bool) error
	CreateUser(ctx context.Context, req CreateRequest) error
	DeleteUser(ctx context.Context, name string, removeHomeDirectory bool) error
	LogOffSession(ctx context.Context, sessionID string) error
	Reboot(ctx context.Context, delaySeconds uint64, message string) error
}

// CommandOperation maps an Operate command path onto its operation name.
// Anything else is not one of this model's commands.
func CommandOperation(cmd string) (string, bool) {
	switch strings.TrimSpace(cmd) {
	case wusp.WUSPOSUsersRebootCommand:
		return OpReboot, true
	case wusp.WUSPOSUsersLogOffSessionCommand:
		return OpLogOffSession, true
	case wusp.WUSPOSUsersEnableUserCommand:
		return OpEnableUser, true
	case wusp.WUSPOSUsersDisableUserCommand:
		return OpDisableUser, true
	case wusp.WUSPOSUsersGrantAdministratorCommand:
		return OpGrantAdministrator, true
	case wusp.WUSPOSUsersRevokeAdministratorCommand:
		return OpRevokeAdministrator, true
	case wusp.WUSPOSUsersCreateUserCommand:
		return OpCreateUser, true
	case wusp.WUSPOSUsersDeleteUserCommand:
		return OpDeleteUser, true
	default:
		return "", false
	}
}

// targetOperations are the commands that act on an account named in Target.
func targetOperation(op string) bool {
	switch op {
	case OpEnableUser, OpDisableUser, OpGrantAdministrator, OpRevokeAdministrator, OpDeleteUser:
		return true
	default:
		return false
	}
}

// deprivilegingOperation reports whether an operation could leave the machine
// with no enabled administrator.
func deprivilegingOperation(op string) bool {
	switch op {
	case OpDisableUser, OpDeleteUser, OpRevokeAdministrator:
		return true
	default:
		return false
	}
}

// Operate runs one account command and returns its outcome. It never returns
// an error for a refusal: the model's whole point is that the console sees the
// code, so a refusal is a Result with Status=Error and one of the codes above.
//
// enabled is Device.WUSP_OSUsers.Enable. With the collection off, every
// command is refused: the device is not offering them.
func Operate(ctx context.Context, backend Backend, enabled bool, cmd string, input *wusp.Message) Result {
	op, known := CommandOperation(cmd)
	if !known {
		return fail(CodeUnsupported, "%s is not a Device.WUSP_OSUsers command", strings.TrimSpace(cmd))
	}
	if backend == nil {
		return fail(CodeUnsupported, "this platform has no account backend")
	}
	if !enabled {
		return fail(CodeUnsupported, "account operations are disabled on this device")
	}
	if !supports(backend.SupportedOperations(), op) {
		return fail(CodeUnsupported, "%s is not in SupportedOperations on this device", op)
	}

	// Reboot touches no account, so it needs no snapshot.
	if op == OpReboot {
		delay, err := rebootDelay(input)
		if err != nil {
			return fail(CodeInvalidInput, "%s", err.Error())
		}
		message := clip(inputString(input, "RebootMessage"), maxRebootMessageLength)
		if err := backend.Reboot(ctx, delay, message); err != nil {
			return failed(op, err)
		}
		if delay == 0 {
			return ok("Rebooting now")
		}
		return ok("Rebooting in " + strconv.FormatUint(delay, 10) + " seconds")
	}

	snap, err := backend.Collect(ctx)
	if err != nil {
		return failed(op, err)
	}

	if op == OpLogOffSession {
		id := inputString(input, "SessionID")
		if id == "" {
			return fail(CodeInvalidInput, "LogOffSession requires a SessionID input")
		}
		session, found := findSession(snap.Sessions, id)
		if !found {
			return fail(CodeSessionNotFound, "no live session %s", id)
		}
		if sameAccount(session.Account, snap.AgentAccount) {
			return fail(CodeSelfTarget, "session %s belongs to the agent's own account %s", id, snap.AgentAccount)
		}
		if err := backend.LogOffSession(ctx, session.SessionID); err != nil {
			return failed(op, err)
		}
		return ok("Signed " + session.Account + " out of session " + session.SessionID)
	}

	if op == OpCreateUser {
		name := inputString(input, "NewName")
		if err := validAccountName(name); err != nil {
			return fail(CodeInvalidInput, "%s", err.Error())
		}
		if _, found := findUser(snap.Users, name); found {
			return fail(CodeExists, "an account named %s already exists", name)
		}
		if sameAccount(name, snap.AgentAccount) {
			return fail(CodeSelfTarget, "%s is the account the agent runs as", name)
		}
		password := inputString(input, "Password")
		if len(password) > maxNewPasswordLength {
			return fail(CodeInvalidInput, "the initial password is longer than %d characters", maxNewPasswordLength)
		}
		req := CreateRequest{
			Name:          name,
			FullName:      clip(inputString(input, "NewFullName"), maxAccountNameLength),
			Administrator: inputBool(input, "NewAdministrator"),
			Password:      password,
		}
		if err := backend.CreateUser(ctx, req); err != nil {
			return failed(op, err)
		}
		// The result message names the account, never the credential.
		if req.Administrator {
			return ok("Created administrator account " + req.Name)
		}
		return ok("Created account " + req.Name)
	}

	if !targetOperation(op) {
		return fail(CodeUnsupported, "%s is not an account operation", op)
	}

	target := inputString(input, "Target")
	if target == "" {
		return fail(CodeInvalidInput, "%s requires a Target input", op)
	}
	// The agent never acts on the account it is running as, so no remote
	// action can lock the machine out of its own administration.
	if sameAccount(target, snap.AgentAccount) {
		return fail(CodeSelfTarget, "%s is the account the agent runs as", target)
	}
	user, found := findUser(snap.Users, target)
	if !found {
		return fail(CodeNotFound, "no local account named %s", target)
	}
	// The last enabled administrator never loses its rights, is never
	// disabled and is never deleted.
	if deprivilegingOperation(op) && isLastEnabledAdministrator(snap.Users, user) {
		return fail(CodeLastAdmin, "%s is the last enabled administrator on this device", user.Name)
	}

	switch op {
	case OpEnableUser:
		if user.Enabled {
			return ok(user.Name + " was already enabled")
		}
		if err := backend.SetUserEnabled(ctx, user.Name, true); err != nil {
			return failed(op, err)
		}
		return ok("Enabled " + user.Name)
	case OpDisableUser:
		if !user.Enabled {
			return ok(user.Name + " was already disabled")
		}
		if err := backend.SetUserEnabled(ctx, user.Name, false); err != nil {
			return failed(op, err)
		}
		return ok("Disabled " + user.Name)
	case OpGrantAdministrator:
		if user.Administrator {
			return ok(user.Name + " was already an administrator")
		}
		if err := backend.SetAdministrator(ctx, user.Name, true); err != nil {
			return failed(op, err)
		}
		return ok("Granted administrator to " + user.Name)
	case OpRevokeAdministrator:
		if !user.Administrator {
			return ok(user.Name + " was not an administrator")
		}
		if err := backend.SetAdministrator(ctx, user.Name, false); err != nil {
			return failed(op, err)
		}
		return ok("Revoked administrator from " + user.Name)
	case OpDeleteUser:
		// Deleting an account out from under a live session loses the
		// person's work; the console can sign them out first.
		if _, logged := findSessionForAccount(snap.Sessions, user.Name); logged {
			return fail(CodeInUse, "%s is logged in; sign the session off first", user.Name)
		}
		if err := backend.DeleteUser(ctx, user.Name, inputBool(input, "RemoveHomeDirectory")); err != nil {
			return failed(op, err)
		}
		return ok("Deleted account " + user.Name)
	}
	return fail(CodeUnsupported, "%s is not implemented on this platform", op)
}

// ResultMessage renders a Result as the Operate reply, the same three leaves
// the next collection will report.
func ResultMessage(result Result) *wusp.Message {
	msg := wusp.NewMessage()
	prefix := wusp.WUSPOSUsersPrefix
	msg.Set(prefix+"LastOperationStatus", wusp.String(result.Status))
	msg.Set(prefix+"LastOperationCode", wusp.String(result.Code))
	msg.Set(prefix+"LastOperationMessage", wusp.String(truncate(result.Message, 256)))
	return msg
}

// failed turns a backend error into a Result, honouring a code the backend
// named itself and otherwise reading the platform's own wording.
func failed(op string, err error) Result {
	if err == nil {
		return ok(op + " finished")
	}
	var coded *CodedError
	if asCoded(err, &coded) {
		return fail(coded.Code, "%s", coded.Message)
	}
	return fail(classifyError(err), "%s: %s", op, err.Error())
}

func asCoded(err error, out **CodedError) bool {
	for err != nil {
		if coded, ok := err.(*CodedError); ok {
			*out = coded
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

// classifyError reads a platform error message for the one thing the model
// cares about: whether the agent simply was not allowed to do it.
func classifyError(err error) string {
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "permission denied"),
		strings.Contains(text, "access is denied"),
		strings.Contains(text, "operation not permitted"),
		strings.Contains(text, "not authorized"),
		strings.Contains(text, "must be run as root"),
		strings.Contains(text, "requires administrator"):
		return CodePermissionDenied
	case strings.Contains(text, "already exists"), strings.Contains(text, "name is already in use"):
		return CodeExists
	case strings.Contains(text, "not found"), strings.Contains(text, "no such"), strings.Contains(text, "cannot be found"):
		return CodeNotFound
	case strings.Contains(text, "policy"), strings.Contains(text, "managed by"), strings.Contains(text, "mdm"):
		return CodePolicyDenied
	case strings.Contains(text, "logged on"), strings.Contains(text, "logged in"), strings.Contains(text, "in use"):
		return CodeInUse
	case strings.Contains(text, "not supported"), strings.Contains(text, "unsupported"), strings.Contains(text, "not implemented"):
		return CodeUnsupported
	default:
		return CodePolicyDenied
	}
}

// isLastEnabledAdministrator reports whether user is the only enabled
// administrator left on the device.
func isLastEnabledAdministrator(users []User, user User) bool {
	if !user.Administrator || !user.Enabled {
		return false
	}
	for _, other := range users {
		if sameAccount(other.Name, user.Name) {
			continue
		}
		if other.Administrator && other.Enabled {
			return false
		}
	}
	return true
}

func supports(operations []string, op string) bool {
	for _, one := range operations {
		if strings.EqualFold(strings.TrimSpace(one), op) {
			return true
		}
	}
	return false
}

// sameAccount compares account names the way the platforms do: Windows is
// case-insensitive and macOS short names are lower-case by convention, so a
// case-insensitive match is the safe side for a refusal.
func sameAccount(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	// A Windows session account may arrive as DOMAIN\name or name@realm.
	return strings.EqualFold(stripAccountQualifier(a), stripAccountQualifier(b))
}

func stripAccountQualifier(name string) string {
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	return name
}

func findUser(users []User, name string) (User, bool) {
	for _, user := range users {
		if sameAccount(user.Name, name) {
			return user, true
		}
	}
	return User{}, false
}

func findSession(sessions []Session, id string) (Session, bool) {
	id = strings.TrimSpace(id)
	for _, session := range sessions {
		if strings.EqualFold(strings.TrimSpace(session.SessionID), id) {
			return session, true
		}
	}
	return Session{}, false
}

func findSessionForAccount(sessions []Session, name string) (Session, bool) {
	for _, session := range sessions {
		if sameAccount(session.Account, name) {
			return session, true
		}
	}
	return Session{}, false
}

// validAccountName checks a new account name before it reaches any platform
// tool, so nothing shell-special or path-special can be passed on.
func validAccountName(name string) error {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return fmt.Errorf("an account name is required")
	case len(name) > maxAccountNameLength:
		return fmt.Errorf("the account name is longer than %d characters", maxAccountNameLength)
	case strings.HasPrefix(name, "-"), strings.HasPrefix(name, "."):
		return fmt.Errorf("an account name cannot start with %q", name[:1])
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return fmt.Errorf("the account name may only hold letters, digits, dot, dash and underscore")
		}
	}
	return nil
}

func rebootDelay(input *wusp.Message) (uint64, error) {
	raw := inputString(input, "RebootDelay")
	if raw == "" {
		return 0, nil
	}
	delay, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("RebootDelay must be a whole number of seconds")
	}
	if delay > maxRebootDelaySeconds {
		return 0, fmt.Errorf("RebootDelay must be at most %d seconds", maxRebootDelaySeconds)
	}
	return delay, nil
}

// inputString reads one Operate input by its leaf name. The inputs are flat
// and never persisted: they exist only inside the request.
func inputString(input *wusp.Message, leaf string) string {
	if input == nil {
		return ""
	}
	full := wusp.WUSPOSUsersPrefix + leaf
	for _, field := range input.Fields {
		if field.Path == full || field.Path == leaf || strings.HasSuffix(field.Path, "."+leaf) {
			return strings.TrimSpace(wusp.ValueToString(field.Val))
		}
	}
	return ""
}

func inputBool(input *wusp.Message, leaf string) bool {
	switch strings.ToLower(inputString(input, leaf)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func clip(value string, limit int) string { return truncate(value, limit) }
