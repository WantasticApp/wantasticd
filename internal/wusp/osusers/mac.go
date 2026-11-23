package osusers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

// This is the macOS account backend. It reads OpenDirectory's local node and
// the session table, and applies the account actions with the system tools
// macOS documents for them.
//
// Every binary is named by its absolute path and every argument is a value
// this package validated first: no shell is involved anywhere, so nothing a
// console sends can be interpreted as a command.
const (
	dsclPath         = "/usr/bin/dscl"
	whoPath          = "/usr/bin/who"
	pwpolicyPath     = "/usr/bin/pwpolicy"
	dseditgroupPath  = "/usr/sbin/dseditgroup"
	sysadminctlPath  = "/usr/sbin/sysadminctl"
	launchctlPath    = "/bin/launchctl"
	pkillPath        = "/usr/bin/pkill"
	shutdownPath     = "/sbin/shutdown"
	wallPath         = "/usr/bin/wall"
	macAdminGroup    = "admin"
	macCollectBudget = 20 * time.Second
)

// Runner runs a platform command and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// StdinRunner runs a platform command with text on its standard input. It
// exists so a credential reaches a tool without ever appearing in the process
// table, where any local user could read it.
type StdinRunner func(ctx context.Context, stdin, name string, args ...string) ([]byte, error)

// MacBackend implements Backend on macOS.
type MacBackend struct {
	run      Runner
	runStdin StdinRunner
	now      func() time.Time
	account  string
}

// NewMacBackend builds the macOS account backend. run is the agent's command
// runner; a nil runStdin uses the default, which pipes the text in.
func NewMacBackend(run Runner, runStdin StdinRunner) *MacBackend {
	if runStdin == nil {
		runStdin = execWithStdin
	}
	return &MacBackend{run: run, runStdin: runStdin, now: time.Now, account: currentAccountName()}
}

// currentAccountName is the account the agent itself runs as. Nothing may
// disable, delete or deprivilege it.
func currentAccountName() string {
	if os.Geteuid() == 0 {
		return "root"
	}
	if current, err := user.Current(); err == nil && current.Username != "" {
		return current.Username
	}
	return strconv.Itoa(os.Geteuid())
}

// SupportedOperations lists what this device accepts. Anything absent is
// refused with LastOperationCode=unsupported.
func (m *MacBackend) SupportedOperations() []string {
	return []string{
		OpReboot, OpLogOffSession, OpEnableUser, OpDisableUser,
		OpGrantAdministrator, OpRevokeAdministrator, OpCreateUser, OpDeleteUser,
	}
}

// Collect reads the local accounts and the live sessions. Passive: it reads
// the directory node and the session table and changes nothing.
func (m *MacBackend) Collect(ctx context.Context) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, macCollectBudget)
	defer cancel()

	snap := Snapshot{
		Platform:            PlatformMacOS,
		AgentAccount:        m.account,
		AdministratorGroup:  macAdminGroup,
		SupportedOperations: m.SupportedOperations(),
	}

	raw, err := m.output(ctx, dsclPath, ".", "-readall", "/Users",
		"RecordName", "UniqueID", "RealName", "NFSHomeDirectory", "UserShell",
		"AuthenticationAuthority", "IsHidden", "GeneratedUID", "accountPolicyData")
	if err != nil {
		return snap, fmt.Errorf("read local accounts: %w", err)
	}
	users, generatedUIDs := MacUsersFromRecords(ParseDSCLReadall(raw))

	groupsText, groupsErr := m.output(ctx, dsclPath, ".", "-readall", "/Groups",
		"RecordName", "GroupMembership", "GroupMembers")
	groups := map[string][]string{}
	if groupsErr == nil {
		groups = MacGroupsFromRecords(ParseDSCLReadall(groupsText), generatedUIDs)
	} else {
		snap.StatusDetail = "group membership unavailable: " + groupsErr.Error()
	}
	for i := range users {
		member := groups[strings.ToLower(users[i].Name)]
		users[i].Groups = member
		users[i].Administrator = containsFold(member, macAdminGroup)
	}
	snap.Users = users

	if whoText, whoErr := m.output(ctx, whoPath, "-u"); whoErr == nil {
		snap.Sessions = ParseWho(whoText, m.now())
	} else if snap.StatusDetail == "" {
		snap.StatusDetail = "session table unavailable: " + whoErr.Error()
	}
	snap.Status = StatusOK
	return snap, nil
}

// SetUserEnabled switches an account's ability to log in. pwpolicy is the
// documented path; where it is unavailable the AuthenticationAuthority marker
// it writes is set directly, which is the same change.
func (m *MacBackend) SetUserEnabled(ctx context.Context, name string, enabled bool) error {
	if err := validAccountName(name); err != nil {
		return Coded(CodeInvalidInput, "%s", err.Error())
	}
	flag := "-disableuser"
	if enabled {
		flag = "-enableuser"
	}
	if _, err := m.output(ctx, pwpolicyPath, "-u", name, flag); err == nil {
		return nil
	}
	action := "-append"
	if enabled {
		action = "-delete"
	}
	_, err := m.output(ctx, dsclPath, ".", action, "/Users/"+name, "AuthenticationAuthority", ";DisabledUser;")
	return err
}

// SetAdministrator adds or removes the account from the admin group.
func (m *MacBackend) SetAdministrator(ctx context.Context, name string, administrator bool) error {
	if err := validAccountName(name); err != nil {
		return Coded(CodeInvalidInput, "%s", err.Error())
	}
	flag := "-d"
	if administrator {
		flag = "-a"
	}
	_, err := m.output(ctx, dseditgroupPath, "-o", "edit", flag, name, "-t", "user", macAdminGroup)
	return err
}

// CreateUser adds a local account. The password goes in on standard input, so
// it never appears in the process table; macOS refuses to create an account
// with no password at all, which the model says to expect.
func (m *MacBackend) CreateUser(ctx context.Context, req CreateRequest) error {
	if err := validAccountName(req.Name); err != nil {
		return Coded(CodeInvalidInput, "%s", err.Error())
	}
	if req.Password == "" {
		return Coded(CodeInvalidInput, "macOS requires an initial password for a new account")
	}
	args := []string{"-addUser", req.Name}
	if full := strings.TrimSpace(req.FullName); full != "" {
		args = append(args, "-fullName", full)
	}
	if req.Administrator {
		args = append(args, "-admin")
	}
	args = append(args, "-password", "-")
	_, err := m.runStdin(ctx, req.Password+"\n", sysadminctlPath, args...)
	return err
}

// DeleteUser removes a local account. removeHomeDirectory=false keeps the home
// where it is; true lets sysadminctl do what macOS does with it, which is to
// move it under /Users/Deleted Users rather than erase it.
func (m *MacBackend) DeleteUser(ctx context.Context, name string, removeHomeDirectory bool) error {
	if err := validAccountName(name); err != nil {
		return Coded(CodeInvalidInput, "%s", err.Error())
	}
	args := []string{"-deleteUser", name}
	if !removeHomeDirectory {
		args = append(args, "-keepHome")
	}
	_, err := m.output(ctx, sysadminctlPath, args...)
	return err
}

// LogOffSession ends one login session: the window-server session for the
// console, and the login shell for a pseudo-terminal.
func (m *MacBackend) LogOffSession(ctx context.Context, sessionID string) error {
	sessionID = strings.TrimSpace(sessionID)
	if !validSessionLine(sessionID) {
		return Coded(CodeInvalidInput, "%q is not a session this device reported", sessionID)
	}
	if strings.HasPrefix(sessionID, "console") {
		snap, err := m.Collect(ctx)
		if err != nil {
			return err
		}
		session, found := findSession(snap.Sessions, sessionID)
		if !found {
			return Coded(CodeSessionNotFound, "no live session %s", sessionID)
		}
		uid, err := lookupUID(session.Account)
		if err != nil {
			return Coded(CodeNotFound, "%s", err.Error())
		}
		_, err = m.output(ctx, launchctlPath, "bootout", "gui/"+strconv.Itoa(uid))
		return err
	}
	_, err := m.output(ctx, pkillPath, "-t", sessionID)
	return err
}

// Reboot restarts the machine, after telling anyone logged in when it is
// coming. It runs once, in the background, so the reply reaches the console
// before the machine goes.
func (m *MacBackend) Reboot(ctx context.Context, delaySeconds uint64, message string) error {
	if delaySeconds > maxRebootDelaySeconds {
		return Coded(CodeInvalidInput, "RebootDelay must be at most %d seconds", maxRebootDelaySeconds)
	}
	if text := strings.TrimSpace(message); text != "" {
		_, _ = m.runStdin(ctx, text+"\n", wallPath)
	}
	run, delay := m.run, time.Duration(delaySeconds)*time.Second
	go func() {
		if delay > 0 {
			time.Sleep(delay)
		}
		// A fresh context: the Operate request's one is long gone.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = run(shutdownCtx, shutdownPath, "-r", "now")
	}()
	return nil
}

// output runs a command and returns its text, folding the tool's own wording
// into the error so the result code can be read off it.
func (m *MacBackend) output(ctx context.Context, name string, args ...string) (string, error) {
	if m.run == nil {
		return "", fmt.Errorf("no command runner available")
	}
	out, err := m.run(ctx, name, args...)
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%s: %v: %s", name, err, firstLine(text))
		}
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return text, nil
}

// validSessionLine accepts only the tty/console names macOS reports, so a
// session identifier from the console cannot name anything else.
func validSessionLine(id string) bool {
	if id == "" || len(id) > 32 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func lookupUID(account string) (int, error) {
	found, err := user.Lookup(account)
	if err != nil {
		return 0, fmt.Errorf("no account named %s", account)
	}
	uid, err := strconv.Atoi(found.Uid)
	if err != nil {
		return 0, fmt.Errorf("account %s has no numeric uid", account)
	}
	return uid, nil
}

// execWithStdin is the default StdinRunner: it starts the binary directly,
// with no shell, and feeds it the text.
func execWithStdin(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %v: %s", name, err, firstLine(strings.TrimSpace(string(out))))
	}
	return out, nil
}

func firstLine(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return text[:i]
	}
	return text
}

func containsFold(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), want) {
			return true
		}
	}
	return false
}
