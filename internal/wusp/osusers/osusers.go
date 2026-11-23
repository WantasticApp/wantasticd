// Package osusers builds Device.WUSP_OSUsers. and runs its guarded account
// operations on Windows and macOS devices.
//
// Everything in this file is OS-neutral: a platform backend reads the local
// accounts and live sessions, and this package shapes them into the model and
// enforces the rules the model encodes.
//
// Collection is passive: the tables are read when a collect asks for them and
// nothing here runs on a timer. An Operate command runs once, only when the
// console asks for it, and only when the device advertised it.
package osusers

import (
	"sort"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/wusp"
)

// Collection statuses, the Device.WUSP_OSUsers.Status enum.
const (
	StatusNotInstalled     = "not_installed"
	StatusDisabled         = "disabled"
	StatusOK               = "ok"
	StatusReadError        = "read_error"
	StatusPermissionDenied = "permission_denied"
)

// Platform families, the Device.WUSP_OSUsers.Platform enum.
const (
	PlatformWindows = "windows"
	PlatformMacOS   = "macos"
)

// Account types, the User.{i}.AccountType enum.
const (
	AccountLocal   = "local"
	AccountDomain  = "domain"
	AccountCloud   = "cloud"
	AccountService = "service"
	AccountSystem  = "system"
)

// Session types, the Session.{i}.Type enum.
const (
	SessionConsole       = "console"
	SessionRDP           = "rdp"
	SessionSSH           = "ssh"
	SessionScreenSharing = "screensharing"
	SessionOther         = "other"
)

// Session states, the Session.{i}.State enum.
const (
	SessionActive       = "active"
	SessionIdle         = "idle"
	SessionDisconnected = "disconnected"
	SessionLocked       = "locked"
)

// User.{i}.SessionType summarizes an account's sessions in a coarser
// vocabulary than Session.{i}.Type.
const (
	SessionSummaryNone    = "none"
	SessionSummaryConsole = "console"
	SessionSummaryRemote  = "remote"
	SessionSummaryService = "service"
)

// User is one local account.
type User struct {
	Name          string
	FullName      string
	UID           string
	Enabled       bool
	Administrator bool
	Groups        []string
	AccountType   string
	Hidden        bool
	LockedOut     bool
	HomeDirectory string
	Shell         string
	LastLogonTime uint64
	// AuthLastChangedTime / AuthExpiresTime / AuthNeverExpires are the
	// password-expiry metadata. They are named Auth* on purpose: the hub
	// drops any path naming a credential from the device snapshot, so
	// Password* here would never reach the console.
	AuthLastChangedTime uint64
	AuthExpiresTime     uint64
	AuthNeverExpires    bool
	CreatedTime         uint64
}

// Session is one live login session.
type Session struct {
	SessionID     string
	Account       string
	Type          string
	State         string
	ClientName    string
	ClientAddress string
	LoginTime     uint64
	IdleSeconds   uint64
}

// Snapshot is one passive reading of the device's accounts and sessions.
type Snapshot struct {
	Platform     string
	Status       string
	StatusDetail string
	// AgentAccount is the account the agent runs as. Every command that
	// would disable, delete or deprivilege it is refused.
	AgentAccount string
	// AdministratorGroup is the group Grant/RevokeAdministrator edits.
	AdministratorGroup string
	// SupportedOperations lists the Operate commands this device accepts.
	// Anything absent from it is refused with LastOperationCode=unsupported.
	SupportedOperations []string
	Users               []User
	Sessions            []Session
}

// Recorder keeps the outcome of the latest Operate command so the next
// collection can report it in LastOperationStatus / Code / Message.
type Recorder struct {
	mu   sync.Mutex
	last Result
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder { return &Recorder{} }

// Record stores an outcome.
func (r *Recorder) Record(result Result) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.last = result
	r.mu.Unlock()
}

// Last returns the stored outcome.
func (r *Recorder) Last() Result {
	if r == nil {
		return Result{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

// Append writes Device.WUSP_OSUsers. onto msg. installed says whether the
// platform exposes local accounts at all; enabled whether the console asked
// for the collection. A disabled backend reports empty tables and, per the
// model, refuses every Operate command.
func Append(msg *wusp.Message, snap Snapshot, installed, enabled bool, now time.Time, recorder *Recorder) {
	if msg == nil {
		return
	}
	prefix := wusp.WUSPOSUsersPrefix
	msg.Set(prefix+"Installed", wusp.Bool(installed))
	msg.Set(prefix+"Enable", wusp.Bool(enabled))
	if snap.Platform != "" {
		msg.Set(prefix+"Platform", wusp.String(snap.Platform))
	}
	appendLastOperation(msg, prefix, recorder)

	switch {
	case !installed:
		appendEmpty(msg, prefix, StatusNotInstalled, snap.StatusDetail)
		return
	case !enabled:
		appendEmpty(msg, prefix, StatusDisabled, "")
		return
	}

	status := snap.Status
	if status == "" {
		status = StatusOK
	}
	msg.Set(prefix+"Status", wusp.String(status))
	msg.Set(prefix+"StatusDetail", wusp.String(truncate(snap.StatusDetail, 256)))
	if status == StatusOK {
		msg.Set(prefix+"LastCollectTime", wusp.Uint(uint64(maxInt64(now.Unix(), 0))))
	}
	msg.Set(prefix+"AgentAccount", wusp.String(truncate(snap.AgentAccount, 128)))
	msg.Set(prefix+"AdministratorGroup", wusp.String(truncate(snap.AdministratorGroup, 64)))
	msg.Set(prefix+"SupportedOperations", wusp.String(joinWithin(snap.SupportedOperations, 256)))

	sessionsByAccount := make(map[string][]Session, len(snap.Sessions))
	for _, session := range snap.Sessions {
		key := strings.ToLower(session.Account)
		sessionsByAccount[key] = append(sessionsByAccount[key], session)
	}

	users := sortedUsers(snap.Users)
	var enabledUsers, admins, loggedIn uint64
	for _, user := range users {
		if user.Enabled {
			enabledUsers++
		}
		if user.Administrator {
			admins++
		}
		if len(sessionsByAccount[strings.ToLower(user.Name)]) > 0 {
			loggedIn++
		}
	}
	msg.Set(prefix+"TotalUsers", wusp.Uint(uint64(len(users))))
	msg.Set(prefix+"EnabledUsers", wusp.Uint(enabledUsers))
	msg.Set(prefix+"AdministratorCount", wusp.Uint(admins))
	msg.Set(prefix+"LoggedInCount", wusp.Uint(loggedIn))

	if len(users) > wusp.WUSPOSUsersMaxUsers {
		users = users[:wusp.WUSPOSUsersMaxUsers]
	}
	msg.Set(prefix+"UserNumberOfEntries", wusp.Uint(uint64(len(users))))
	for i, user := range users {
		base := prefix + "User." + itoa(i+1) + "."
		sessions := sessionsByAccount[strings.ToLower(user.Name)]
		msg.Set(base+"Name", wusp.String(truncate(user.Name, 128)))
		msg.Set(base+"FullName", wusp.String(truncate(user.FullName, 128)))
		msg.Set(base+"UID", wusp.String(truncate(user.UID, 96)))
		msg.Set(base+"Enabled", wusp.Bool(user.Enabled))
		msg.Set(base+"Administrator", wusp.Bool(user.Administrator))
		msg.Set(base+"Groups", wusp.String(joinWithin(user.Groups, 512)))
		msg.Set(base+"AccountType", wusp.String(NormalizeAccountType(user.AccountType)))
		msg.Set(base+"Hidden", wusp.Bool(user.Hidden))
		msg.Set(base+"LockedOut", wusp.Bool(user.LockedOut))
		msg.Set(base+"HomeDirectory", wusp.String(truncate(user.HomeDirectory, 256)))
		msg.Set(base+"Shell", wusp.String(truncate(user.Shell, 128)))
		msg.Set(base+"LastLogonTime", wusp.Uint(user.LastLogonTime))
		msg.Set(base+"LoggedIn", wusp.Bool(len(sessions) > 0))
		msg.Set(base+"SessionType", wusp.String(SummarizeSessionTypes(sessions)))
		msg.Set(base+"AuthLastChangedTime", wusp.Uint(user.AuthLastChangedTime))
		msg.Set(base+"AuthExpiresTime", wusp.Uint(user.AuthExpiresTime))
		msg.Set(base+"AuthNeverExpires", wusp.Bool(user.AuthNeverExpires))
		msg.Set(base+"CreatedTime", wusp.Uint(user.CreatedTime))
	}

	sessions := snap.Sessions
	if len(sessions) > wusp.WUSPOSUsersMaxSessions {
		sessions = sessions[:wusp.WUSPOSUsersMaxSessions]
	}
	msg.Set(prefix+"SessionNumberOfEntries", wusp.Uint(uint64(len(sessions))))
	for i, session := range sessions {
		base := prefix + "Session." + itoa(i+1) + "."
		msg.Set(base+"SessionID", wusp.String(truncate(session.SessionID, 64)))
		msg.Set(base+"Account", wusp.String(truncate(session.Account, 128)))
		msg.Set(base+"Type", wusp.String(NormalizeSessionType(session.Type)))
		msg.Set(base+"State", wusp.String(NormalizeSessionState(session.State)))
		msg.Set(base+"ClientName", wusp.String(truncate(session.ClientName, 128)))
		msg.Set(base+"ClientAddress", wusp.String(truncate(session.ClientAddress, 64)))
		msg.Set(base+"LoginTime", wusp.Uint(session.LoginTime))
		msg.Set(base+"IdleSeconds", wusp.Uint(session.IdleSeconds))
	}
}

func appendLastOperation(msg *wusp.Message, prefix string, recorder *Recorder) {
	last := recorder.Last()
	msg.Set(prefix+"LastOperationStatus", wusp.String(last.Status))
	msg.Set(prefix+"LastOperationCode", wusp.String(last.Code))
	msg.Set(prefix+"LastOperationMessage", wusp.String(truncate(last.Message, 256)))
}

func appendEmpty(msg *wusp.Message, prefix, status, detail string) {
	msg.Set(prefix+"Status", wusp.String(status))
	msg.Set(prefix+"StatusDetail", wusp.String(truncate(detail, 256)))
	msg.Set(prefix+"UserNumberOfEntries", wusp.Uint(0))
	msg.Set(prefix+"SessionNumberOfEntries", wusp.Uint(0))
	msg.Set(prefix+"TotalUsers", wusp.Uint(0))
	msg.Set(prefix+"EnabledUsers", wusp.Uint(0))
	msg.Set(prefix+"AdministratorCount", wusp.Uint(0))
	msg.Set(prefix+"LoggedInCount", wusp.Uint(0))
	msg.Set(prefix+"SupportedOperations", wusp.String(""))
}

// sortedUsers puts the accounts a technician cares about first — real,
// enabled accounts — so the table cap drops service accounts rather than
// people.
func sortedUsers(users []User) []User {
	out := append([]User(nil), users...)
	rank := func(user User) int {
		switch {
		case user.AccountType == AccountSystem || user.AccountType == AccountService:
			return 2
		case user.Hidden:
			return 1
		default:
			return 0
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := rank(out[i]), rank(out[j]); a != b {
			return a < b
		}
		if out[i].Administrator != out[j].Administrator {
			return out[i].Administrator
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// SummarizeSessionTypes folds an account's session types into the coarser
// User.{i}.SessionType vocabulary. A console session wins over a remote one.
func SummarizeSessionTypes(sessions []Session) string {
	if len(sessions) == 0 {
		return SessionSummaryNone
	}
	summary := ""
	for _, session := range sessions {
		switch NormalizeSessionType(session.Type) {
		case SessionConsole:
			return SessionSummaryConsole
		case SessionRDP, SessionSSH, SessionScreenSharing:
			summary = SessionSummaryRemote
		default:
			if summary == "" {
				summary = SessionSummaryService
			}
		}
	}
	if summary == "" {
		return SessionSummaryNone
	}
	return summary
}

// NormalizeAccountType maps a platform's own account classification onto the
// model enum; an unknown value becomes empty rather than failing validation.
func NormalizeAccountType(kind string) string {
	switch k := strings.ToLower(strings.TrimSpace(kind)); k {
	case AccountLocal, AccountDomain, AccountCloud, AccountService, AccountSystem:
		return k
	default:
		return ""
	}
}

// NormalizeSessionType maps a session kind onto the model enum.
func NormalizeSessionType(kind string) string {
	switch k := strings.ToLower(strings.TrimSpace(kind)); k {
	case SessionConsole, SessionRDP, SessionSSH, SessionScreenSharing, SessionOther:
		return k
	case "":
		return ""
	default:
		return SessionOther
	}
}

// NormalizeSessionState maps a session state onto the model enum.
func NormalizeSessionState(state string) string {
	switch s := strings.ToLower(strings.TrimSpace(state)); s {
	case SessionActive, SessionIdle, SessionDisconnected, SessionLocked:
		return s
	default:
		return ""
	}
}

// joinWithin joins items with commas, dropping whole items rather than
// cutting one in half when the model's MaxLength would be exceeded.
func joinWithin(items []string, limit int) string {
	var out strings.Builder
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		extra := len(item)
		if out.Len() > 0 {
			extra++
		}
		if out.Len()+extra > limit {
			break
		}
		if out.Len() > 0 {
			out.WriteByte(',')
		}
		out.WriteString(item)
	}
	return out.String()
}

func truncate(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
