//go:build windows

package platforms

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"wantastic-agent/internal/wusp/osusers"
)

// osUsersSupported: Windows exposes its local accounts through the
// NetUserEnum family and its sessions through WTS enumeration, and takes the
// account actions through the same APIs. Nothing here shells out, so no
// credential ever reaches a command line.
const osUsersSupported = true

var (
	modNetapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserSetInfo          = modNetapi32.NewProc("NetUserSetInfo")
	procNetUserAdd              = modNetapi32.NewProc("NetUserAdd")
	procNetUserDel              = modNetapi32.NewProc("NetUserDel")
	procNetUserGetLocalGroups   = modNetapi32.NewProc("NetUserGetLocalGroups")
	procNetLocalGroupAddMembers = modNetapi32.NewProc("NetLocalGroupAddMembers")
	procNetLocalGroupDelMembers = modNetapi32.NewProc("NetLocalGroupDelMembers")

	modWtsapi32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = modWtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSLogoffSession            = modWtsapi32.NewProc("WTSLogoffSession")

	modAdvapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	procInitiateSystemShutdownExW = modAdvapi32.NewProc("InitiateSystemShutdownExW")

	modUserenv         = windows.NewLazySystemDLL("userenv.dll")
	procDeleteProfileW = modUserenv.NewProc("DeleteProfileW")
)

// UF_* account control flags (lmaccess.h).
const (
	ufAccountDisable    = 0x0002
	ufLockout           = 0x0010
	ufDontExpirePasswd  = 0x10000
	filterNormalAccount = 0x0002
	lgIncludeIndirect   = 0x0001
	userPrivGuest       = 0
	userPrivAdmin       = 2
	// timeqForever is what NetUserEnum reports for a value that never
	// happens, e.g. an account that does not expire.
	timeqForever = 0xFFFFFFFF
	// maxPreferredLength (MAX_PREFERRED_LENGTH) lets netapi32 size its own
	// answer buffer.
	maxPreferredLength = 0xFFFFFFFF
)

// WTS_INFO_CLASS values used here (wtsapi32.h).
const (
	wtsUserName      = 5
	wtsClientName    = 10
	wtsClientAddress = 14
	wtsSessionInfo   = 24
)

// userInfo3 mirrors USER_INFO_3 (lmaccess.h).
type userInfo3 struct {
	Name            *uint16
	Password        *uint16
	PasswordAge     uint32
	Priv            uint32
	HomeDir         *uint16
	Comment         *uint16
	Flags           uint32
	ScriptPath      *uint16
	AuthFlags       uint32
	FullName        *uint16
	UsrComment      *uint16
	Parms           *uint16
	Workstations    *uint16
	LastLogon       uint32
	LastLogoff      uint32
	AcctExpires     uint32
	MaxStorage      uint32
	UnitsPerWeek    uint32
	LogonHours      *byte
	BadPwCount      uint32
	NumLogons       uint32
	LogonServer     *uint16
	CountryCode     uint32
	CodePage        uint32
	UserID          uint32
	PrimaryGroupID  uint32
	Profile         *uint16
	HomeDirDrive    *uint16
	PasswordExpired uint32
}

// userInfo1 mirrors USER_INFO_1, the level NetUserAdd takes.
type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

// userInfo1008 mirrors USER_INFO_1008: the account control flags alone.
type userInfo1008 struct{ Flags uint32 }

// localGroupMembersInfo3 mirrors LOCALGROUP_MEMBERS_INFO_3.
type localGroupMembersInfo3 struct{ DomainAndName *uint16 }

// localGroupUsersInfo0 mirrors LOCALGROUP_USERS_INFO_0.
type localGroupUsersInfo0 struct{ Name *uint16 }

// wtsInfoW mirrors WTSINFOW, which carries a session's logon and last-input
// times. The string fields are fixed-size WCHAR arrays.
type wtsInfoW struct {
	State                   uint32
	SessionID               uint32
	IncomingBytes           uint32
	OutgoingBytes           uint32
	IncomingFrames          uint32
	OutgoingFrames          uint32
	IncomingCompressedBytes uint32
	OutgoingCompressedBytes uint32
	WinStationName          [33]uint16
	Domain                  [18]uint16
	UserName                [21]uint16
	LastInputTime           int64
	LogonTime               int64
	CurrentTime             int64
	DisconnectTime          int64
}

// wtsClientAddressStruct mirrors WTS_CLIENT_ADDRESS.
type wtsClientAddressStruct struct {
	AddressFamily uint32
	Address       [20]byte
}

// windowsOSUsers implements osusers.Backend on Windows.
type windowsOSUsers struct {
	now func() time.Time
}

func newOSUsersBackend(CommandRunner) osusers.Backend {
	return &windowsOSUsers{now: time.Now}
}

// SupportedOperations lists what this device accepts. Anything absent is
// refused with LastOperationCode=unsupported.
func (w *windowsOSUsers) SupportedOperations() []string {
	return []string{
		osusers.OpReboot, osusers.OpLogOffSession, osusers.OpEnableUser, osusers.OpDisableUser,
		osusers.OpGrantAdministrator, osusers.OpRevokeAdministrator, osusers.OpCreateUser, osusers.OpDeleteUser,
	}
}

// Collect reads the local accounts out of the SAM and the live sessions out of
// WTS. Passive: it enumerates and changes nothing.
func (w *windowsOSUsers) Collect(ctx context.Context) (osusers.Snapshot, error) {
	adminGroup := windowsAdministratorsGroup()
	snap := osusers.Snapshot{
		Platform:            osusers.PlatformWindows,
		AgentAccount:        windowsAgentAccount(),
		AdministratorGroup:  adminGroup,
		SupportedOperations: w.SupportedOperations(),
	}

	users, err := windowsEnumerateUsers(w.now())
	if err != nil {
		return snap, err
	}
	hidden := windowsHiddenAccounts()
	for i := range users {
		users[i].Hidden = users[i].Hidden || hidden[strings.ToLower(users[i].Name)]
		groups, groupErr := windowsUserLocalGroups(users[i].Name)
		if groupErr == nil {
			users[i].Groups = groups
			users[i].Administrator = containsFoldList(groups, adminGroup)
		}
	}
	snap.Users = users
	snap.Sessions = windowsEnumerateSessions()
	snap.Status = osusers.StatusOK
	return snap, nil
}

// windowsEnumerateUsers walks NetUserEnum at level 3, which carries the flags,
// the dates and the RID this model reports.
func windowsEnumerateUsers(now time.Time) ([]osusers.User, error) {
	var out []osusers.User
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		err := windows.NetUserEnum(nil, 3, filterNormalAccount, &buf, maxPreferredLength, &read, &total, &resume)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return nil, fmt.Errorf("NetUserEnum: %w", err)
		}
		if buf == nil {
			break
		}
		entries := unsafe.Slice((*userInfo3)(unsafe.Pointer(buf)), read)
		for i := range entries {
			out = append(out, windowsUserFromInfo(&entries[i], now))
		}
		_ = windows.NetApiBufferFree(buf)
		if err != windows.ERROR_MORE_DATA {
			break
		}
		if len(out) >= 4*128 {
			break
		}
	}
	return out, nil
}

func windowsUserFromInfo(info *userInfo3, now time.Time) osusers.User {
	name := windows.UTF16PtrToString(info.Name)
	user := osusers.User{
		Name:             name,
		FullName:         windows.UTF16PtrToString(info.FullName),
		Enabled:          info.Flags&ufAccountDisable == 0,
		LockedOut:        info.Flags&ufLockout != 0,
		AuthNeverExpires: info.Flags&ufDontExpirePasswd != 0,
		HomeDirectory:    windows.UTF16PtrToString(info.HomeDir),
		AccountType:      windowsAccountType(name, info),
		UID:              windowsAccountSID(name),
	}
	// Shell is a macOS notion; Windows accounts have none.
	if info.LastLogon > 0 && info.LastLogon != timeqForever {
		user.LastLogonTime = uint64(info.LastLogon)
	}
	// password_age is how long ago the password was set, in seconds.
	if info.PasswordAge > 0 && info.PasswordAge != timeqForever {
		if set := now.Unix() - int64(info.PasswordAge); set > 0 {
			user.AuthLastChangedTime = uint64(set)
		}
	}
	if info.AcctExpires > 0 && info.AcctExpires != timeqForever {
		user.AuthExpiresTime = uint64(info.AcctExpires)
	}
	return user
}

// windowsAccountType classifies a local account. NetUserEnum reads the local
// SAM, so a domain or Microsoft-account sign-in is not represented here; the
// built-in accounts Windows ships are reported as system accounts.
func windowsAccountType(name string, info *userInfo3) string {
	switch {
	case info.Priv == userPrivGuest:
		return osusers.AccountSystem
	case strings.HasSuffix(name, "$"):
		return osusers.AccountService
	}
	switch info.UserID {
	case 501, 503, 504: // Guest, DefaultAccount, WDAGUtilityAccount
		return osusers.AccountSystem
	}
	switch strings.ToLower(name) {
	case "guest", "defaultaccount", "wdagutilityaccount":
		return osusers.AccountSystem
	}
	return osusers.AccountLocal
}

// windowsAccountSID returns the account's SID in string form, the platform's
// own identifier for User.{i}.UID.
func windowsAccountSID(name string) string {
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil || sid == nil {
		return ""
	}
	return sid.String()
}

// windowsAdministratorsGroup resolves the built-in administrators group by its
// well-known SID, so a renamed or localized group is still the right one.
func windowsAdministratorsGroup() string {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err == nil && sid != nil {
		if account, _, _, lookupErr := sid.LookupAccount(""); lookupErr == nil && account != "" {
			return account
		}
	}
	return "Administrators"
}

// windowsUserLocalGroups lists the local groups an account belongs to,
// following nested membership the way Windows resolves it.
func windowsUserLocalGroups(name string) ([]string, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var buf *byte
	var read, total uint32
	rc, _, _ := procNetUserGetLocalGroups.Call(0, uintptr(unsafe.Pointer(namePtr)), 0,
		lgIncludeIndirect, uintptr(unsafe.Pointer(&buf)), uintptr(uint32(maxPreferredLength)),
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
	if rc != 0 || buf == nil {
		return nil, fmt.Errorf("NetUserGetLocalGroups: %w", windows.Errno(rc))
	}
	defer windows.NetApiBufferFree(buf)
	entries := unsafe.Slice((*localGroupUsersInfo0)(unsafe.Pointer(buf)), read)
	out := make([]string, 0, len(entries))
	for i := range entries {
		if group := windows.UTF16PtrToString(entries[i].Name); group != "" {
			out = append(out, group)
		}
	}
	return out, nil
}

// windowsHiddenAccounts reads the Winlogon list of accounts the login screen
// does not show.
func windowsHiddenAccounts() map[string]bool {
	out := map[string]bool{}
	const userList = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, userList, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer key.Close()
	names, err := key.ReadValueNames(0)
	if err != nil {
		return out
	}
	for _, name := range names {
		if value, _, valueErr := key.GetIntegerValue(name); valueErr == nil && value == 0 {
			out[strings.ToLower(name)] = true
		}
	}
	return out
}

// windowsAgentAccount names the account the agent runs as. Nothing may
// disable, delete or deprivilege it; a service running as SYSTEM says so.
func windowsAgentAccount() string {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err == nil {
		defer token.Close()
		if tokenUser, err := token.GetTokenUser(); err == nil && tokenUser != nil && tokenUser.User.Sid != nil {
			if account, _, _, err := tokenUser.User.Sid.LookupAccount(""); err == nil && account != "" {
				return account
			}
		}
	}
	if name := os.Getenv("USERNAME"); name != "" {
		return name
	}
	return "SYSTEM"
}

// windowsEnumerateSessions lists the live logon sessions: at the console, over
// RDP, or a service logon.
func windowsEnumerateSessions() []osusers.Session {
	var infos *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &infos, &count); err != nil || infos == nil {
		return nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(infos)))
	entries := unsafe.Slice(infos, count)

	out := make([]osusers.Session, 0, len(entries))
	for i := range entries {
		entry := entries[i]
		account := wtsQueryString(entry.SessionID, wtsUserName)
		station := windows.UTF16PtrToString(entry.WindowStationName)
		if account == "" {
			// A listener or an unused station is not a login session.
			continue
		}
		session := osusers.Session{
			SessionID:  strconv.FormatUint(uint64(entry.SessionID), 10),
			Account:    account,
			Type:       windowsSessionType(station),
			State:      windowsSessionState(entry.State),
			ClientName: wtsQueryString(entry.SessionID, wtsClientName),
		}
		session.ClientAddress = wtsQueryClientAddress(entry.SessionID)
		if info, ok := wtsQuerySessionInfo(entry.SessionID); ok {
			if info.LogonTime > 0 {
				session.LoginTime = uint64(filetimeToUnix(info.LogonTime))
			}
			if info.LastInputTime > 0 && info.CurrentTime > info.LastInputTime {
				session.IdleSeconds = uint64((info.CurrentTime - info.LastInputTime) / 10_000_000)
			}
		}
		out = append(out, session)
	}
	return out
}

// windowsSessionType reads the station name: the console is the machine
// itself, RDP-Tcp#N is a remote desktop, Services is a service logon.
func windowsSessionType(station string) string {
	switch name := strings.ToLower(strings.TrimSpace(station)); {
	case name == "console":
		return osusers.SessionConsole
	case strings.HasPrefix(name, "rdp-"):
		return osusers.SessionRDP
	case name == "services", name == "":
		return osusers.SessionOther
	default:
		return osusers.SessionOther
	}
}

// windowsSessionState maps WTS_CONNECTSTATE_CLASS onto the model enum. WTS
// does not report a locked session, so that value never appears here.
func windowsSessionState(state uint32) string {
	switch state {
	case windows.WTSActive:
		return osusers.SessionActive
	case windows.WTSDisconnected:
		return osusers.SessionDisconnected
	case windows.WTSIdle, windows.WTSConnected, windows.WTSConnectQuery, windows.WTSShadow:
		return osusers.SessionIdle
	default:
		return ""
	}
}

func wtsQueryString(session uint32, class uint32) string {
	var buf *uint16
	var size uint32
	rc, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), uintptr(class),
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&size)))
	if rc == 0 || buf == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return strings.TrimSpace(windows.UTF16PtrToString(buf))
}

func wtsQuerySessionInfo(session uint32) (wtsInfoW, bool) {
	var buf *wtsInfoW
	var size uint32
	rc, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), wtsSessionInfo,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&size)))
	if rc == 0 || buf == nil {
		return wtsInfoW{}, false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	if uintptr(size) < unsafe.Sizeof(wtsInfoW{}) {
		return wtsInfoW{}, false
	}
	return *buf, true
}

func wtsQueryClientAddress(session uint32) string {
	var buf *wtsClientAddressStruct
	var size uint32
	rc, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), wtsClientAddress,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&size)))
	if rc == 0 || buf == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	switch buf.AddressFamily {
	case windows.AF_INET:
		ip := net.IPv4(buf.Address[2], buf.Address[3], buf.Address[4], buf.Address[5])
		if ip.IsUnspecified() {
			return ""
		}
		return ip.String()
	case windows.AF_INET6:
		ip := make(net.IP, net.IPv6len)
		copy(ip, buf.Address[2:18])
		if ip.IsUnspecified() {
			return ""
		}
		return ip.String()
	default:
		return ""
	}
}

// filetimeToUnix converts a Windows FILETIME tick count to Unix seconds.
func filetimeToUnix(ticks int64) int64 {
	const epochDelta = 116444736000000000 // 1601-01-01 to 1970-01-01, in ticks
	if ticks <= epochDelta {
		return 0
	}
	return (ticks - epochDelta) / 10_000_000
}

// SetUserEnabled toggles UF_ACCOUNTDISABLE, preserving the account's other
// control flags.
func (w *windowsOSUsers) SetUserEnabled(ctx context.Context, name string, enabled bool) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return osusers.Coded(osusers.CodeInvalidInput, "invalid account name")
	}
	var buf *byte
	if err := windows.NetUserGetInfo(nil, namePtr, 3, &buf); err != nil {
		return fmt.Errorf("NetUserGetInfo: %w", err)
	}
	info := (*userInfo3)(unsafe.Pointer(buf))
	flags := info.Flags
	windows.NetApiBufferFree(buf)

	if enabled {
		flags &^= ufAccountDisable
	} else {
		flags |= ufAccountDisable
	}
	update := userInfo1008{Flags: flags}
	rc, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(namePtr)), 1008,
		uintptr(unsafe.Pointer(&update)), 0)
	if rc != 0 {
		return fmt.Errorf("NetUserSetInfo: %w", windows.Errno(rc))
	}
	return nil
}

// SetAdministrator adds or removes the account from the built-in
// administrators group.
func (w *windowsOSUsers) SetAdministrator(ctx context.Context, name string, administrator bool) error {
	group, err := windows.UTF16PtrFromString(windowsAdministratorsGroup())
	if err != nil {
		return err
	}
	member, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return osusers.Coded(osusers.CodeInvalidInput, "invalid account name")
	}
	entry := localGroupMembersInfo3{DomainAndName: member}
	proc := procNetLocalGroupDelMembers
	if administrator {
		proc = procNetLocalGroupAddMembers
	}
	rc, _, _ := proc.Call(0, uintptr(unsafe.Pointer(group)), 3, uintptr(unsafe.Pointer(&entry)), 1)
	if rc != 0 {
		return fmt.Errorf("NetLocalGroup members: %w", windows.Errno(rc))
	}
	return nil
}

// CreateUser adds a local account through NetUserAdd. The password is handed
// over as an in-process UTF-16 buffer, which is wiped afterwards, so it never
// reaches a command line or the process table.
func (w *windowsOSUsers) CreateUser(ctx context.Context, req osusers.CreateRequest) error {
	namePtr, err := windows.UTF16PtrFromString(req.Name)
	if err != nil {
		return osusers.Coded(osusers.CodeInvalidInput, "invalid account name")
	}
	password, err := windows.UTF16FromString(req.Password)
	if err != nil {
		return osusers.Coded(osusers.CodeInvalidInput, "invalid initial password")
	}
	defer wipeUTF16(password)

	info := userInfo1{
		Name:     namePtr,
		Password: &password[0],
		Priv:     1, // USER_PRIV_USER: administrator comes from the group
		Flags:    0x0201,
	}
	if comment, err := windows.UTF16PtrFromString(req.FullName); err == nil && req.FullName != "" {
		info.Comment = comment
	}
	var paramErr uint32
	rc, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&paramErr)))
	if rc != 0 {
		return fmt.Errorf("NetUserAdd: %w", windows.Errno(rc))
	}
	if req.FullName != "" {
		_ = windowsSetFullName(req.Name, req.FullName)
	}
	if req.Administrator {
		if err := w.SetAdministrator(ctx, req.Name, true); err != nil {
			return fmt.Errorf("account created but not made an administrator: %w", err)
		}
	}
	return nil
}

// userInfo1011 mirrors USER_INFO_1011: the display name alone.
type userInfo1011 struct{ FullName *uint16 }

func windowsSetFullName(name, fullName string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	fullPtr, err := windows.UTF16PtrFromString(fullName)
	if err != nil {
		return err
	}
	update := userInfo1011{FullName: fullPtr}
	rc, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(namePtr)), 1011,
		uintptr(unsafe.Pointer(&update)), 0)
	if rc != 0 {
		return windows.Errno(rc)
	}
	return nil
}

// DeleteUser removes a local account. NetUserDel leaves the profile on disk,
// which is what removeHomeDirectory=false asks for; true deletes it with
// DeleteProfile, the documented way to remove a user profile.
func (w *windowsOSUsers) DeleteUser(ctx context.Context, name string, removeHomeDirectory bool) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return osusers.Coded(osusers.CodeInvalidInput, "invalid account name")
	}
	sidText := windowsAccountSID(name)
	rc, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(namePtr)))
	if rc != 0 {
		return fmt.Errorf("NetUserDel: %w", windows.Errno(rc))
	}
	if !removeHomeDirectory || sidText == "" {
		return nil
	}
	sidPtr, err := windows.UTF16PtrFromString(sidText)
	if err != nil {
		return nil
	}
	// The account is already gone; a profile that cannot be removed is not
	// worth failing the operation for.
	procDeleteProfileW.Call(uintptr(unsafe.Pointer(sidPtr)), 0, 0)
	return nil
}

// LogOffSession signs one WTS session out.
func (w *windowsOSUsers) LogOffSession(ctx context.Context, sessionID string) error {
	id, err := strconv.ParseUint(strings.TrimSpace(sessionID), 10, 32)
	if err != nil {
		return osusers.Coded(osusers.CodeInvalidInput, "%q is not a Windows session id", sessionID)
	}
	rc, _, callErr := procWTSLogoffSession.Call(0, uintptr(uint32(id)), 0)
	if rc == 0 {
		return fmt.Errorf("WTSLogoffSession: %v", callErr)
	}
	return nil
}

// Reboot restarts the machine, telling anyone logged in when and why.
func (w *windowsOSUsers) Reboot(ctx context.Context, delaySeconds uint64, message string) error {
	if err := enableShutdownPrivilege(); err != nil {
		return osusers.Coded(osusers.CodePermissionDenied, "the agent may not restart this machine: %v", err)
	}
	var messagePtr *uint16
	if text := strings.TrimSpace(message); text != "" {
		if ptr, err := windows.UTF16PtrFromString(text); err == nil {
			messagePtr = ptr
		}
	}
	const (
		reasonMajorOther  = 0x00000000
		reasonMinorOther  = 0x00000000
		reasonFlagPlanned = 0x80000000
	)
	rc, _, callErr := procInitiateSystemShutdownExW.Call(
		0,                                   // this machine
		uintptr(unsafe.Pointer(messagePtr)), // the message shown to anyone logged in
		uintptr(uint32(delaySeconds)),       // seconds to wait
		0,                                   // do not force applications closed
		1,                                   // restart rather than power off
		reasonMajorOther|reasonMinorOther|reasonFlagPlanned,
	)
	if rc == 0 {
		return fmt.Errorf("InitiateSystemShutdownEx: %v", callErr)
	}
	return nil
}

// enableShutdownPrivilege turns on SeShutdownPrivilege in the agent's own
// token, which a process must do before Windows lets it restart the machine.
func enableShutdownPrivilege() error {
	var token windows.Token
	process := windows.CurrentProcess()
	if err := windows.OpenProcessToken(process, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	name, err := windows.UTF16PtrFromString("SeShutdownPrivilege")
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return err
	}
	privileges := windows.Tokenprivileges{PrivilegeCount: 1}
	privileges.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	return windows.AdjustTokenPrivileges(token, false, &privileges, uint32(unsafe.Sizeof(privileges)), nil, nil)
}

// wipeUTF16 clears a credential buffer once the API has copied it.
func wipeUTF16(buf []uint16) {
	for i := range buf {
		buf[i] = 0
	}
}

func containsFoldList(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), want) {
			return true
		}
	}
	return false
}
