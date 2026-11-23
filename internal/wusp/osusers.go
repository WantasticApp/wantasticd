package wusp

// WUSPOSUsers: the Wantastic operating-system account and privileged-access
// data model on Windows and macOS devices.
//
// The agent reports the device's local accounts and its live login sessions,
// and accepts the account actions a Windows Server or macOS Server console
// offers: reboot the machine, log a session off, enable or disable an
// account, grant or revoke administrator rights, and create or delete an
// account.
//
// Sources, per platform, all read-only:
//   - Windows: the SAM through the NetUserEnum / NetLocalGroupGetMembers
//     family (the accounts, their flags and group membership) and WTS session
//     enumeration (who is logged on, on the console or over RDP).
//   - macOS: OpenDirectory / DirectoryService records for the local node
//     (dscl . -readall /Users, the source of the user list, the admin group
//     membership and the password-policy dates) and the utmpx session table.
//
// The model stays OS-neutral and reports what the platform can supply, empty
// where it cannot: a POSIX uid on macOS and a SID on Windows both land in
// User.{i}.UID, and group names are whatever the OS calls them
// (Administrators on Windows, admin on macOS).
//
// Rules this model encodes, which the agent-side collectors must enforce:
//
//   - Collection is passive. The account and session tables are read when the
//     console asks for the path. Nothing here runs on a timer.
//   - An Operate command runs once, only when the console asks, and only when
//     it is listed in SupportedOperations. A command the agent does not offer
//     must fail with LastOperationCode = unsupported rather than be attempted.
//   - The agent never acts on the account it is running as, and never removes
//     the last enabled administrator: DisableUser, DeleteUser and
//     RevokeAdministrator must refuse with self_target or last_admin instead,
//     so a remote action cannot lock the machine (or the agent) out of its own
//     administration.
//   - Every command reports its outcome in LastOperationStatus,
//     LastOperationCode and LastOperationMessage. The console shows the code,
//     so codes are a closed vocabulary (see LastOperationCode).
//
// Privileged OS actions are dangerous by nature. The guard is in three
// places and all three must hold: the device lists what it will accept in
// SupportedOperations, the hub only forwards what the console sends, and the
// console offers nothing to a viewer without write access.

const WUSPOSUsersPrefix = "Device.WUSP_OSUsers."

// Bounds for the tables. A workstation or a small server fits; past the cap
// the agent reports the accounts it can and the true count in TotalUsers.
const (
	WUSPOSUsersMaxUsers    = 128
	WUSPOSUsersMaxSessions = 32
)

// Operate commands on Device.WUSP_OSUsers. Each takes its inputs from the
// flat input parameters below (Target, SessionID, NewName, ...) sent with the
// Operate request; none of them is persisted as device state.
const (
	// Reboot restarts the machine. Inputs: RebootDelay, RebootMessage.
	WUSPOSUsersRebootCommand = WUSPOSUsersPrefix + "Reboot()"
	// LogOffSession ends one login session. Input: SessionID.
	WUSPOSUsersLogOffSessionCommand = WUSPOSUsersPrefix + "LogOffSession()"
	// EnableUser / DisableUser switch an account's ability to log in.
	// Input: Target.
	WUSPOSUsersEnableUserCommand  = WUSPOSUsersPrefix + "EnableUser()"
	WUSPOSUsersDisableUserCommand = WUSPOSUsersPrefix + "DisableUser()"
	// GrantAdministrator / RevokeAdministrator add or remove the account
	// from the platform's administrators group. Input: Target.
	WUSPOSUsersGrantAdministratorCommand  = WUSPOSUsersPrefix + "GrantAdministrator()"
	WUSPOSUsersRevokeAdministratorCommand = WUSPOSUsersPrefix + "RevokeAdministrator()"
	// CreateUser adds a local account. Inputs: NewName, NewFullName,
	// NewAdministrator, Password.
	WUSPOSUsersCreateUserCommand = WUSPOSUsersPrefix + "CreateUser()"
	// DeleteUser removes a local account. Inputs: Target,
	// RemoveHomeDirectory. Irreversible.
	WUSPOSUsersDeleteUserCommand = WUSPOSUsersPrefix + "DeleteUser()"
)

var WUSPOSUsersObjects = []Object{
	{Path: WUSPOSUsersPrefix, SinceVersion: "1.0", Description: "Operating-system accounts and privileged access on a Windows or macOS device: the local accounts, who is logged in, and the guarded account actions."},
	{Path: WUSPOSUsersPrefix + "User.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "One row per local account, keyed by its name. Enabled and Administrator are read-only here: they change only through the matching Operate command, which reports a result."},
	{Path: WUSPOSUsersPrefix + "Session.{i}.", MultiInstance: true, SinceVersion: "1.0", Description: "One row per live login session, console or remote."},
}

func osUsersParam(leaf string, typ ParamType, access Access, description string, limits Limits) Param {
	return Param{Path: WUSPOSUsersPrefix + leaf, Type: typ, Access: access, SinceVersion: "1.0", Description: description, Limits: limits}
}

var AllWUSPOSUsersParams = []Param{
	osUsersParam("Installed", TypeBoolean, ReadOnly, "True when this device's platform exposes local accounts the agent can read.", Limits{}),
	osUsersParam("Enable", TypeBoolean, ReadWrite, "Collect the account and session tables and accept account actions on this device. Off clears the tables and refuses every Operate command.", Limits{}),
	osUsersParam("Platform", TypeString, ReadOnly, "Platform family this backend speaks: windows or macos.", Limits{Enums: []string{"", "windows", "macos"}}),
	osUsersParam("Status", TypeString, ReadOnly, "Collection status of the account backend.", Limits{Enums: []string{"not_installed", "disabled", "ok", "read_error", "permission_denied"}}),
	osUsersParam("StatusDetail", TypeString, ReadOnly, "Detail for the current status, empty when ok. On a device where the agent is not privileged enough to enumerate accounts this names what it lacks.", Limits{MaxLength: 256}),
	osUsersParam("LastCollectTime", TypeUnsignedInt, ReadOnly, "Unix seconds of the last successful collection.", Limits{Min: iptr(0)}),

	osUsersParam("UserNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OSUsers.User.{i}.", Limits{Min: iptr(0), Max: iptr(WUSPOSUsersMaxUsers)}),
	osUsersParam("SessionNumberOfEntries", TypeUnsignedInt, ReadOnly, "Number of entries in Device.WUSP_OSUsers.Session.{i}.", Limits{Min: iptr(0), Max: iptr(WUSPOSUsersMaxSessions)}),

	osUsersParam("TotalUsers", TypeUnsignedInt, ReadOnly, "Local accounts on the device, even when more than the table cap.", Limits{Min: iptr(0)}),
	osUsersParam("EnabledUsers", TypeUnsignedInt, ReadOnly, "Local accounts that may log in.", Limits{Min: iptr(0)}),
	osUsersParam("AdministratorCount", TypeUnsignedInt, ReadOnly, "Local accounts with administrator (privileged) rights.", Limits{Min: iptr(0)}),
	osUsersParam("LoggedInCount", TypeUnsignedInt, ReadOnly, "Accounts with at least one live session.", Limits{Min: iptr(0)}),
	osUsersParam("AgentAccount", TypeString, ReadOnly, "Name of the account the agent itself runs as (or SYSTEM / root where it runs as a service). The device refuses every action that would disable, delete or deprivilege this account.", Limits{MaxLength: 128}),
	osUsersParam("AdministratorGroup", TypeString, ReadOnly, "Name of the platform's administrators group, the one Grant/RevokeAdministrator edits: Administrators on Windows, admin on macOS.", Limits{MaxLength: 64}),

	osUsersParam("SupportedOperations", TypeString, ReadOnly, "Comma-separated Operate commands this device accepts: Reboot, LogOffSession, EnableUser, DisableUser, GrantAdministrator, RevokeAdministrator, CreateUser, DeleteUser. A command absent from this list must be refused with LastOperationCode = unsupported, and the console does not offer it. They run only when requested, never on a timer.", Limits{MaxLength: 256}),
	osUsersParam("LastOperationStatus", TypeString, ReadOnly, "Result of the latest account Operate command.", Limits{Enums: []string{"", "Success", "Error"}}),
	osUsersParam("LastOperationCode", TypeString, ReadOnly, "Stable machine-readable code of the latest account Operate command: ok, not_found (no such account or session), unsupported (not in SupportedOperations, or the platform cannot do it), permission_denied (the agent is not privileged enough), last_admin (it would leave no enabled administrator), self_target (it would act on AgentAccount), session_not_found, in_use (the account is logged in and the platform refuses), invalid_input (a missing or malformed input), exists (the account name is taken), policy_denied (a platform or MDM policy forbids it).", Limits{MaxLength: 64}),
	osUsersParam("LastOperationMessage", TypeString, ReadOnly, "Short result detail of the latest account Operate command. Never contains a credential.", Limits{MaxLength: 256}),

	// ── Operate inputs ──────────────────────────────────────────────────
	// Flat, deliberately outside the User.{i}. and Session.{i}. tables so a
	// table refresh cannot be confused with a pending input.
	osUsersParam("Target", TypeString, WriteOnly, "Input: the account name EnableUser, DisableUser, GrantAdministrator, RevokeAdministrator and DeleteUser act on. Must match a User.{i}.Name; must not be AgentAccount.", Limits{MaxLength: 128}),
	osUsersParam("SessionID", TypeString, WriteOnly, "Input: the session LogOffSession ends. Must match a Session.{i}.SessionID.", Limits{MaxLength: 64}),
	osUsersParam("NewName", TypeString, WriteOnly, "Input: the account name CreateUser creates.", Limits{MaxLength: 128}),
	osUsersParam("NewFullName", TypeString, WriteOnly, "Input: the display name CreateUser gives the new account, optional.", Limits{MaxLength: 128}),
	osUsersParam("NewAdministrator", TypeBoolean, WriteOnly, "Input: true to create the account with administrator rights. False creates a standard account.", Limits{}),
	// Named Password on purpose: wusp.IsSecretParamPath treats any path
	// containing "password" as a credential, so this value is dropped from
	// every stored snapshot and never reaches the portal. It exists only
	// inside the CreateUser request.
	osUsersParam("Password", TypeString, WriteOnly, "Input: the initial password CreateUser sets. Write-only and never persisted: the hub drops any path naming a credential from the device snapshot. Empty asks the platform for its own default (Windows: a blank password the user must change; macOS: refuses).", Limits{MaxLength: 256}),
	osUsersParam("RemoveHomeDirectory", TypeBoolean, WriteOnly, "Input: true to delete the account's home directory with the account. False leaves the files on disk (macOS keeps them in /Users/Deleted Users).", Limits{}),
	osUsersParam("RebootDelay", TypeUnsignedInt, WriteOnly, "Input: seconds to wait before Reboot restarts the machine, giving anyone logged in a chance to save. 0 reboots at once.", Limits{Min: iptr(0), Max: iptr(3600)}),
	osUsersParam("RebootMessage", TypeString, WriteOnly, "Input: the message shown to logged-in users before Reboot restarts the machine, empty for none.", Limits{MaxLength: 256}),

	// ── Accounts ────────────────────────────────────────────────────────
	osUsersParam("User.{i}.Name", TypeString, ReadOnly, "The account's login name, as the OS spells it. The Target input of the account commands.", Limits{MaxLength: 128}),
	osUsersParam("User.{i}.FullName", TypeString, ReadOnly, "Display name of the account, empty when it has none.", Limits{MaxLength: 128}),
	osUsersParam("User.{i}.UID", TypeString, ReadOnly, "The platform's own identifier: a POSIX uid on macOS, a SID on Windows.", Limits{MaxLength: 96}),
	osUsersParam("User.{i}.Enabled", TypeBoolean, ReadOnly, "True when the account may log in. Read-only: it changes through EnableUser() / DisableUser(), which report a result.", Limits{}),
	osUsersParam("User.{i}.Administrator", TypeBoolean, ReadOnly, "True when the account has administrator (privileged) rights, i.e. is a member of AdministratorGroup. Read-only: it changes through GrantAdministrator() / RevokeAdministrator().", Limits{}),
	osUsersParam("User.{i}.Groups", TypeString, ReadOnly, "Comma-separated group names the account belongs to, as the OS names them.", Limits{MaxLength: 512}),
	osUsersParam("User.{i}.AccountType", TypeString, ReadOnly, "What kind of account this is: local, domain (Active Directory or a bound directory), cloud (a Microsoft or managed Apple account), service (a service or daemon account), system (built-in, e.g. SYSTEM or _mdnsresponder).", Limits{Enums: []string{"", "local", "domain", "cloud", "service", "system"}}),
	osUsersParam("User.{i}.Hidden", TypeBoolean, ReadOnly, "True when the OS hides the account from the login window (a service or system account).", Limits{}),
	osUsersParam("User.{i}.LockedOut", TypeBoolean, ReadOnly, "True when the account is locked out by policy after failed logins, which is not the same as disabled.", Limits{}),
	osUsersParam("User.{i}.HomeDirectory", TypeString, ReadOnly, "Path of the account's home directory, empty when it has none.", Limits{MaxLength: 256}),
	osUsersParam("User.{i}.Shell", TypeString, ReadOnly, "Login shell on macOS, empty on Windows.", Limits{MaxLength: 128}),
	osUsersParam("User.{i}.LastLogonTime", TypeUnsignedInt, ReadOnly, "Unix seconds of the account's last logon as the OS records it, 0 when it has never logged in or the platform does not keep it.", Limits{Min: iptr(0)}),
	osUsersParam("User.{i}.LoggedIn", TypeBoolean, ReadOnly, "True when the account has at least one live session in Session.{i}.", Limits{}),
	// A summary of this account's Session.{i}.Type rows, in a coarser
	// vocabulary: console for a console session, remote for rdp, ssh or
	// screensharing, service for a service logon, none when it has no session.
	// Where an account holds several sessions, console wins over remote.
	osUsersParam("User.{i}.SessionType", TypeString, ReadOnly, "How the account is logged in right now, summarizing its Session.{i}.Type rows: console (at the machine), remote (rdp, ssh or screensharing), service, or none.", Limits{Enums: []string{"", "none", "console", "remote", "service"}}),
	// Named Auth*, not Password*: a path containing "password" is treated as
	// a credential by the hub and dropped from the snapshot, so the expiry
	// metadata would never reach the console.
	osUsersParam("User.{i}.AuthLastChangedTime", TypeUnsignedInt, ReadOnly, "Unix seconds when the account's password was last set, 0 when the platform does not expose it.", Limits{Min: iptr(0)}),
	osUsersParam("User.{i}.AuthExpiresTime", TypeUnsignedInt, ReadOnly, "Unix seconds when the account's password expires, 0 when it does not expire or the platform does not expose it.", Limits{Min: iptr(0)}),
	osUsersParam("User.{i}.AuthNeverExpires", TypeBoolean, ReadOnly, "True when policy exempts the account's password from expiry.", Limits{}),
	osUsersParam("User.{i}.CreatedTime", TypeUnsignedInt, ReadOnly, "Unix seconds when the account was created, 0 when the platform does not expose it.", Limits{Min: iptr(0)}),

	// ── Live sessions ───────────────────────────────────────────────────
	osUsersParam("Session.{i}.SessionID", TypeString, ReadOnly, "The platform's session identifier: a WTS session id on Windows, a tty or console name on macOS. The SessionID input of LogOffSession().", Limits{MaxLength: 64}),
	osUsersParam("Session.{i}.Account", TypeString, ReadOnly, "Account this session belongs to; matches a User.{i}.Name.", Limits{MaxLength: 128}),
	osUsersParam("Session.{i}.Type", TypeString, ReadOnly, "How the session arrived: console, rdp, ssh, screensharing or other.", Limits{Enums: []string{"", "console", "rdp", "ssh", "screensharing", "other"}}),
	osUsersParam("Session.{i}.State", TypeString, ReadOnly, "State of the session: active, idle, disconnected (signed in, no display attached) or locked.", Limits{Enums: []string{"", "active", "idle", "disconnected", "locked"}}),
	osUsersParam("Session.{i}.ClientName", TypeString, ReadOnly, "Name of the connecting client for a remote session, empty at the console.", Limits{MaxLength: 128}),
	osUsersParam("Session.{i}.ClientAddress", TypeString, ReadOnly, "IP address the remote session comes from, empty at the console.", Limits{MaxLength: 64}),
	osUsersParam("Session.{i}.LoginTime", TypeUnsignedInt, ReadOnly, "Unix seconds when the session began.", Limits{Min: iptr(0)}),
	osUsersParam("Session.{i}.IdleSeconds", TypeUnsignedInt, ReadOnly, "Seconds since the session last saw input, 0 when active or unknown.", Limits{Min: iptr(0)}),
}
