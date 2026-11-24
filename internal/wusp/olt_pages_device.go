package wusp

// Web-UI pages of the Device Settings menu (see olt_spec.go).
//
// Done elsewhere: Management.ServicePorts / Management.Login
// (olt_pages_core.go), Network.NTP.Server/Enabled and the system log
// entries (Syslog.{i}) in olt.go, reboot / factory restore / backup /
// restore / upgrade / SaveConfig commands.
//
// Secrets: user passwords (getUserList returns them Base64), AAA shared
// keys, the enable password and the 802.1X key are never exposed as
// parameters; whole-form writes re-send the current values unchanged and
// new values go through Operate inputs.

// Tables referenced by their Operate commands (Rows deletes).
var oltUserTable = OLTTable{
	Object: "Management.User",
	Label:  "Local users",
	Help:   "Web/CLI accounts (passwords are not exposed). Add/change with AddUser()/SetUser().",
	Get:    OLTCall{Path: "/goform/getUserList"},
	Key:    []string{"userName"},
	Columns: []OLTField{
		{Leaf: "UserName", Vendor: "userName", Label: "User"},
		{Leaf: "UserType", Vendor: "userType", Label: "User type", Enum: []string{"root", "admin", "operate", "guest"}},
		{Leaf: "Timeout", Vendor: "timeout", Codec: "uint", Units: "s", Label: "Login timeout (0 = none)"},
	},
	// Deleting the account the agent logs in with locks it out.
	Delete: &OLTWrite{Path: "/goform/delUserList"},
}

var oltAccessRuleTable = OLTTable{
	Object: "Management.AccessList.Rule",
	Label:  "Login access rules",
	Help:   "Management-plane permit/deny ranges per service. Deleting the permit rule the agent matches can lock it out.",
	Get:    OLTCall{Path: "/goform/getAccessList"},
	Key:    []string{"service_name", "svindex"},
	Columns: []OLTField{
		{Leaf: "Service", Vendor: "service_name", Label: "Service"},
		{Leaf: "Index", Vendor: "svindex", Label: "Index"},
		{Leaf: "RealIndex", Vendor: "real_index", Label: "Internal index"},
		{Leaf: "StartIP", Vendor: "ip_start", Label: "IP range start"},
		{Leaf: "EndIP", Vendor: "ip_end", Label: "IP range end"},
		{Leaf: "Action", Vendor: "action", Label: "permit | deny"},
	},
	Delete:       &OLTWrite{Path: "/goform/delAccessList"},
	DeleteEffect: OLTEffectDisruptive,
}

var oltSyslogServerTable = OLTTable{
	Object: "Management.Syslog.Server",
	Label:  "Remote syslog hosts",
	Help:   "Max 5. Add with AddServer() (the add body uses serverip, the list serverIp).",
	Get:    OLTCall{Path: "/goform/getSystemLogInfo"},
	Key:    []string{"serverIp", "port"},
	Columns: []OLTField{
		{Leaf: "ServerIP", Vendor: "serverIp", Label: "Server IP"},
		{Leaf: "Port", Vendor: "port", Codec: "uint", Label: "UDP port"},
	},
	Delete:       &OLTWrite{Path: "/goform/delLogHost"},
	DeleteEffect: OLTEffectConfig,
}

var oltSNMPCommunityTable = OLTTable{
	Object: "Management.SNMP.Community",
	Label:  "SNMP communities",
	Get:    OLTCall{Path: "/goform/getSnmpAccessList"},
	List:   "communityList",
	Key:    []string{"communityName"},
	Columns: []OLTField{
		{Leaf: "Name", Vendor: "communityName", Required: true, MaxLength: 32, Label: "Community name"},
		{Leaf: "Access", Vendor: "accessRule", Write: true, Required: true, Enum: []string{"read", "readwrite"}, Label: "Access rule"},
	},
	Add:    &OLTWrite{Path: "/goform/setSnmpCommunityInfo", Body: []string{"communityName", "accessRule"}, Extra: map[string]any{"action": "add"}},
	Edit:   &OLTWrite{Path: "/goform/setSnmpCommunityInfo", Body: []string{"communityName", "accessRule"}, Extra: map[string]any{"action": "edit"}, Origin: "row"},
	Delete: &OLTWrite{Path: "/goform/delSnmpCommunityList"},
}

var oltSNMPTrapHostTable = OLTTable{
	Object: "Management.SNMP.TrapHost",
	Label:  "Trap target hosts",
	Get:    OLTCall{Path: "/goform/getSnmpNoticeList"},
	Key:    []string{"destHost", "securityWord"},
	Columns: []OLTField{
		{Leaf: "Host", Vendor: "destHost", Required: true, Label: "Target host IP"},
		{Leaf: "Community", Vendor: "securityWord", Required: true, MaxLength: 32, Label: "Community / user"},
		{Leaf: "UDPPort", Vendor: "udpPort", Required: true, Label: "UDP port (the UI always uses 162)"},
		{Leaf: "Version", Vendor: "securityMode", Write: true, Required: true, Enum: []string{"v1", "v2c"}, Label: "SNMP version"},
		{Leaf: "Level", Vendor: "securityLevel", Label: "Security level (v3 only)"},
	},
	// securityLevel is not sent (v3 is not offered).
	Add:    &OLTWrite{Path: "/goform/setSnmpNoticeInfo", Body: []string{"destHost", "securityWord", "udpPort", "securityMode"}, Extra: map[string]any{"action": "add"}},
	Edit:   &OLTWrite{Path: "/goform/setSnmpNoticeInfo", Body: []string{"destHost", "securityWord", "udpPort", "securityMode"}, Extra: map[string]any{"action": "edit"}, Origin: "row"},
	Delete: &OLTWrite{Path: "/goform/delSnmpNoticeList"},
}

var oltPagesDevice = []OLTPage{
	{
		Route: "/device/user", Title: "User Management", Group: "Management", Section: "User",
		Tables: []OLTTable{oltUserTable},
		Actions: []OLTAction{
			{
				Command: "Management.User.DeleteUser()", Label: "Delete user", Effect: OLTEffectDestructive,
				Help:  "delUserList {list:[user row]} for the account named by Index (userName). Deleting the account the agent logs in with locks it out.",
				Write: OLTWrite{Path: "/goform/delUserList"},
				Rows:  &oltUserTable,
			},
			{
				Command: "Management.User.AddUser()", Label: "Add user", Effect: OLTEffectConfig,
				Help: "setUserInfo action add (oldPwd not sent). Password 5-16 chars, sent in plain text as the web UI does.",
				Write: OLTWrite{Path: "/goform/setUserInfo", Body: []string{"userName", "newPwd", "confirmPwd", "userType", "timeout"},
					Extra: map[string]any{"action": "add"}},
				Inputs: []OLTField{
					{Leaf: "UserName", Vendor: "userName", Required: true, MaxLength: 16, Label: "User name"},
					{Leaf: "Password", Vendor: "newPwd", Required: true, MaxLength: 16, Label: "Password"},
					{Leaf: "ConfirmPassword", Vendor: "confirmPwd", Required: true, MaxLength: 16, Label: "Password again"},
					{Leaf: "UserType", Vendor: "userType", Required: true, Enum: []string{"admin", "operate", "guest"}, Label: "admin | operate | guest"},
					{Leaf: "Timeout", Vendor: "timeout", Required: true, Label: "Login timeout s (0 or 30-300; UI default 300)"},
				},
			},
			{
				Command: "Management.User.SetUser()", Label: "Edit user / change password", Effect: OLTEffectConfig,
				Help: "setUserInfo action edit. Leave NewPassword/ConfirmPassword empty to keep the password. Changing the agent's own login password breaks its next login.",
				Write: OLTWrite{Path: "/goform/setUserInfo", Body: []string{"userName", "oldPwd", "newPwd", "confirmPwd", "userType", "timeout"},
					Extra: map[string]any{"action": "edit"}},
				Inputs: []OLTField{
					{Leaf: "UserName", Vendor: "userName", Required: true, MaxLength: 16, Label: "User name"},
					{Leaf: "OldPassword", Vendor: "oldPwd", MaxLength: 16, Label: "Old password"},
					{Leaf: "NewPassword", Vendor: "newPwd", MaxLength: 16, Label: "New password (empty = keep)"},
					{Leaf: "ConfirmPassword", Vendor: "confirmPwd", MaxLength: 16, Label: "New password again"},
					{Leaf: "UserType", Vendor: "userType", Required: true, Enum: []string{"root", "admin", "operate", "guest"}, Label: "User type (root for the root user)"},
					{Leaf: "Timeout", Vendor: "timeout", Required: true, Label: "Login timeout s (0 or 30-300)"},
				},
			},
		},
	},
	{
		Route: "/device/tools", Title: "Maintenance", Group: "Management", Section: "System",
		Forms: []OLTForm{{
			Object: "Management.System",
			Get:    OLTCall{Path: "/goform/getSysMisc"},
			Fields: []OLTField{
				{Leaf: "RunningVersion", Vendor: "runningversion", Label: "Running version"},
				{Leaf: "FlashVersion", Vendor: "flashversion", Label: "Flash version"},
				{Leaf: "FreeTime", Vendor: "freetime", Label: "Free (license) time"},
				{Leaf: "RunDays", Vendor: "runday", Codec: "uint", Units: "d", Label: "Run time (days)"},
				{Leaf: "RunHours", Vendor: "runhour", Codec: "uint", Units: "h", Label: "Run time (hours)"},
				{Leaf: "PONNotStarted", Vendor: "pon_not_start", Label: "PON not started flag"},
			},
		}},
		Actions: []OLTAction{{
			Command: "Management.System.Unlock()", Label: "Unlock device (license)", Effect: OLTEffectConfig,
			Help:  "setUnlockUrl {unlockkey: Base64(key), day}.",
			Write: OLTWrite{Path: "/goform/setUnlockUrl", Body: []string{"unlockkey", "day"}},
			Inputs: []OLTField{
				{Leaf: "UnlockKey", Vendor: "unlockkey", Codec: "base64", Required: true, MaxLength: 255, Label: "License key"},
				{Leaf: "Days", Vendor: "day", Required: true, Label: "Days (0 = forever, 1-10000)"},
			},
		}},
	},
	{
		Route: "/device/snmp/basic", Title: "Snmp Basic", Group: "Management", Section: "SNMP",
		Forms: []OLTForm{{
			Object: "Management.SNMP",
			Get:    OLTCall{Path: "/goform/getSnmpBasicInfo"},
			Set:    &OLTWrite{Path: "/goform/setSnmpBasicInfo", Body: []string{"contactInfo", "locationInfo"}},
			Fields: []OLTField{
				{Leaf: "Contact", Vendor: "contactInfo", Codec: "base64", Write: true, MaxLength: 255, Label: "Contact info"},
				{Leaf: "Location", Vendor: "locationInfo", Codec: "base64", Write: true, MaxLength: 255, Label: "Location info"},
			},
		}},
	},
	{
		Route: "/device/snmp/group", Title: "Snmp Group", Group: "Management", Section: "SNMP",
		Tables: []OLTTable{oltSNMPCommunityTable},
		Actions: []OLTAction{
			{
				Command: "Management.SNMP.AddCommunity()", Label: "Add SNMP community", Effect: OLTEffectConfig,
				Help:  "setSnmpCommunityInfo {communityName, accessRule, action:add}. The community string is write-only: the command does not report it back.",
				Write: *oltSNMPCommunityTable.Add,
				Inputs: []OLTField{
					{Leaf: "Name", Vendor: "communityName", Required: true, MaxLength: 32, Label: "Community name"},
					{Leaf: "Access", Vendor: "accessRule", Required: true, Enum: []string{"read", "readwrite"}, Label: "Access rule"},
				},
			},
			{
				Command: "Management.SNMP.DeleteCommunity()", Label: "Delete SNMP community", Effect: OLTEffectDisruptive,
				Help:  "delSnmpCommunityList {list:[community row]} for the community named by Index (communityName).",
				Write: OLTWrite{Path: "/goform/delSnmpCommunityList"},
				Rows:  &oltSNMPCommunityTable,
			}},
	},
	{
		Route: "/device/snmp/trap", Title: "Snmp Trap", Group: "Management", Section: "SNMP",
		Forms: []OLTForm{{
			Object: "Management.SNMP.Trap",
			Get:    OLTCall{Path: "/goform/getSnmpNoticeList"},
			Fields: []OLTField{
				{Leaf: "Enable", Vendor: "trapEn", Codec: "bool01", Write: true, Label: "Enable all traps",
					Set: &OLTWrite{Path: "/goform/setSnmpNoticeGlobal", Body: []string{"trapEn"}}},
			},
		}},
		Tables: []OLTTable{oltSNMPTrapHostTable},
		Actions: []OLTAction{
			{
				Command: "Management.SNMP.AddTrapHost()", Label: "Add SNMP trap host", Effect: OLTEffectConfig,
				Help:  "setSnmpNoticeInfo {destHost, securityWord, udpPort, securityMode, action:add} (v1/v2c; the UI always uses port 162). The community is write-only.",
				Write: *oltSNMPTrapHostTable.Add,
				Inputs: []OLTField{
					{Leaf: "Host", Vendor: "destHost", Required: true, Label: "Target host IP"},
					{Leaf: "Community", Vendor: "securityWord", Required: true, MaxLength: 32, Label: "Community"},
					{Leaf: "UDPPort", Vendor: "udpPort", Required: true, Label: "UDP port (162)"},
					{Leaf: "Version", Vendor: "securityMode", Required: true, Enum: []string{"v1", "v2c"}, Label: "SNMP version"},
				},
			},
			{
				Command: "Management.SNMP.DeleteTrapHost()", Label: "Delete SNMP trap host", Effect: OLTEffectConfig,
				Help:  "delSnmpNoticeList {list:[trap host row]} for the host named by Index (\"destHost|securityWord\").",
				Write: OLTWrite{Path: "/goform/delSnmpNoticeList"},
				Rows:  &oltSNMPTrapHostTable,
			}},
	},
	{
		Route: "/device/nms", Title: "NMS", Group: "Management", Section: "NMS",
		Forms: []OLTForm{{
			Object: "Management.NMS",
			Get:    OLTCall{Path: "/goform/getNmsConfigInfo"},
			Set:    &OLTWrite{Path: "/goform/setNmsConfigInfo", Body: []string{"cloudState", "serverIp", "serverPort", "tenantId"}},
			Fields: []OLTField{
				{Leaf: "State", Vendor: "cloudState", Write: true, Enum: []string{"enable", "disable"}, Label: "NMS state",
					Help: "Disabling re-sends the current server fields (the web UI sends \"-\" for them)."},
				{Leaf: "ServerIP", Vendor: "serverIp", Write: true, Label: "Server IP / domain"},
				{Leaf: "ServerPort", Vendor: "serverPort", Write: true, Label: "Server port (1024-65536, \"-\" when disabled)"},
				{Leaf: "TenantID", Vendor: "tenantId", Write: true, MaxLength: 128, Label: "Tenant ID"},
			},
		}},
	},
	{
		Route: "/device/systime", Title: "System Time", Group: "Management", Section: "Time",
		Forms: []OLTForm{{
			// timeType and sntppserver are Network.NTP.Enabled / Server.
			Object: "Management.Time",
			Get:    OLTCall{Path: "/goform/getSystemTimeInfo"},
			Set:    &OLTWrite{Path: "/goform/setSystemTimeInfo", Body: []string{"timeType", "systemTime", "timeZone", "sntppserver", "sntpsserver"}},
			Fields: []OLTField{
				{Leaf: "CurrentTime", Vendor: "currentTime", Label: "Current time (YYYY-MM-DD HH:mm:ss)"},
				{Leaf: "TimeZone", Vendor: "timeZone", Write: true, Label: "Time zone (UTC offset)",
					Enum: []string{"-12", "-11", "-10", "-9", "-8", "-7", "-6", "-5", "-4", "-3", "-2", "-1", "0", "1", "2", "3", "4", "5", "5.5", "6", "7", "8"}},
				{Leaf: "SecondaryServer", Vendor: "sntpsserver", Write: true, Label: "Secondary SNTP server"},
				{Leaf: "SystemTime", Vendor: "systemTime", Write: true, Label: "Manual date/time (YYYY-MM-DD HH:mm:ss)",
					Help: "Applies when Network.NTP.Enabled is false (timeType local).",
					Set: &OLTWrite{Path: "/goform/setSystemTimeInfo", Body: []string{"timeType", "systemTime", "timeZone", "sntppserver", "sntpsserver"},
						NoVerify: true}},
			},
		}},
	},
	{
		Route: "/device/loginmanage/accessList", Title: "Login Manage > Access List", Group: "Management", Section: "AccessList",
		Forms: []OLTForm{{
			Object: "Management.AccessList",
			Get:    OLTCall{Path: "/goform/getAccessList"},
			Fields: []OLTField{
				{Leaf: "DefaultAction", Vendor: "accessStatus", Label: "Login access default", Enum: []string{"0", "1"}, EnumLabels: []string{"Permit", "Deny"},
					Help: "Changed only via SetDefaultAction()."},
			},
		}},
		Tables: []OLTTable{oltAccessRuleTable},
		Actions: []OLTAction{
			{
				Command: "Management.AccessList.DeleteRule()", Label: "Delete login access rule", Effect: OLTEffectDisruptive,
				Help:  "delAccessList {list:[rule row]} for the rule named by Index (\"service|svindex\", e.g. telnet|1). Deleting the permit rule the agent matches can lock it out.",
				Write: OLTWrite{Path: "/goform/delAccessList"},
				Rows:  &oltAccessRuleTable,
			},
			{
				Command: "Management.AccessList.SetDefaultAction()", Label: "Set login access default", Effect: OLTEffectDisruptive,
				Help: "setAccessDefaultAction. WARNING: 1 (deny) blocks every management login not permitted by a rule - add a permit rule for the agent's address (AddRule) first, or the agent is locked out.",
				Write: OLTWrite{Path: "/goform/setAccessDefaultAction", Body: []string{"accessStatus"},
					// The UI posts the add-dialog fields with their defaults too.
					Extra: map[string]any{"service": "telnet", "startIp": "", "endIp": "", "action": "permit"}},
				Inputs: []OLTField{
					{Leaf: "DefaultAction", Vendor: "accessStatus", Required: true, Enum: []string{"0", "1"}, Label: "0 permit | 1 deny"},
				},
			},
			{
				Command: "Management.AccessList.AddRule()", Label: "Add login access rule", Effect: OLTEffectDisruptive,
				Help:  "addAccessList (no duplicate check). WARNING: with default deny, only permitted ranges can log in; a deny rule covering the agent's address locks it out.",
				Read:  &OLTCall{Path: "/goform/getAccessList"},
				Write: OLTWrite{Path: "/goform/addAccessList", Body: []string{"accessStatus"}},
				Inputs: []OLTField{
					{Leaf: "Service", Vendor: "service", Required: true, Enum: []string{"telnet", "ssh", "http", "https", "snmp", "icmp"}, Label: "Service"},
					{Leaf: "StartIP", Vendor: "startIp", Required: true, Label: "IP range start"},
					{Leaf: "EndIP", Vendor: "endIp", Required: true, Label: "IP range end"},
					{Leaf: "Action", Vendor: "action", Required: true, Enum: []string{"permit", "deny"}, Label: "permit | deny"},
				},
			},
		},
	},
	{
		Route: "/device/authentication/authen", Title: "Authentication Config", Group: "Management", Section: "AAA",
		Forms: []OLTForm{{
			// Shared keys and enablepwd come back from the getter (keys in
			// clear, enablepwd Base64) and are re-sent unchanged; they are
			// set only via SetKeys().
			Object: "Management.AAA",
			Get:    OLTCall{Path: "/goform/getRadiusInfo"},
			Set:    &OLTWrite{Path: "/goform/setRadiusInfo", Body: oltAAABody},
			Fields: []OLTField{
				{Leaf: "Mode", Vendor: "aaaMode", Write: true, Effect: OLTEffectDisruptive, Label: "Login authentication mode",
					Enum: []string{"local", "local-radius", "radius", "local-tacacs", "tacacs"},
					Help: "WARNING: radius/tacacs (without local) authenticate the agent's own web login remotely; a wrong server or key locks it out."},
				{Leaf: "RADIUSPrimaryServer", Vendor: "radiusPriServer", Write: true, Label: "RADIUS primary server"},
				{Leaf: "RADIUSPrimaryPort", Vendor: "radiusPriPort", Write: true, Label: "RADIUS primary port (1-65535)"},
				{Leaf: "RADIUSPrimaryTimeout", Vendor: "radiusPriTimeout", Write: true, Units: "s", Label: "RADIUS primary timeout (1-70)"},
				{Leaf: "RADIUSSecondaryServer", Vendor: "radiusSecServer", Write: true, Label: "RADIUS secondary server"},
				{Leaf: "RADIUSSecondaryPort", Vendor: "radiusSecPort", Write: true, Label: "RADIUS secondary port"},
				{Leaf: "RADIUSSecondaryTimeout", Vendor: "radiusSecTimeout", Write: true, Units: "s", Label: "RADIUS secondary timeout"},
				{Leaf: "TACACSPrimaryServer", Vendor: "tacacsPriServer", Write: true, Label: "TACACS+ primary server"},
				{Leaf: "TACACSPrimaryPort", Vendor: "tacPriPort", Write: true, Label: "TACACS+ primary port"},
				{Leaf: "TACACSPrimaryTimeout", Vendor: "tacPriTimeout", Write: true, Units: "s", Label: "TACACS+ primary timeout"},
				{Leaf: "TACACSSecondaryServer", Vendor: "tacacsSecServer", Write: true, Label: "TACACS+ secondary server"},
				{Leaf: "TACACSSecondaryPort", Vendor: "tacSecPort", Write: true, Label: "TACACS+ secondary port"},
				{Leaf: "TACACSSecondaryTimeout", Vendor: "tacSecTimeout", Write: true, Units: "s", Label: "TACACS+ secondary timeout"},
				{Leaf: "EnablePasswordCheck", Vendor: "enablePasswordCheckEn", Codec: "bool01", Write: true, Label: "CLI enable password check"},
			},
		}},
		Actions: []OLTAction{
			{
				Command: "Management.AAA.SetKeys()", Label: "Set AAA shared keys / enable password", Effect: OLTEffectDisruptive,
				Help:  "setRadiusInfo (whole form, current values kept for inputs left empty). A wrong key in a remote AAA mode can lock the agent out.",
				Read:  &OLTCall{Path: "/goform/getRadiusInfo"},
				Write: OLTWrite{Path: "/goform/setRadiusInfo", Body: oltAAABody},
				Inputs: []OLTField{
					{Leaf: "RADIUSPrimaryKey", Vendor: "radiusPriSharedKey", MaxLength: 32, Label: "RADIUS primary shared key"},
					{Leaf: "RADIUSSecondaryKey", Vendor: "radiusSecSharedKey", MaxLength: 32, Label: "RADIUS secondary shared key"},
					{Leaf: "TACACSPrimaryKey", Vendor: "tacPriSharedKey", MaxLength: 32, Label: "TACACS+ primary shared key"},
					{Leaf: "TACACSSecondaryKey", Vendor: "tacSecSharedKey", MaxLength: 32, Label: "TACACS+ secondary shared key"},
					{Leaf: "EnablePassword", Vendor: "enablepwd", Codec: "base64", MaxLength: 32, Label: "CLI enable password"},
				},
			},
			{
				Command: "Management.AAA.Reset()", Label: "Reset authentication config", Effect: OLTEffectDisruptive,
				Help:  "resetRadiusInfo (empty body): AAA back to defaults.",
				Write: OLTWrite{Path: "/goform/resetRadiusInfo"},
			},
		},
	},
	{
		Route: "/device/autoTask/autotask", Title: "AutoTask", Group: "Management", Section: "AutoTask",
		Forms: []OLTForm{{
			// Read-only: setAutoBackupInfo needs *old copies of the fetched
			// values under other keys, which the spec cannot express.
			Object: "Management.AutoTask",
			Get:    OLTCall{Path: "/goform/getTaskInfo"},
			Fields: []OLTField{
				{Leaf: "RebootMode", Vendor: "oltrebootmode", Label: "OLT reboot schedule",
					Enum: []string{"0", "1", "2", "3", "4"}, EnumLabels: []string{"Disable", "Once", "Every day", "Week day", "Month day"}},
				{Leaf: "RebootWeekday", Vendor: "weekday", Label: "Reboot weekday (0 Sun - 6 Sat)"},
				{Leaf: "RebootMonthDay", Vendor: "monthday", Label: "Reboot day of month (1-30)"},
				{Leaf: "RebootHour", Vendor: "oltreboothour", Label: "Reboot hour"},
				{Leaf: "RebootMinute", Vendor: "oltrebootmin", Label: "Reboot minute"},
				{Leaf: "AutoSaveDays", Vendor: "autosaveday", Label: "Auto save interval days (0 = off)"},
				{Leaf: "AutoSaveHours", Vendor: "autosavehour", Label: "Auto save hours"},
				{Leaf: "AutoSaveMinutes", Vendor: "autosaveminute", Label: "Auto save minutes"},
				{Leaf: "AutoBackupDays", Vendor: "autobackupday", Label: "Auto backup interval days (0 = off)"},
				{Leaf: "AutoBackupHours", Vendor: "autobackuphour", Label: "Auto backup hours"},
				{Leaf: "AutoBackupMinutes", Vendor: "autobackupminute", Label: "Auto backup minutes"},
				{Leaf: "AutoBackupServer", Vendor: "autobackupserver", Label: "Auto backup server"},
			},
		}},
		Actions: []OLTAction{{
			Command: "Management.AutoTask.SetRebootSchedule()", Label: "Schedule OLT reboot", Effect: OLTEffectDestructive,
			Help:  "setTaskInfo mode 1: the OLT reboots on this schedule. Inputs left empty keep the current value; RebootMode 0 disables.",
			Read:  &OLTCall{Path: "/goform/getTaskInfo"},
			Write: OLTWrite{Path: "/goform/setTaskInfo", Body: []string{"oltrebootmode", "weekday", "monthday", "oltreboothour", "oltrebootmin"}, Extra: map[string]any{"mode": 1}},
			Inputs: []OLTField{
				{Leaf: "RebootMode", Vendor: "oltrebootmode", Enum: []string{"0", "1", "2", "3", "4"}, Label: "0 off, 1 once, 2 daily, 3 weekly, 4 monthly"},
				{Leaf: "Weekday", Vendor: "weekday", Label: "0 Sun - 6 Sat (mode 3)"},
				{Leaf: "MonthDay", Vendor: "monthday", Label: "1-30 (mode 4)"},
				{Leaf: "Hour", Vendor: "oltreboothour", Label: "0-23"},
				{Leaf: "Minute", Vendor: "oltrebootmin", Label: "0-59"},
			},
		}},
	},
	{
		Route: "/device/syslog/list", Title: "Log Management > Log Info", Group: "Management", Section: "Log",
		// The entries themselves are Device.WUSP_OLT.Syslog.{i}.
		Actions: []OLTAction{{
			Command: "Management.Log.Clear()", Label: "Clear system log", Effect: OLTEffectDestructive,
			Write: OLTWrite{Path: "/goform/delSystemLog", Extra: map[string]any{"action": "delete"}},
		}},
	},
	{
		Route: "/device/syslog/server", Title: "Log Management > Server Settings", Group: "Management", Section: "Syslog",
		Tables: []OLTTable{oltSyslogServerTable},
		Actions: []OLTAction{{
			Command: "Management.Syslog.DeleteServer()", Label: "Delete syslog server", Effect: OLTEffectConfig,
			Help:  "delLogHost {list:[server row]} for the host named by Index (\"serverIp|port\").",
			Write: OLTWrite{Path: "/goform/delLogHost"},
			Rows:  &oltSyslogServerTable,
		}, {
			Command: "Management.Syslog.AddServer()", Label: "Add syslog server", Effect: OLTEffectConfig,
			Write: OLTWrite{Path: "/goform/setSystemLogInfo", Body: []string{"serverip", "port"}, Extra: map[string]any{"action": "add"}},
			Inputs: []OLTField{
				{Leaf: "ServerIP", Vendor: "serverip", Required: true, MaxLength: 32, Label: "Server IP"},
				{Leaf: "Port", Vendor: "port", Required: true, Label: "Port 1-65535 (514)"},
			},
		}},
	},
	{
		Route: "/device/diagnosis/ping", Title: "Diagnostics > Ping Test", Group: "Management", Section: "Diagnostics",
		Actions: []OLTAction{{
			Command: "Management.Diagnostics.Ping()", Label: "Ping (one echo)", Effect: OLTEffectNone, Result: true,
			Help:  "setPingInfo sends ONE echo per call (the web UI loops). Result errCode 2 = reply (ipStr, ttl, time), 3 = unknown host, else timeout.",
			Write: OLTWrite{Path: "/goform/setPingInfo", Body: []string{"packageLen", "destIp"}, OK: []string{"2", "3"}},
			Inputs: []OLTField{
				{Leaf: "Host", Vendor: "destIp", Required: true, Label: "Target IP or domain"},
				{Leaf: "PacketSize", Vendor: "packageLen", Required: true, Label: "Packet size 18-512 B"},
			},
		}},
	},
	{
		Route: "/device/diagnosis/tracert", Title: "Diagnostics > Tracert", Group: "Management", Section: "Diagnostics",
		Actions: []OLTAction{{
			Command: "Management.Diagnostics.Traceroute()", Label: "Traceroute (one hop)", Effect: OLTEffectNone, Result: true,
			Help:  "setTracertInfo probes ONE hop per call: call with TTL 0 (header), 1, 2, ... up to MaxHops. Result errCode 2 = hop line in result (trailing '$' = destination reached), 261 = finished.",
			Write: OLTWrite{Path: "/goform/setTracertInfo", Body: []string{"destIp", "hopCount", "ttl"}, OK: []string{"2", "261"}},
			Inputs: []OLTField{
				{Leaf: "Host", Vendor: "destIp", Required: true, Label: "Target IP or domain"},
				{Leaf: "MaxHops", Vendor: "hopCount", Required: true, Label: "Maximum hops 1-30"},
				{Leaf: "TTL", Vendor: "ttl", Required: true, Label: "Hop to probe (0 = header line)"},
			},
		}},
	},

	// ---- hidden pages ----

	{Route: "/device/web", Title: "Web",
		Unsupported: "hidden page (hide:true); same getSnmpBasicInfo/setSnmpBasicInfo controls as Device.WUSP_OLT.Management.SNMP"},
	{Route: "(orphan) autoSaveBackup", Title: "Auto save/backup (Configure File Manage)",
		Unsupported: "stale orphan chunk; getAutoBackupInfo values are in Management.AutoTask; setAutoBackupInfo needs *old copies of the fetched values the spec cannot express"},
	{Route: "/device/edfa/edfa", Title: "EDFA",
		Unsupported: "HAVE_SUPPORT_EDFA=n; getEdfaStatus/setEdfaInfo have no handler in firmware 1.1.3.18"},
	{Route: "/device/time/list", Title: "Time Period",
		Unsupported: "CONFIG_HAVE_TIME_RANGE=n; getTimeList/setTimeInfo/delTimeList have no handler"},
	{Route: "/device/ims", Title: "IMS Cloud Management",
		Unsupported: "CONFIG_HAVE_IMS=n; getCloudCfg/setCloudCfg have no handler (Cloud Backup on the Maintenance page is IMS-only too)"},
	{Route: "(orphan) help", Title: "Help",
		Unsupported: "separate help.html window, no data"},
}

// oltAAABody is every key the Authentication Config page posts.
var oltAAABody = []string{
	"aaaMode",
	"radiusPriServer", "radiusPriSharedKey", "radiusPriPort", "radiusPriTimeout",
	"radiusSecServer", "radiusSecSharedKey", "radiusSecPort", "radiusSecTimeout",
	"tacacsPriServer", "tacPriSharedKey", "tacPriPort", "tacPriTimeout",
	"tacacsSecServer", "tacSecSharedKey", "tacSecPort", "tacSecTimeout",
	"enablePasswordCheckEn", "enablepwd",
}
