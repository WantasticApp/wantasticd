package osusers

import (
	"strconv"
	"strings"
	"time"
)

// This file parses what the macOS directory and session tools print. It holds
// no exec call of its own so the parsing is covered by tests on any host.

// DSRecord is one record of a dscl -readall dump: its keys and their values.
type DSRecord map[string][]string

// First returns the first value of a key, or "".
func (r DSRecord) First(key string) string {
	if values := r[key]; len(values) > 0 {
		return strings.TrimSpace(values[0])
	}
	return ""
}

// All returns every value of a key, splitting the space-separated lists dscl
// prints for multi-valued attributes.
func (r DSRecord) All(key string) []string {
	var out []string
	for _, value := range r[key] {
		out = append(out, strings.Fields(value)...)
	}
	return out
}

// ParseDSCLReadall parses `dscl . -readall <path> <keys...>` output.
//
// dscl prints "Key: value" lines, continues a long or multi-valued attribute
// on following indented lines, and separates records with a line holding only
// a dash.
func ParseDSCLReadall(text string) []DSRecord {
	var out []DSRecord
	record := DSRecord{}
	key := ""
	flush := func() {
		if len(record) > 0 {
			out = append(out, record)
		}
		record = DSRecord{}
		key = ""
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "-" {
			flush()
			continue
		}
		if line == "" {
			continue
		}
		// An indented line continues the attribute above it.
		if line[0] == ' ' || line[0] == '\t' {
			if key != "" {
				record[key] = append(record[key], strings.TrimSpace(line))
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(name)
		if value = strings.TrimSpace(value); value != "" {
			record[key] = append(record[key], value)
		} else if _, exists := record[key]; !exists {
			record[key] = nil
		}
	}
	flush()
	return out
}

// MacUsersFromRecords turns the /Users dump into model rows. generatedUIDs
// collects each account's GeneratedUID so group membership recorded by UUID
// can be resolved back to a name.
func MacUsersFromRecords(records []DSRecord) (users []User, generatedUIDs map[string]string) {
	generatedUIDs = make(map[string]string, len(records))
	for _, record := range records {
		name := record.First("RecordName")
		if name == "" {
			continue
		}
		uid := record.First("UniqueID")
		authority := strings.Join(record["AuthenticationAuthority"], " ")
		user := User{
			Name:          name,
			FullName:      record.First("RealName"),
			UID:           uid,
			HomeDirectory: record.First("NFSHomeDirectory"),
			Shell:         record.First("UserShell"),
			// macOS marks a disabled local account by adding
			// ";DisabledUser;" to its AuthenticationAuthority, which is
			// what pwpolicy -disableuser writes.
			Enabled:     !strings.Contains(authority, ";DisabledUser;"),
			AccountType: macAccountType(name, uid, record.First("UserShell")),
			Hidden:      macHiddenAccount(name, uid, record.First("IsHidden")),
		}
		policy := strings.Join(record["accountPolicyData"], "\n")
		user.AuthLastChangedTime = plistEpochSeconds(policy, "passwordLastSetTime")
		user.CreatedTime = plistEpochSeconds(policy, "creationTime")
		if guid := record.First("GeneratedUID"); guid != "" {
			generatedUIDs[strings.ToUpper(guid)] = name
		}
		users = append(users, user)
	}
	return users, generatedUIDs
}

// MacGroupsFromRecords turns the /Groups dump into an account-to-group-names
// index, resolving the GroupMembers UUID form through generatedUIDs.
func MacGroupsFromRecords(records []DSRecord, generatedUIDs map[string]string) map[string][]string {
	out := map[string][]string{}
	add := func(account, group string) {
		key := strings.ToLower(account)
		for _, existing := range out[key] {
			if existing == group {
				return
			}
		}
		out[key] = append(out[key], group)
	}
	for _, record := range records {
		group := record.First("RecordName")
		if group == "" {
			continue
		}
		for _, member := range record.All("GroupMembership") {
			add(member, group)
		}
		for _, uuid := range record.All("GroupMembers") {
			if name := generatedUIDs[strings.ToUpper(uuid)]; name != "" {
				add(name, group)
			}
		}
	}
	return out
}

// macAccountType classifies a local macOS account. `dscl .` reads the local
// node only, so every record here is a local or a built-in system account; a
// directory-bound or managed Apple account is not distinguishable from one.
func macAccountType(name, uid, shell string) string {
	id, err := strconv.Atoi(strings.TrimSpace(uid))
	switch {
	case strings.HasPrefix(name, "_"), err == nil && id < 500, name == "root", name == "nobody", name == "daemon":
		if shell == "/usr/bin/false" || shell == "/usr/bin/nologin" || shell == "/sbin/nologin" {
			return AccountService
		}
		return AccountSystem
	default:
		return AccountLocal
	}
}

// macHiddenAccount reports whether the login window hides the account.
func macHiddenAccount(name, uid, isHidden string) bool {
	switch strings.ToLower(strings.TrimSpace(isHidden)) {
	case "1", "true", "yes":
		return true
	}
	if strings.HasPrefix(name, "_") {
		return true
	}
	id, err := strconv.Atoi(strings.TrimSpace(uid))
	return err == nil && id < 500
}

// plistEpochSeconds pulls one numeric value out of the embedded XML plist
// dscl prints for accountPolicyData. Nothing is persisted from it: the only
// values read are the two dates the model asks for.
func plistEpochSeconds(plist, key string) uint64 {
	marker := "<key>" + key + "</key>"
	i := strings.Index(plist, marker)
	if i < 0 {
		return 0
	}
	rest := plist[i+len(marker):]
	start := strings.IndexByte(rest, '>')
	if start < 0 {
		return 0
	}
	rest = rest[start+1:]
	end := strings.IndexByte(rest, '<')
	if end < 0 {
		return 0
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(rest[:end]), 64)
	if err != nil || value <= 0 {
		return 0
	}
	return uint64(value)
}

// ParseWho parses `who -u` output into live sessions.
//
// The columns are name, line, the login date, an idle marker and a pid, with a
// remote host in parentheses when the session came over the network. Locales
// and macOS versions move the trailing columns around, so each token is
// recognized by its shape rather than by its position.
func ParseWho(text string, now time.Time) []Session {
	var out []Session
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimRight(line, "\r"))
		if len(fields) < 2 {
			continue
		}
		account, tty := fields[0], fields[1]
		if account == "" || tty == "" || strings.EqualFold(account, "NAME") {
			continue
		}
		// With -T, who puts the message-status marker between the account
		// and the line.
		next := 1
		if isMessageStatus(fields[next]) && len(fields) > next+1 {
			next++
		}
		tty = fields[next]
		next++

		session := Session{
			SessionID: tty,
			Account:   account,
			State:     SessionActive,
		}
		// The login stamp is the next three tokens: month, day and time.
		var dateParts []string
		for len(dateParts) < 3 && next < len(fields) {
			dateParts = append(dateParts, fields[next])
			next++
		}
		session.LoginTime = parseWhoTime(dateParts, now)

		// What is left is the idle marker, the pid and the remote host.
		for ; next < len(fields); next++ {
			field := fields[next]
			switch {
			case strings.HasPrefix(field, "(") && strings.HasSuffix(field, ")"):
				session.ClientName = strings.Trim(field, "()")
			case field == "old":
				// who prints "old" for a session idle for over a day.
				session.State = SessionIdle
				session.IdleSeconds = 24 * 3600
			case isIdleClock(field):
				if idle := parseIdleClock(field); idle > 0 {
					session.State = SessionIdle
					session.IdleSeconds = idle
				}
			}
		}
		session.Type = macSessionType(tty, session.ClientName)
		if host := session.ClientName; host != "" && looksLikeAddress(host) {
			session.ClientAddress, session.ClientName = host, ""
		}
		out = append(out, session)
	}
	return out
}

// macSessionType classifies a macOS login. The console is the machine itself;
// a pseudo-terminal with a remote host behind it arrived over ssh; one without
// is a local terminal window, which the model calls other.
func macSessionType(tty, host string) string {
	switch {
	case strings.HasPrefix(tty, "console"):
		return SessionConsole
	case host != "":
		return SessionSSH
	default:
		return SessionOther
	}
}

// parseWhoTime reads who's "Nov 20 09:12" into Unix seconds. who prints no
// year, so the current one is assumed and a date in the future is read as last
// year's.
func parseWhoTime(parts []string, now time.Time) uint64 {
	if len(parts) < 3 {
		return 0
	}
	stamp := strings.Join(parts[:3], " ")
	for _, layout := range []string{"Jan 2 15:04", "Jan _2 15:04", "2 Jan 15:04", "Jan 2 2006"} {
		parsed, err := time.ParseInLocation(layout, stamp, now.Location())
		if err != nil {
			continue
		}
		if parsed.Year() == 0 {
			parsed = parsed.AddDate(now.Year(), 0, 0)
		}
		if parsed.After(now.Add(24 * time.Hour)) {
			parsed = parsed.AddDate(-1, 0, 0)
		}
		if parsed.Unix() <= 0 {
			return 0
		}
		return uint64(parsed.Unix())
	}
	return 0
}

// isMessageStatus reports whether a token is who -T's write-permission
// marker, which sits between the account name and the line.
func isMessageStatus(field string) bool {
	return field == "+" || field == "-" || field == "?"
}

// isIdleClock reports whether a token looks like who's HH:MM idle column.
func isIdleClock(field string) bool {
	hours, minutes, ok := strings.Cut(field, ":")
	return ok && isAllDigits(hours) && isAllDigits(minutes) && len(minutes) == 2 && len(hours) <= 3
}

// parseIdleClock turns who's HH:MM idle column into seconds.
func parseIdleClock(field string) uint64 {
	hours, minutes, ok := strings.Cut(field, ":")
	if !ok {
		return 0
	}
	h, errH := strconv.ParseUint(hours, 10, 32)
	m, errM := strconv.ParseUint(minutes, 10, 32)
	if errH != nil || errM != nil {
		return 0
	}
	return h*3600 + m*60
}

func isAllDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// looksLikeAddress reports whether who's parenthesized host is an IP address
// rather than a name, so it lands in ClientAddress.
func looksLikeAddress(host string) bool {
	if strings.Contains(host, ":") {
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if !isAllDigits(part) {
			return false
		}
	}
	return true
}

// ParseAdminMembership reads the admin group's member names out of a
// `dscl . -read /Groups/admin GroupMembership` answer.
func ParseAdminMembership(text string) []string {
	for _, record := range ParseDSCLReadall(text) {
		if members := record.All("GroupMembership"); len(members) > 0 {
			return members
		}
	}
	return nil
}
