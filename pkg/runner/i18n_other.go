//go:build !windows

package runner

// detectLocale returns the POSIX locale from the environment, honouring the
// usual precedence: LC_ALL overrides LC_MESSAGES, which overrides LANG. The
// value (e.g. "fr_FR.UTF-8") is normalized by the caller.
func detectLocale() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := envLang(k); v != "" {
			return v
		}
	}
	return ""
}
