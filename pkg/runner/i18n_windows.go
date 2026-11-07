//go:build windows

package runner

import "golang.org/x/sys/windows"

// detectLocale returns the user's preferred UI language on Windows, e.g.
// "fr-FR". GetUserPreferredUILanguages(MUI_LANGUAGE_NAME) gives the display
// language list (what the UI should match), not the regional-format locale
// that GetUserDefaultLocaleName returns, and it needs no hand-written LCID
// map. The whole list is scanned so a user whose top language is unsupported
// but whose next one is supported still gets a translated menu; the system
// list is tried if the user list is empty.
func detectLocale() string {
	if code := firstSupported(userUILanguages()); code != "" {
		return code
	}
	return firstRaw(systemUILanguages())
}

func userUILanguages() []string {
	langs, err := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
	if err != nil {
		return nil
	}
	return langs
}

func systemUILanguages() []string {
	langs, err := windows.GetSystemPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
	if err != nil {
		return nil
	}
	return langs
}

// firstSupported returns the first locale that maps to a supported language,
// or "" if none do.
func firstSupported(langs []string) string {
	for _, l := range langs {
		if normalizeLang(l) != "" {
			return l
		}
	}
	return ""
}

func firstRaw(langs []string) string {
	if len(langs) > 0 {
		return langs[0]
	}
	return ""
}
