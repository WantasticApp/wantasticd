package runner

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestMain forces the tray language to English so the package's string
// assertions (tray_view_test.go, tray_exit_menu_test.go) are deterministic
// regardless of the CI box's locale or a stray WANTASTIC_LANG.
func TestMain(m *testing.M) {
	forceLang("en")
	os.Exit(m.Run())
}

// nonBaseLangs is every supported language other than the English base.
var nonBaseLangs = []string{"fr", "ar", "es", "de"}

// TestEveryKeyTranslated asserts every English key exists in every other
// language, so no menu string silently falls back to English.
func TestEveryKeyTranslated(t *testing.T) {
	for _, lang := range nonBaseLangs {
		for key := range catalog["en"] {
			if _, ok := catalog[lang][key]; !ok {
				t.Errorf("language %q is missing key %q", lang, key)
			}
		}
	}
}

// TestNoExtraKeys asserts no language defines a key the base does not, which
// would be a dead entry (and usually a typo in the key name).
func TestNoExtraKeys(t *testing.T) {
	for _, lang := range nonBaseLangs {
		for key := range catalog[lang] {
			if _, ok := catalog["en"][key]; !ok {
				t.Errorf("language %q has key %q not present in en", lang, key)
			}
		}
	}
}

// TestFallbackUnknownLang asserts T falls back to the English template when
// the active language is unsupported, and to the key itself for an unknown
// key.
func TestFallbackUnknownLang(t *testing.T) {
	if got, want := translate("zz", "menu.quit"), catalog["en"]["menu.quit"]; got != want {
		t.Errorf("unknown language: got %q, want English %q", got, want)
	}
	if got, want := translate("en", "no.such.key"), "no.such.key"; got != want {
		t.Errorf("unknown key: got %q, want %q", got, want)
	}
	// An unknown key in a non-base language also returns the key itself
	// (via the English fallback, which does not have it either).
	if got, want := translate("fr", "no.such.key"), "no.such.key"; got != want {
		t.Errorf("unknown key in fr: got %q, want %q", got, want)
	}
}

// formatVerb matches a Go format verb, e.g. %s, %d, %.0f, %[1]d.
var formatVerb = regexp.MustCompile(`%[\[\]0-9.+\- #]*[a-zA-Z]`)

// verbMultiset returns the sorted verb letters of a template, with literal
// "%%" removed first so it is not counted.
func verbMultiset(tmpl string) []string {
	tmpl = strings.ReplaceAll(tmpl, "%%", "")
	var verbs []string
	for _, m := range formatVerb.FindAllString(tmpl, -1) {
		verbs = append(verbs, m[len(m)-1:]) // the verb letter
	}
	sort.Strings(verbs)
	return verbs
}

// TestVerbConsistency asserts each language's template has the same multiset
// of format verbs as the English base, so no translation dropped or added a
// %s/%d/%f (which would misformat or emit %!verb(MISSING) at runtime).
func TestVerbConsistency(t *testing.T) {
	for key, base := range catalog["en"] {
		want := verbMultiset(base)
		for _, lang := range nonBaseLangs {
			got := verbMultiset(catalog[lang][key])
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("key %q verbs differ: en=%v %s=%v", key, want, lang, got)
			}
		}
	}
}

// TestFormattedRenders exercises a representative formatted key in every
// language with real args and checks the args land in the output.
func TestFormattedRenders(t *testing.T) {
	langs := append([]string{"en"}, nonBaseLangs...)
	for _, lang := range langs {
		// "peers" = "...%d direct, %d relay": both numbers must appear.
		if got := translate(lang, "peers", 3, 2); !strings.Contains(got, "3") || !strings.Contains(got, "2") {
			t.Errorf("peers[%s] = %q, missing args", lang, got)
		}
		// "exit.use.ok" = "...%s": the IP must appear.
		if got := translate(lang, "exit.use.ok", "10.0.0.5"); !strings.Contains(got, "10.0.0.5") {
			t.Errorf("exit.use.ok[%s] = %q, missing arg", lang, got)
		}
		// "ping.summary" renders a float without a formatting marker.
		if got := translate(lang, "ping.summary", 2, 3, 12.0); strings.Contains(got, "%!") {
			t.Errorf("ping.summary[%s] = %q, bad format", lang, got)
		}
		// "version" renders a version string.
		if got := translate(lang, "version", "1.2.3"); !strings.Contains(got, "1.2.3") {
			t.Errorf("version[%s] = %q, missing arg", lang, got)
		}
	}
}

// TestNormalizeLang covers locale-string mapping and the primary-subtag rule.
func TestNormalizeLang(t *testing.T) {
	cases := map[string]string{
		"en":            "en",
		"en-US":         "en",
		"fr_FR.UTF-8":   "fr",
		"es-ES":         "es",
		"de":            "de",
		"ar-EG":         "ar",
		"AR":            "ar",
		"pt-BR":         "", // unsupported
		"C":             "", // POSIX C locale
		"POSIX":         "",
		"":              "",
		"zh_CN.GB18030": "",
	}
	for in, want := range cases {
		if got := normalizeLang(in); got != want {
			t.Errorf("normalizeLang(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLangOverride checks WANTASTIC_LANG wins over OS detection.
func TestLangOverride(t *testing.T) {
	t.Setenv("WANTASTIC_LANG", "de")
	if got := resolveLang(); got != "de" {
		t.Errorf("WANTASTIC_LANG=de: resolveLang() = %q, want de", got)
	}
	t.Setenv("WANTASTIC_LANG", "pt") // unsupported override is ignored
	// With an unsupported override, resolution falls through to the OS locale
	// or the English default; it must still be a supported language.
	if got := resolveLang(); !supportedLangs[got] {
		t.Errorf("resolveLang() = %q, not a supported language", got)
	}
}
