package main

import "strings"

type trayStrings struct {
	Offline, Online, Starting, Connect, Disconnect, StartingAction string
	Devices, Network, OpenApp, SignIn, Settings, Quit              string
}

var trayLanguages = map[string]trayStrings{
	"en": {"Offline", "Online", "Starting", "Connect", "Disconnect", "Starting…", "Devices", "Network", "Open app", "Sign in", "Settings", "Quit Wantastic"},
	"fr": {"Hors ligne", "En ligne", "Démarrage", "Connecter", "Déconnecter", "Démarrage…", "Appareils", "Réseau", "Ouvrir l’application", "Se connecter", "Réglages", "Quitter Wantastic"},
	"es": {"Sin conexión", "En línea", "Iniciando", "Conectar", "Desconectar", "Iniciando…", "Dispositivos", "Red", "Abrir aplicación", "Iniciar sesión", "Ajustes", "Salir de Wantastic"},
	"de": {"Offline", "Online", "Wird gestartet", "Verbinden", "Trennen", "Wird gestartet…", "Geräte", "Netzwerk", "App öffnen", "Anmelden", "Einstellungen", "Wantastic beenden"},
	"ar": {"غير متصل", "متصل", "جارٍ البدء", "اتصال", "قطع الاتصال", "جارٍ البدء…", "الأجهزة", "الشبكة", "فتح التطبيق", "تسجيل الدخول", "الإعدادات", "إنهاء Wantastic"},
}

func normalizeDesktopLanguage(language string) string {
	language = strings.ToLower(strings.TrimSpace(language))
	if separator := strings.IndexAny(language, "-_"); separator >= 0 {
		language = language[:separator]
	}
	if _, ok := trayLanguages[language]; ok {
		return language
	}
	return "en"
}

func trayStringsFor(language string) trayStrings {
	return trayLanguages[normalizeDesktopLanguage(language)]
}
