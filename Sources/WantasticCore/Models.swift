import Foundation

public enum ConnectionState: String, Codable, Hashable, Sendable {
    case disconnected
    case connecting
    case connected
    case needsApproval
    case failed

    public var trayStatusCopyKey: String {
        switch self {
        case .connected: "online"
        case .connecting: "connecting"
        case .disconnected, .needsApproval, .failed: "offline"
        }
    }

    public static func mainStatusCopyKey(for state: Self, profileReady: Bool,
                                         specificStatusCopyKey: String?) -> String {
        switch state {
        case .connected: "connected"
        case .connecting: "connecting"
        case .failed: "connection_failed"
        case .needsApproval:
            specificStatusCopyKey ?? (profileReady ? "registered_offline" : "not_connected")
        case .disconnected: profileReady ? "registered_offline" : "not_connected"
        }
    }
}

public enum TunnelProfilePolicy {
    public static let providerBundleIdentifier = "app.wantastic.desktop.network-extension"

    public static func isWantastic(providerBundleIdentifier: String?) -> Bool {
        providerBundleIdentifier == Self.providerBundleIdentifier
    }
}

public struct DeviceRecord: Identifiable, Codable, Equatable, Sendable {
    public let id: String
    public var name: String
    public var address: String?
    public var platform: String?
    public var online: Bool
    public var direct: Bool
    public var p2pReachable: Bool
    public var services: [NetworkService]

    public init(id: String, name: String, address: String? = nil, platform: String? = nil,
                online: Bool, direct: Bool = false, p2pReachable: Bool = false,
                services: [NetworkService] = []) {
        self.id = id
        self.name = name
        self.address = address
        self.platform = platform
        self.online = online
        self.direct = direct
        self.p2pReachable = p2pReachable
        self.services = services
    }
}

public enum ServiceKind: String, Codable, CaseIterable, Sendable {
    case web
    case remoteDesktop
    case secureShell
    case other
}

public struct NetworkService: Identifiable, Codable, Equatable, Sendable {
    public var id: Int { port }
    public let port: Int
    public let kind: ServiceKind
    public let isOpen: Bool

    public init(port: Int, kind: ServiceKind, isOpen: Bool) {
        self.port = port
        self.kind = kind
        self.isOpen = isOpen
    }
}

public enum WUSPMethod: String, Codable, Sendable, CaseIterable {
    case get
    case set
    case add
    case delete
    case getInstances
    case operate
    case notify
    case getSupportedDM
    case getSupportedProtocol
    case upload
    case download

    public var wireID: UInt8 {
        switch self {
        case .get: 1
        case .set: 2
        case .add: 3
        case .delete: 4
        case .getInstances: 5
        case .operate: 6
        case .notify: 7
        case .getSupportedDM: 8
        case .getSupportedProtocol: 9
        case .upload: 10
        case .download: 11
        }
    }
}

public struct WUSPRequest: Codable, Equatable, Sendable {
    public let id: UInt64
    public let method: WUSPMethod
    public let paths: [String]
    public let values: [String: String]

    public init(id: UInt64, method: WUSPMethod, paths: [String] = [], values: [String: String] = [:]) {
        self.id = id
        self.method = method
        self.paths = paths
        self.values = values
    }
}

public struct WUSPResponse: Codable, Equatable, Sendable {
    public let id: UInt64
    public let values: [String: String]
    public let error: String?

    public init(id: UInt64, values: [String: String] = [:], error: String? = nil) {
        self.id = id
        self.values = values
        self.error = error
    }
}

public protocol WUSPTransport: Sendable {
    func send(_ request: WUSPRequest, to deviceID: String) async throws -> WUSPResponse
}

public enum ServiceClassifier {
    public static func kind(for port: Int) -> ServiceKind {
        switch port {
        case 80, 443, 8000, 8080, 8443: .web
        case 3389, 5900: .remoteDesktop
        case 22: .secureShell
        default: .other
        }
    }
}

public enum WantasticError: Error, Equatable {
    case invalidConsoleURL
    case invalidDeviceAddress
    case tunnelUnavailable
}

public enum AppLanguage: String, CaseIterable, Identifiable, Sendable {
    case english = "en"
    case spanish = "es"
    case arabic = "ar"
    case french = "fr"
    case german = "de"

    public var id: String { rawValue }

    public var name: String {
        switch self {
        case .english: "English"
        case .spanish: "Español"
        case .arabic: "العربية"
        case .french: "Français"
        case .german: "Deutsch"
        }
    }
}

public enum AppCopy {
    private static let translations: [String: [AppLanguage: String]] = [
        "devices": [.english: "Devices", .spanish: "Dispositivos", .arabic: "الأجهزة", .french: "Appareils", .german: "Geräte"],
        "exit_node": [.english: "Exit node", .spanish: "Nodo de salida", .arabic: "عقدة الخروج", .french: "Nœud de sortie", .german: "Exit-Node"],
        "exit_node_hint": [.english: "Use a device that offers internet routing.", .spanish: "Usa un dispositivo que ofrezca enrutamiento a internet.", .arabic: "استخدم جهازا يوفّر توجيه الاتصال بالإنترنت.", .french: "Utilisez un appareil qui propose le routage Internet.", .german: "Verwende ein Gerät, das Internet-Routing anbietet."],
        "none": [.english: "None", .spanish: "Ninguno", .arabic: "بدون", .french: "Aucun", .german: "Keine"],
        "copy_ip": [.english: "Copy IP address", .spanish: "Copiar dirección IP", .arabic: "نسخ عنوان IP", .french: "Copier l’adresse IP", .german: "IP-Adresse kopieren"],
        "clear_search": [.english: "Clear search", .spanish: "Borrar búsqueda", .arabic: "مسح البحث", .french: "Effacer la recherche", .german: "Suche löschen"],
        "no_matching_devices": [.english: "No matching devices", .spanish: "No hay dispositivos coincidentes", .arabic: "لا توجد أجهزة مطابقة", .french: "Aucun appareil correspondant", .german: "Keine passenden Geräte"],
        "path_unconfirmed": [.english: "Path not confirmed", .spanish: "Ruta sin confirmar", .arabic: "لم يتم تأكيد المسار", .french: "Chemin non confirmé", .german: "Pfad nicht bestätigt"],
        "p2p_enabled": [.english: "P2P enabled", .spanish: "P2P activado", .arabic: "اتصال P2P مفعّل", .french: "P2P activé", .german: "P2P aktiviert"],
        "network": [.english: "Network", .spanish: "Red", .arabic: "الشبكة", .french: "Réseau", .german: "Netzwerk"],
        "local_network_access": [.english: "Local network access", .spanish: "Acceso a la red local", .arabic: "الوصول إلى الشبكة المحلية", .french: "Accès au réseau local", .german: "Zugriff auf das lokale Netzwerk"],
        "local_network_access_hint": [.english: "Choose private networks this Mac can share with your Wantastic devices.", .spanish: "Elige las redes privadas que este Mac puede compartir con tus dispositivos Wantastic.", .arabic: "اختر الشبكات الخاصة التي يمكن لهذا الـ Mac مشاركتها مع أجهزة Wantastic.", .french: "Choisissez les réseaux privés que ce Mac peut partager avec vos appareils Wantastic.", .german: "Wähle private Netzwerke aus, die dieser Mac für deine Wantastic-Geräte freigeben darf."],
        "refresh_networks": [.english: "Refresh", .spanish: "Actualizar", .arabic: "تحديث", .french: "Actualiser", .german: "Aktualisieren"],
        "no_private_networks": [.english: "No private networks found", .spanish: "No se encontraron redes privadas", .arabic: "لم يتم العثور على شبكات خاصة", .french: "Aucun réseau privé détecté", .german: "Keine privaten Netzwerke gefunden"],
        "no_private_networks_hint": [.english: "Connect this Mac to a private network, then refresh.", .spanish: "Conecta este Mac a una red privada y actualiza.", .arabic: "اتصل بشبكة خاصة من هذا الـ Mac ثم حدّث القائمة.", .french: "Connectez ce Mac à un réseau privé, puis actualisez.", .german: "Verbinde diesen Mac mit einem privaten Netzwerk und aktualisiere dann."],
        "allow_local_access": [.english: "Allow access", .spanish: "Permitir acceso", .arabic: "السماح بالوصول", .french: "Autoriser l’accès", .german: "Zugriff erlauben"],
        "stop_local_access": [.english: "Stop sharing", .spanish: "Dejar de compartir", .arabic: "إيقاف المشاركة", .french: "Arrêter le partage", .german: "Freigabe beenden"],
        "local_access_on": [.english: "Selected networks are shared with your Wantastic network.", .spanish: "Las redes seleccionadas se comparten con tu red Wantastic.", .arabic: "تتم مشاركة الشبكات المحددة مع شبكة Wantastic.", .french: "Les réseaux sélectionnés sont partagés avec votre réseau Wantastic.", .german: "Die ausgewählten Netzwerke werden für dein Wantastic-Netzwerk freigegeben."],
        "local_access_off": [.english: "Local network sharing is off.", .spanish: "El acceso a la red local está desactivado.", .arabic: "مشاركة الشبكة المحلية متوقفة.", .french: "Le partage du réseau local est désactivé.", .german: "Die Freigabe lokaler Netzwerke ist deaktiviert."],
        "local_access_approval": [.english: "Approve Wantastic’s local network helper in System Settings, then try again.", .spanish: "Aprueba el servicio de red local de Wantastic en Ajustes del Sistema y vuelve a intentarlo.", .arabic: "وافق على خدمة الشبكة المحلية لـ Wantastic في إعدادات النظام ثم حاول مجددا.", .french: "Autorisez le service réseau local de Wantastic dans Réglages Système, puis réessayez.", .german: "Erlaube den lokalen Netzwerkdienst von Wantastic in den Systemeinstellungen und versuche es erneut."],
        "local_access_failed": [.english: "Could not update local network access. Check the connection and helper approval.", .spanish: "No se pudo actualizar el acceso a la red local. Comprueba la conexión y la aprobación del servicio.", .arabic: "تعذر تحديث الوصول إلى الشبكة المحلية. تحقق من الاتصال وموافقة الخدمة.", .french: "Impossible de modifier l’accès au réseau local. Vérifiez la connexion et l’autorisation du service.", .german: "Der Zugriff auf das lokale Netzwerk konnte nicht geändert werden. Prüfe Verbindung und Dienstfreigabe."],
        "local_access_discovery_failed": [.english: "Could not read this Mac’s local network settings.", .spanish: "No se pudo leer la configuración de red local de este Mac.", .arabic: "تعذرت قراءة إعدادات الشبكة المحلية لهذا الـ Mac.", .french: "Impossible de lire la configuration réseau locale de ce Mac.", .german: "Die lokalen Netzwerkeinstellungen dieses Mac konnten nicht gelesen werden."],
        "activity": [.english: "Activity", .spanish: "Actividad", .arabic: "النشاط", .french: "Activité", .german: "Aktivität"],
        "settings": [.english: "Settings", .spanish: "Ajustes", .arabic: "الإعدادات", .french: "Réglages", .german: "Einstellungen"],
        "console": [.english: "Console", .spanish: "Consola", .arabic: "وحدة التحكم", .french: "Console", .german: "Konsole"],
        "your_network": [.english: "Your network", .spanish: "Tu red", .arabic: "شبكتك", .french: "Votre réseau", .german: "Dein Netzwerk"],
        "sign_in": [.english: "Sign in", .spanish: "Iniciar sesión", .arabic: "تسجيل الدخول", .french: "Se connecter", .german: "Anmelden"],
        "no_devices": [.english: "No devices yet", .spanish: "Aún no hay dispositivos", .arabic: "لا توجد أجهزة بعد", .french: "Aucun appareil pour le moment", .german: "Noch keine Geräte"],
        "no_online_devices": [.english: "No other devices are online right now.", .spanish: "No hay otros dispositivos conectados en este momento.", .arabic: "لا توجد أجهزة أخرى متصلة الآن.", .french: "Aucun autre appareil n’est connecté pour le moment.", .german: "Zurzeit sind keine anderen Geräte online."],
        "language": [.english: "Language", .spanish: "Idioma", .arabic: "اللغة", .french: "Langue", .german: "Sprache"],
        "not_connected": [.english: "Not connected", .spanish: "Sin conexión", .arabic: "غير متصل", .french: "Non connecté", .german: "Nicht verbunden"],
        "registered_offline": [.english: "Registered · tunnel offline", .spanish: "Registrado · túnel desconectado", .arabic: "مسجل · النفق غير متصل", .french: "Enregistré · tunnel hors ligne", .german: "Registriert · Tunnel offline"],
        "connected_to_network": [.english: "To your Wantastic network", .spanish: "A tu red Wantastic", .arabic: "بشبكة Wantastic الخاصة بك", .french: "À votre réseau Wantastic", .german: "Mit deinem Wantastic-Netzwerk"],
        "menu_sign_in_hint": [.english: "Open Wantastic to sign in and add this Mac.", .spanish: "Abre Wantastic para iniciar sesión y añadir este Mac.", .arabic: "افتح Wantastic لتسجيل الدخول وإضافة هذا الـ Mac.", .french: "Ouvrez Wantastic pour vous connecter et ajouter ce Mac.", .german: "Öffne Wantastic, um dich anzumelden und diesen Mac hinzuzufügen."],
        "menu_service_unavailable_hint": [.english: "The network service isn’t ready. Open Wantastic to finish setup.", .spanish: "El servicio de red aún no está listo. Abre Wantastic para terminar la configuración.", .arabic: "خدمة الشبكة غير جاهزة بعد. افتح Wantastic لإكمال الإعداد.", .french: "Le service réseau n’est pas prêt. Ouvrez Wantastic pour terminer la configuration.", .german: "Der Netzwerkdienst ist noch nicht bereit. Öffne Wantastic, um die Einrichtung abzuschließen."],
        "registered": [.english: "Registered", .spanish: "Registrado", .arabic: "مسجل", .french: "Enregistré", .german: "Registriert"],
        "tunnel_unavailable": [.english: "The tunnel service is not available in this build.", .spanish: "El servicio de túnel no está disponible en esta versión.", .arabic: "خدمة النفق غير متاحة في هذا الإصدار.", .french: "Le service de tunnel n’est pas disponible dans cette version.", .german: "Der Tunneldienst ist in diesem Build nicht verfügbar."],
        "registered_tunnel_offline": [.english: "This Mac is registered. The tunnel is not active.", .spanish: "Este Mac está registrado. El túnel no está activo.", .arabic: "هذا الـ Mac مسجل. النفق غير نشط.", .french: "Ce Mac est enregistré. Le tunnel n’est pas actif.", .german: "Dieser Mac ist registriert. Der Tunnel ist nicht aktiv."],
        "add_mac_description": [.english: "Sign in to your Wantastic console to add this Mac and see your devices.", .spanish: "Inicia sesión en la consola de Wantastic para añadir este Mac y ver tus dispositivos.", .arabic: "سجل الدخول إلى وحدة تحكم Wantastic لإضافة هذا الـ Mac وعرض أجهزتك.", .french: "Connectez-vous à la console Wantastic pour ajouter ce Mac et voir vos appareils.", .german: "Melde dich in der Wantastic-Konsole an, um diesen Mac hinzuzufügen und deine Geräte zu sehen."],
        "search_devices": [.english: "Search devices", .spanish: "Buscar dispositivos", .arabic: "البحث عن الأجهزة", .french: "Rechercher des appareils", .german: "Geräte suchen"],
        "refresh_devices": [.english: "Refresh devices", .spanish: "Actualizar dispositivos", .arabic: "تحديث الأجهزة", .french: "Actualiser les appareils", .german: "Geräte aktualisieren"],
        "address_unavailable": [.english: "Address unavailable", .spanish: "Dirección no disponible", .arabic: "العنوان غير متاح", .french: "Adresse indisponible", .german: "Adresse nicht verfügbar"],
        "direct": [.english: "Direct", .spanish: "Directo", .arabic: "مباشر", .french: "Direct", .german: "Direkt"],
        "p2p_reachable": [.english: "P2P reachable", .spanish: "P2P disponible", .arabic: "اتصال P2P متاح", .french: "P2P joignable", .german: "P2P erreichbar"],
        "online": [.english: "Online", .spanish: "En línea", .arabic: "متصل", .french: "En ligne", .german: "Online"],
        "offline": [.english: "Offline", .spanish: "Sin conexión", .arabic: "غير متصل", .french: "Hors ligne", .german: "Offline"],
        "ping": [.english: "Ping", .spanish: "Probar conexión", .arabic: "اختبار الاتصال", .french: "Tester la connexion", .german: "Verbindung testen"],
        "pinging_device": [.english: "Sending six connection checks…", .spanish: "Enviando seis comprobaciones…", .arabic: "جارٍ إرسال ستة اختبارات اتصال…", .french: "Envoi de six tests de connexion…", .german: "Sechs Verbindungstests werden gesendet…"],
        "ping_summary": [.english: "Average {average} ms · {loss}% loss", .spanish: "Promedio: {average} ms · {loss}% de pérdida", .arabic: "المتوسط {average} مللي ثانية · فقدان {loss}%", .french: "Moyenne : {average} ms · {loss}% de perte", .german: "Durchschnitt {average} ms · {loss}% Verlust"],
        "ping_unreachable": [.english: "No replies", .spanish: "Sin respuesta", .arabic: "لا توجد استجابة", .french: "Aucune réponse", .german: "Keine Antwort"],
        "ping_failed": [.english: "Ping could not run. Check the device address and connection.", .spanish: "No se pudo probar la conexión. Comprueba la dirección y la conexión del dispositivo.", .arabic: "تعذر اختبار الاتصال. تحقق من عنوان الجهاز واتصاله.", .french: "Le test a échoué. Vérifiez l’adresse et la connexion de l’appareil.", .german: "Der Verbindungstest ist fehlgeschlagen. Prüfe Adresse und Verbindung."],
        "ping_chart_accessibility": [.english: "{count} ping samples, {loss}% packet loss", .spanish: "{count} muestras de ping, {loss}% de pérdida de paquetes", .arabic: "‏{count} عينات اختبار، فقدان الحزم {loss}%", .french: "{count} mesures de ping, {loss}% de perte de paquets", .german: "{count} Ping-Messungen, {loss}% Paketverlust"],
        "waiting_approval": [.english: "Waiting for approval…", .spanish: "Esperando aprobación…", .arabic: "بانتظار الموافقة…", .french: "En attente d’approbation…", .german: "Warte auf Bestätigung…"],
        "approve_mac": [.english: "Approve this Mac", .spanish: "Aprobar este Mac", .arabic: "الموافقة على هذا الـ Mac", .french: "Approuver ce Mac", .german: "Diesen Mac bestätigen"],
        "sign_in_add_mac": [.english: "Sign in and add this Mac", .spanish: "Inicia sesión y añade este Mac", .arabic: "سجل الدخول وأضف هذا الـ Mac", .french: "Connectez-vous et ajoutez ce Mac", .german: "Anmelden und diesen Mac hinzufügen"],
        "connect_devices_prompt": [.english: "Connect to see devices in your network.", .spanish: "Conéctate para ver los dispositivos de tu red.", .arabic: "اتصل لعرض الأجهزة في شبكتك.", .french: "Connectez-vous pour voir les appareils de votre réseau.", .german: "Verbinde dich, um Geräte in deinem Netzwerk zu sehen."],
        "console_address": [.english: "Console address", .spanish: "Dirección de la consola", .arabic: "عنوان وحدة التحكم", .french: "Adresse de la console", .german: "Konsolenadresse"],
        "remove_credentials": [.english: "Remove saved device credentials", .spanish: "Eliminar las credenciales guardadas", .arabic: "إزالة بيانات اعتماد الجهاز المحفوظة", .french: "Supprimer les identifiants enregistrés", .german: "Gespeicherte Gerätezugangsdaten entfernen"],
        "service_discovery_opt_in": [.english: "Service discovery is optional and limited to devices you select.", .spanish: "La detección de servicios es opcional y se limita a los dispositivos que elijas.", .arabic: "اكتشاف الخدمات اختياري ويقتصر على الأجهزة التي تختارها.", .french: "La découverte des services est facultative et limitée aux appareils choisis.", .german: "Die Diensterkennung ist optional und auf ausgewählte Geräte beschränkt."],
        "service_actions_note": [.english: "Service actions are based on the detected type and never run automatically.", .spanish: "Las acciones dependen del servicio detectado y nunca se ejecutan automáticamente.", .arabic: "تعتمد إجراءات الخدمة على نوعها ولا تعمل تلقائيا.", .french: "Les actions dépendent du type de service détecté et ne se lancent jamais automatiquement.", .german: "Dienstaktionen richten sich nach dem erkannten Typ und starten nie automatisch."],
        "open_service": [.english: "Open", .spanish: "Abrir", .arabic: "فتح", .french: "Ouvrir", .german: "Öffnen"],
        "service_app_unavailable": [.english: "No app is available to open this service.", .spanish: "No hay una aplicación disponible para abrir este servicio.", .arabic: "لا يوجد تطبيق متاح لفتح هذه الخدمة.", .french: "Aucune app ne peut ouvrir ce service.", .german: "Keine App zum Öffnen dieses Dienstes verfügbar."],
        "scan_services": [.english: "Scan services", .spanish: "Buscar servicios", .arabic: "فحص الخدمات", .french: "Rechercher des services", .german: "Dienste suchen"],
        "scan_scope": [.english: "Check common TCP services on {device} only.", .spanish: "Comprobar solo los servicios TCP habituales de {device}.", .arabic: "فحص خدمات TCP الشائعة على {device} فقط.", .french: "Vérifier uniquement les services TCP courants de {device}.", .german: "Nur übliche TCP-Dienste auf {device} prüfen."],
        "cancel": [.english: "Cancel", .spanish: "Cancelar", .arabic: "إلغاء", .french: "Annuler", .german: "Abbrechen"],
        "scanning_services": [.english: "Checking this device…", .spanish: "Comprobando este dispositivo…", .arabic: "جارٍ فحص هذا الجهاز…", .french: "Vérification de cet appareil…", .german: "Dieses Gerät wird geprüft…"],
        "no_services_found": [.english: "No common services responded.", .spanish: "No respondieron los servicios habituales.", .arabic: "لم تستجب الخدمات الشائعة.", .french: "Aucun service courant n’a répondu.", .german: "Keine üblichen Dienste haben geantwortet."],
        "service_scan_failed": [.english: "Could not scan this device. Check its address and connection.", .spanish: "No se pudo analizar este dispositivo. Comprueba su dirección y conexión.", .arabic: "تعذر فحص هذا الجهاز. تحقق من عنوانه واتصاله.", .french: "Impossible d’analyser cet appareil. Vérifiez son adresse et sa connexion.", .german: "Dieses Gerät konnte nicht geprüft werden. Prüfe Adresse und Verbindung."],
        "web_service": [.english: "Web", .spanish: "Web", .arabic: "ويب", .french: "Web", .german: "Web"],
        "remote_desktop_service": [.english: "Remote desktop", .spanish: "Escritorio remoto", .arabic: "سطح المكتب البعيد", .french: "Bureau à distance", .german: "Remotedesktop"],
        "ssh_service": [.english: "Secure shell", .spanish: "Terminal segura", .arabic: "طرفية آمنة", .french: "Terminal sécurisé", .german: "Sichere Shell"],
        "other_service": [.english: "Other service", .spanish: "Otro servicio", .arabic: "خدمة أخرى", .french: "Autre service", .german: "Anderer Dienst"],
        "network_setup": [.english: "Network setup", .spanish: "Configuración de red", .arabic: "إعداد الشبكة", .french: "Configuration réseau", .german: "Netzwerkeinrichtung"],
        "connect_to_routes": [.english: "Connect to view your network routes.", .spanish: "Conéctate para ver las rutas de red.", .arabic: "اتصل لعرض مسارات الشبكة.", .french: "Connectez-vous pour voir les routes réseau.", .german: "Verbinde dich, um deine Netzwerkrouten zu sehen."],
        "no_activity": [.english: "No recent activity", .spanish: "Sin actividad reciente", .arabic: "لا يوجد نشاط حديث", .french: "Aucune activité récente", .german: "Keine aktuellen Aktivitäten"],
        "device_credentials_removed": [.english: "Saved device credentials removed from this Mac.", .spanish: "Se eliminaron las credenciales guardadas de este Mac.", .arabic: "تمت إزالة بيانات الاعتماد المحفوظة من هذا الـ Mac.", .french: "Les identifiants enregistrés ont été supprimés de ce Mac.", .german: "Gespeicherte Zugangsdaten wurden von diesem Mac entfernt."],
        "credentials_remove_failed": [.english: "Saved credentials could not be removed.", .spanish: "No se pudieron eliminar las credenciales guardadas.", .arabic: "تعذرت إزالة بيانات الاعتماد المحفوظة.", .french: "Impossible de supprimer les identifiants enregistrés.", .german: "Gespeicherte Zugangsdaten konnten nicht entfernt werden."],
        "credentials_read_failed": [.english: "Saved device credentials could not be read. Sign in again.", .spanish: "No se pudieron leer las credenciales guardadas. Inicia sesión de nuevo.", .arabic: "تعذرت قراءة بيانات الاعتماد المحفوظة. سجل الدخول مجددا.", .french: "Impossible de lire les identifiants enregistrés. Reconnectez-vous.", .german: "Gespeicherte Zugangsdaten konnten nicht gelesen werden. Bitte erneut anmelden."],
        "open_app": [.english: "Open Wantastic", .spanish: "Abrir Wantastic", .arabic: "فتح Wantastic", .french: "Ouvrir Wantastic", .german: "Wantastic öffnen"],
        "quit": [.english: "Quit", .spanish: "Salir", .arabic: "إنهاء", .french: "Quitter", .german: "Beenden"],
        "connect": [.english: "Connect", .spanish: "Conectar", .arabic: "اتصال", .french: "Connecter", .german: "Verbinden"],
        "disconnect": [.english: "Disconnect", .spanish: "Desconectar", .arabic: "قطع الاتصال", .french: "Déconnecter", .german: "Trennen"],
        "connected": [.english: "Connected", .spanish: "Conectado", .arabic: "متصل", .french: "Connecté", .german: "Verbunden"],
        "connecting": [.english: "Connecting…", .spanish: "Conectando…", .arabic: "جارٍ الاتصال…", .french: "Connexion…", .german: "Verbindung wird hergestellt…"],
        "connection_failed": [.english: "Connection unavailable", .spanish: "Conexión no disponible", .arabic: "الاتصال غير متاح", .french: "Connexion indisponible", .german: "Verbindung nicht verfügbar"],
        "account": [.english: "Account", .spanish: "Cuenta", .arabic: "الحساب", .french: "Compte", .german: "Konto"],
        "manual_configuration": [.english: "Manual configuration", .spanish: "Configuración manual", .arabic: "إعداد يدوي", .french: "Configuration manuelle", .german: "Manuelle Konfiguration"],
        "manual_config_hint": [.english: "Paste a WireGuard configuration. The private key is stored securely in Keychain.", .spanish: "Pega una configuración de WireGuard. La clave privada se guarda de forma segura en el llavero.", .arabic: "ألصق إعداد WireGuard. سيُحفظ المفتاح الخاص بأمان في سلسلة المفاتيح.", .french: "Collez une configuration WireGuard. La clé privée est conservée dans le trousseau.", .german: "Füge eine WireGuard-Konfiguration ein. Der private Schlüssel wird sicher im Schlüsselbund gespeichert."],
        "import_and_connect": [.english: "Import and connect", .spanish: "Importar y conectar", .arabic: "استيراد واتصال", .french: "Importer et connecter", .german: "Importieren und verbinden"],
        "manual_configuration_active": [.english: "Manual configuration saved on this Mac.", .spanish: "La configuración manual se guardó en este Mac.", .arabic: "تم حفظ الإعداد اليدوي على هذا الـ Mac.", .french: "La configuration manuelle est enregistrée sur ce Mac.", .german: "Die manuelle Konfiguration wurde auf diesem Mac gespeichert."],
        "configuration_importing": [.english: "Validating and saving the configuration…", .spanish: "Validando y guardando la configuración…", .arabic: "جارٍ التحقق من الإعداد وحفظه…", .french: "Validation et enregistrement de la configuration…", .german: "Konfiguration wird geprüft und gespeichert…"],
        "configuration_import_failed": [.english: "Could not import this configuration. Check its format and try again.", .spanish: "No se pudo importar esta configuración. Comprueba el formato e inténtalo de nuevo.", .arabic: "تعذر استيراد هذا الإعداد. تحقق من التنسيق وحاول مجددا.", .french: "Impossible d’importer cette configuration. Vérifiez son format et réessayez.", .german: "Diese Konfiguration konnte nicht importiert werden. Prüfe das Format und versuche es erneut."],
        "services": [.english: "Services", .spanish: "Servicios", .arabic: "الخدمات", .french: "Services", .german: "Dienste"],
        "device": [.english: "Device", .spanish: "Dispositivo", .arabic: "الجهاز", .french: "Appareil", .german: "Gerät"],
        "code": [.english: "Code", .spanish: "Código", .arabic: "الرمز", .french: "Code", .german: "Code"],
        "approve_in_browser": [.english: "Approve this Mac in your browser.", .spanish: "Aprueba este Mac en el navegador.", .arabic: "وافق على هذا الـ Mac في المتصفح.", .french: "Approuvez ce Mac dans votre navigateur.", .german: "Bestätige diesen Mac im Browser."],
        "open_console_to_finish": [.english: "Open the Wantastic console to sign in and finish setup.", .spanish: "Abre la consola de Wantastic para iniciar sesión y terminar la configuración.", .arabic: "افتح وحدة تحكم Wantastic لتسجيل الدخول وإكمال الإعداد.", .french: "Ouvrez la console Wantastic pour vous connecter et terminer la configuration.", .german: "Öffne die Wantastic-Konsole, um dich anzumelden und die Einrichtung abzuschließen."],
        "signin_starting": [.english: "Starting secure sign-in…", .spanish: "Iniciando sesión segura…", .arabic: "جارٍ بدء تسجيل الدخول الآمن…", .french: "Connexion sécurisée en cours…", .german: "Sichere Anmeldung wird gestartet…"],
        "signin_url_error": [.english: "Enter a secure HTTPS console address.", .spanish: "Introduce una dirección HTTPS segura de la consola.", .arabic: "أدخل عنوان HTTPS آمنا لوحدة التحكم.", .french: "Saisissez une adresse HTTPS sécurisée pour la console.", .german: "Gib eine sichere HTTPS-Adresse für die Konsole ein."],
        "signin_error": [.english: "Sign-in could not be completed. Check your connection and try again.", .spanish: "No se pudo iniciar sesión. Comprueba la conexión e inténtalo de nuevo.", .arabic: "تعذر إكمال تسجيل الدخول. تحقق من الاتصال وحاول مجددا.", .french: "La connexion a échoué. Vérifiez votre réseau et réessayez.", .german: "Die Anmeldung ist fehlgeschlagen. Prüfe die Verbindung und versuche es erneut."],
        "open_console_browser": [.english: "Open the console in your browser to continue.", .spanish: "Abre la consola en el navegador para continuar.", .arabic: "افتح وحدة التحكم في المتصفح للمتابعة.", .french: "Ouvrez la console dans le navigateur pour continuer.", .german: "Öffne die Konsole im Browser, um fortzufahren."],
        "browser_back": [.english: "Back", .spanish: "Atrás", .arabic: "رجوع", .french: "Retour", .german: "Zurück"],
        "browser_forward": [.english: "Forward", .spanish: "Adelante", .arabic: "تقدم", .french: "Avancer", .german: "Vorwärts"],
        "browser_reload": [.english: "Reload page", .spanish: "Recargar página", .arabic: "إعادة تحميل الصفحة", .french: "Recharger la page", .german: "Seite neu laden"],
        "browser_stop": [.english: "Stop loading", .spanish: "Detener carga", .arabic: "إيقاف التحميل", .french: "Arrêter le chargement", .german: "Laden stoppen"],
        "open_in_browser": [.english: "Open in browser", .spanish: "Abrir en el navegador", .arabic: "فتح في المتصفح", .french: "Ouvrir dans le navigateur", .german: "Im Browser öffnen"],
        "web_url_invalid": [.english: "Set a valid console address in Settings.", .spanish: "Configura una dirección válida de la consola en Ajustes.", .arabic: "أدخل عنوانا صالحا لوحدة التحكم في الإعدادات.", .french: "Définissez une adresse de console valide dans les réglages.", .german: "Lege in den Einstellungen eine gültige Konsolenadresse fest."],
        "web_https_only": [.english: "Only secure HTTPS pages can open in this view.", .spanish: "Esta vista solo puede abrir páginas HTTPS seguras.", .arabic: "يمكن لهذه النافذة فتح صفحات HTTPS الآمنة فقط.", .french: "Seules les pages HTTPS sécurisées peuvent s’ouvrir ici.", .german: "In dieser Ansicht können nur sichere HTTPS-Seiten geöffnet werden."],
        "web_load_failed": [.english: "The page couldn’t load. Check your connection and try again.", .spanish: "No se pudo cargar la página. Comprueba la conexión e inténtalo de nuevo.", .arabic: "تعذر تحميل الصفحة. تحقق من اتصالك وحاول مجددا.", .french: "La page n’a pas pu se charger. Vérifiez votre connexion et réessayez.", .german: "Die Seite konnte nicht geladen werden. Prüfe die Verbindung und versuche es erneut."],
        "tunnel_extension_not_installed": [.english: "Network extension is not installed.", .spanish: "La extensión de red no está instalada.", .arabic: "امتداد الشبكة غير مثبت.", .french: "L’extension réseau n’est pas installée.", .german: "Die Netzwerkerweiterung ist nicht installiert."],
        "tunnel_profile_ready": [.english: "Wantastic is ready to connect.", .spanish: "Wantastic está listo para conectarse.", .arabic: "Wantastic جاهز للاتصال.", .french: "Wantastic est prêt à se connecter.", .german: "Wantastic ist verbindungsbereit."],
        "requesting_extension_approval": [.english: "Requesting macOS approval…", .spanish: "Solicitando aprobación de macOS…", .arabic: "جارٍ طلب موافقة macOS…", .french: "Demande d’autorisation de macOS…", .german: "macOS-Genehmigung wird angefordert…"],
        "approve_extension_in_settings": [.english: "Approve Wantastic in System Settings to connect.", .spanish: "Aprueba Wantastic en Ajustes del Sistema para conectarte.", .arabic: "وافق على Wantastic في إعدادات النظام للاتصال.", .french: "Autorisez Wantastic dans Réglages Système pour vous connecter.", .german: "Erlaube Wantastic in den Systemeinstellungen, um dich zu verbinden."],
        "restart_to_enable_extension": [.english: "Restart your Mac to finish enabling the network extension.", .spanish: "Reinicia el Mac para terminar de activar la extensión de red.", .arabic: "أعد تشغيل Mac لإكمال تفعيل امتداد الشبكة.", .french: "Redémarrez votre Mac pour terminer l’activation de l’extension réseau.", .german: "Starte deinen Mac neu, um die Netzwerkerweiterung zu aktivieren."],
        "starting_secure_connection": [.english: "Starting secure connection…", .spanish: "Iniciando conexión segura…", .arabic: "جارٍ بدء اتصال آمن…", .french: "Démarrage de la connexion sécurisée…", .german: "Sichere Verbindung wird gestartet…"],
        "use_exit_node": [.english: "Use as exit node", .spanish: "Usar como nodo de salida", .arabic: "استخدامه كعقدة خروج", .french: "Utiliser comme nœud de sortie", .german: "Als Exit-Node verwenden"],
        "stop_using_exit_node": [.english: "Stop using exit node", .spanish: "Dejar de usar el nodo de salida", .arabic: "إيقاف استخدام عقدة الخروج", .french: "Ne plus utiliser le nœud de sortie", .german: "Exit-Node nicht mehr verwenden"],
        "peer_not_exit_node": [.english: "This device is not offering exit-node access.", .spanish: "Este dispositivo no ofrece acceso como nodo de salida.", .arabic: "هذا الجهاز لا يوفّر الوصول كعقدة خروج.", .french: "Cet appareil ne propose pas l’accès comme nœud de sortie.", .german: "Dieses Gerät bietet keinen Exit-Node-Zugang an."],
        "exit_node_request_failed": [.english: "Could not update exit-node settings.", .spanish: "No se pudo actualizar la configuración del nodo de salida.", .arabic: "تعذر تحديث إعدادات عقدة الخروج.", .french: "Impossible de modifier les réglages du nœud de sortie.", .german: "Die Exit-Node-Einstellungen konnten nicht geändert werden."],
    ]

    public static var allKeys: [String] { translations.keys.sorted() }

    public static func text(_ key: String, language: AppLanguage) -> String {
        translations[key]?[language] ?? translations[key]?[.english] ?? key
    }

    public static func hasTranslation(_ key: String, language: AppLanguage) -> Bool {
        translations[key]?[language] != nil
    }
}
