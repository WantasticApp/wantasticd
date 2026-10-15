import { createContext, useContext } from 'react'

export type Language = 'en' | 'fr' | 'es' | 'de' | 'ar'

export const languages: Array<{ code: Language; label: string }> = [
  { code: 'en', label: 'English' },
  { code: 'fr', label: 'Français' },
  { code: 'es', label: 'Español' },
  { code: 'de', label: 'Deutsch' },
  { code: 'ar', label: 'العربية' },
]

const en = {
  loadingNetwork: 'Loading your network', startingConnection: 'Starting your secure connection', privateNetwork: 'Private network',
  settings: 'Settings', close: 'Close', back: 'Back', more: 'More options', dismiss: 'Dismiss', mainNavigation: 'Main navigation',
  online: 'Online', offline: 'Offline', connectedTo: 'Connected to Wantastic', readyToConnect: 'Ready to connect', signInToContinue: 'Sign in to connect this device',
  connect: 'Connect', disconnect: 'Disconnect', connected: 'Connected', disconnected: 'Disconnected',
  privateAddressUnavailable: 'Private address not ready', directSummary: '{{count}} of {{total}} direct',
  devices: 'Devices', network: 'Network', activity: 'Activity', namesReady: 'Device names ready', namesPreparing: 'Setting up device names',
  searchDevices: 'Search devices', availableDevices: 'Available devices', joinNetwork: 'Connect this device',
  joinNetworkDetail: 'Open Settings and sign in to add this device to your network.', noDevices: 'No devices found',
  differentSearch: 'Try a different search.', devicesAppear: 'Your devices will appear here when they come online.', waitingAddress: 'Waiting for a private address',
  direct: 'Direct', protectedRelay: 'Protected relay', device: 'Device', info: 'Info', connection: 'Connection', actions: 'Actions',
  networkName: 'Network name', notAvailable: 'Not available', ipAddress: 'IP address', directConnection: 'Direct connection', findingDirect: 'Finding a direct connection',
  lastSeen: 'Last seen', traffic: 'Traffic', directActive: 'Direct connection active', findingDirectPath: 'Finding the best connection', relayActive: 'Protected relay active',
  directAvailable: 'Traffic flows directly between devices', relayProtected: 'Traffic remains encrypted through Wantastic',
  pingDevice: 'Check connection', pingSummary: '{{average}} ms average · {{loss}}% loss', noReplies: 'No replies · 100% loss', pingPrompt: 'Run a short connection check',
  pingedDevice: 'Connection to {{name}} checked', useInternetThrough: 'Use internet through this device', useInternetDetail: 'Send internet traffic through this device',
  internetUnavailable: 'This device is not sharing its internet connection', usingInternetThrough: 'Internet is now routed through {{name}}', copyAddress: 'Copy IP address',
  pingHistory: 'Connection history: {{loss}}% packet loss', samples: '{{count}} checks', average: 'avg {{value}} ms', unreachable: 'unreachable', noReply: 'No reply',
  networkControls: 'Network controls', deviceNames: 'Device names', namesReadyDetail: 'Reach your devices by name', namesPreparingDetail: 'Available when the secure connection is ready',
  ready: 'Ready', settingUp: 'Setting up', shareInternet: 'Share this internet connection', shareInternetDetail: 'Let your other devices use this device for internet access',
  sharingStopped: 'Internet sharing turned off', sharingStarted: 'Internet sharing turned on', allowLocal: 'Share local network access',
  allowLocalDetail: 'Let your Wantastic devices reach a local network or one specific address.', localPlaceholder: '192.168.1.0/24, 10.0.0.25/32',
  enableApply: 'Save and enable', disable: 'Disable', localUpdated: 'Local network access updated', localDisabled: 'Local network access disabled',
  automaticDiscovery: 'Automatic local network discovery', stopInternetRouting: 'Stop using another device for internet',
  connectionActivity: 'Connection activity', live: 'Live', networkConnected: 'Secure connection active', networkDisconnected: 'Secure connection off',
  directPaths: '{{count}} direct connections', devicesAvailable: '{{count}} devices available', waitingNames: 'Waiting for the secure connection',
  localShared: 'Local network access shared', localNotShared: 'Local network access off', noLocalNetworks: 'No local networks shared', now: 'Now',
  language: 'Language', languageDetail: 'Choose the language used in Wantastic', account: 'Your account', accountReady: 'Signed in', accountReadyDetail: 'This device is connected to your Wantastic account.', setupRequired: 'Sign-in required',
  signInTitle: 'Connect this device', signInDetail: 'Sign in securely in your browser. Wantastic connects automatically when you finish.', signIn: 'Sign in',
  openingBrowser: 'Opening your browser…', browserOpened: 'Finish signing in in your browser. This app will connect automatically.', signInComplete: 'Signed in and connected.',
  advancedSetup: 'Advanced setup', advancedDetail: 'Import a configuration file or paste its contents.', importConnect: 'Import and connect', imported: 'Configuration imported',
  console: 'Wantastic Console', openConsole: 'Open console', consoleDetail: 'Manage your network in the browser', thisMac: 'This Mac', thisPC: 'This PC', thisDevice: 'This device',
  enable: 'Enable', enabled: 'Enabled', errorPermission: 'Wantastic needs administrator access to connect. Try again and approve the system prompt.',
  errorConflict: 'This setting is already being updated. Refresh and try again.', errorUnexpected: 'Wantastic could not complete that action. Try again.',
  previewUnavailable: 'Sign-in is unavailable in visual preview.', never: 'Never',
}

type Messages = typeof en

const fr: Messages = {
  loadingNetwork: 'Chargement de votre réseau', startingConnection: 'Démarrage de votre connexion sécurisée', privateNetwork: 'Réseau privé',
  settings: 'Réglages', close: 'Fermer', back: 'Retour', more: 'Plus d’options', dismiss: 'Fermer le message', mainNavigation: 'Navigation principale',
  online: 'En ligne', offline: 'Hors ligne', connectedTo: 'Connecté à Wantastic', readyToConnect: 'Prêt à se connecter', signInToContinue: 'Connectez-vous pour relier cet appareil',
  connect: 'Connecter', disconnect: 'Déconnecter', connected: 'Connecté', disconnected: 'Déconnecté',
  privateAddressUnavailable: 'Adresse privée en préparation', directSummary: '{{count}} sur {{total}} en direct',
  devices: 'Appareils', network: 'Réseau', activity: 'Activité', namesReady: 'Noms des appareils disponibles', namesPreparing: 'Configuration des noms',
  searchDevices: 'Rechercher un appareil', availableDevices: 'Appareils disponibles', joinNetwork: 'Connecter cet appareil',
  joinNetworkDetail: 'Ouvrez les Réglages et connectez-vous pour ajouter cet appareil à votre réseau.', noDevices: 'Aucun appareil trouvé',
  differentSearch: 'Essayez une autre recherche.', devicesAppear: 'Vos appareils apparaîtront ici lorsqu’ils seront en ligne.', waitingAddress: 'Adresse privée en préparation',
  direct: 'Direct', protectedRelay: 'Relais protégé', device: 'Appareil', info: 'Infos', connection: 'Connexion', actions: 'Actions',
  networkName: 'Nom réseau', notAvailable: 'Indisponible', ipAddress: 'Adresse IP', directConnection: 'Connexion directe', findingDirect: 'Recherche d’une connexion directe',
  lastSeen: 'Dernière activité', traffic: 'Trafic', directActive: 'Connexion directe active', findingDirectPath: 'Recherche de la meilleure connexion', relayActive: 'Relais protégé actif',
  directAvailable: 'Le trafic circule directement entre les appareils', relayProtected: 'Le trafic reste chiffré via Wantastic',
  pingDevice: 'Tester la connexion', pingSummary: '{{average}} ms en moyenne · {{loss}} % de perte', noReplies: 'Aucune réponse · 100 % de perte', pingPrompt: 'Lancer un test rapide de connexion',
  pingedDevice: 'Connexion à {{name}} testée', useInternetThrough: 'Utiliser Internet via cet appareil', useInternetDetail: 'Faire passer le trafic Internet par cet appareil',
  internetUnavailable: 'Cet appareil ne partage pas sa connexion Internet', usingInternetThrough: 'Internet passe maintenant par {{name}}', copyAddress: 'Copier l’adresse IP',
  pingHistory: 'Historique de connexion : {{loss}} % de perte', samples: '{{count}} tests', average: 'moy. {{value}} ms', unreachable: 'injoignable', noReply: 'Aucune réponse',
  networkControls: 'Réglages du réseau', deviceNames: 'Noms des appareils', namesReadyDetail: 'Accédez à vos appareils par leur nom', namesPreparingDetail: 'Disponible lorsque la connexion sécurisée est prête',
  ready: 'Prêt', settingUp: 'Configuration', shareInternet: 'Partager cette connexion Internet', shareInternetDetail: 'Permettre à vos autres appareils d’utiliser cette connexion Internet',
  sharingStopped: 'Partage Internet désactivé', sharingStarted: 'Partage Internet activé', allowLocal: 'Partager l’accès au réseau local',
  allowLocalDetail: 'Permettre à vos appareils Wantastic d’accéder à un réseau local ou à une adresse précise.', localPlaceholder: '192.168.1.0/24, 10.0.0.25/32',
  enableApply: 'Enregistrer et activer', disable: 'Désactiver', localUpdated: 'Accès au réseau local mis à jour', localDisabled: 'Accès au réseau local désactivé',
  automaticDiscovery: 'Détection automatique du réseau local', stopInternetRouting: 'Ne plus utiliser un autre appareil pour Internet',
  connectionActivity: 'Activité de connexion', live: 'En direct', networkConnected: 'Connexion sécurisée active', networkDisconnected: 'Connexion sécurisée arrêtée',
  directPaths: '{{count}} connexions directes', devicesAvailable: '{{count}} appareils disponibles', waitingNames: 'En attente de la connexion sécurisée',
  localShared: 'Accès au réseau local partagé', localNotShared: 'Accès au réseau local désactivé', noLocalNetworks: 'Aucun réseau local partagé', now: 'Maintenant',
  language: 'Langue', languageDetail: 'Choisissez la langue de Wantastic', account: 'Votre compte', accountReady: 'Connecté', accountReadyDetail: 'Cet appareil est connecté à votre compte Wantastic.', setupRequired: 'Connexion requise',
  signInTitle: 'Connecter cet appareil', signInDetail: 'Connectez-vous en toute sécurité dans votre navigateur. Wantastic se connectera automatiquement à la fin.', signIn: 'Se connecter',
  openingBrowser: 'Ouverture du navigateur…', browserOpened: 'Terminez la connexion dans votre navigateur. L’application se connectera automatiquement.', signInComplete: 'Connecté avec succès.',
  advancedSetup: 'Configuration avancée', advancedDetail: 'Importez un fichier de configuration ou collez son contenu.', importConnect: 'Importer et connecter', imported: 'Configuration importée',
  console: 'Console Wantastic', openConsole: 'Ouvrir la console', consoleDetail: 'Gérez votre réseau dans le navigateur', thisMac: 'Ce Mac', thisPC: 'Ce PC', thisDevice: 'Cet appareil',
  enable: 'Activer', enabled: 'Activé', errorPermission: 'Wantastic a besoin d’un accès administrateur pour se connecter. Réessayez et autorisez la demande du système.',
  errorConflict: 'Ce réglage est déjà en cours de mise à jour. Actualisez puis réessayez.', errorUnexpected: 'Wantastic n’a pas pu terminer cette action. Réessayez.',
  previewUnavailable: 'La connexion est indisponible dans l’aperçu.', never: 'Jamais',
}

const es: Messages = {
  loadingNetwork: 'Cargando tu red', startingConnection: 'Iniciando tu conexión segura', privateNetwork: 'Red privada',
  settings: 'Ajustes', close: 'Cerrar', back: 'Volver', more: 'Más opciones', dismiss: 'Cerrar mensaje', mainNavigation: 'Navegación principal',
  online: 'En línea', offline: 'Sin conexión', connectedTo: 'Conectado a Wantastic', readyToConnect: 'Listo para conectar', signInToContinue: 'Inicia sesión para conectar este dispositivo',
  connect: 'Conectar', disconnect: 'Desconectar', connected: 'Conectado', disconnected: 'Desconectado',
  privateAddressUnavailable: 'Preparando la dirección privada', directSummary: '{{count}} de {{total}} directas',
  devices: 'Dispositivos', network: 'Red', activity: 'Actividad', namesReady: 'Nombres de dispositivos listos', namesPreparing: 'Configurando nombres de dispositivos',
  searchDevices: 'Buscar dispositivos', availableDevices: 'Dispositivos disponibles', joinNetwork: 'Conectar este dispositivo',
  joinNetworkDetail: 'Abre Ajustes e inicia sesión para añadir este dispositivo a tu red.', noDevices: 'No se encontraron dispositivos',
  differentSearch: 'Prueba con otra búsqueda.', devicesAppear: 'Tus dispositivos aparecerán aquí cuando estén en línea.', waitingAddress: 'Esperando una dirección privada',
  direct: 'Directa', protectedRelay: 'Conexión protegida', device: 'Dispositivo', info: 'Información', connection: 'Conexión', actions: 'Acciones',
  networkName: 'Nombre de red', notAvailable: 'No disponible', ipAddress: 'Dirección IP', directConnection: 'Conexión directa', findingDirect: 'Buscando una conexión directa',
  lastSeen: 'Última conexión', traffic: 'Tráfico', directActive: 'Conexión directa activa', findingDirectPath: 'Buscando la mejor conexión', relayActive: 'Conexión protegida activa',
  directAvailable: 'El tráfico fluye directamente entre dispositivos', relayProtected: 'El tráfico permanece cifrado mediante Wantastic',
  pingDevice: 'Comprobar conexión', pingSummary: '{{average}} ms de media · {{loss}}% de pérdida', noReplies: 'Sin respuesta · 100% de pérdida', pingPrompt: 'Realizar una comprobación rápida',
  pingedDevice: 'Conexión con {{name}} comprobada', useInternetThrough: 'Usar Internet mediante este dispositivo', useInternetDetail: 'Enviar el tráfico de Internet mediante este dispositivo',
  internetUnavailable: 'Este dispositivo no comparte su conexión a Internet', usingInternetThrough: 'Internet ahora pasa por {{name}}', copyAddress: 'Copiar dirección IP',
  pingHistory: 'Historial de conexión: {{loss}}% de pérdida', samples: '{{count}} comprobaciones', average: 'media {{value}} ms', unreachable: 'inaccesible', noReply: 'Sin respuesta',
  networkControls: 'Controles de red', deviceNames: 'Nombres de dispositivos', namesReadyDetail: 'Accede a tus dispositivos por su nombre', namesPreparingDetail: 'Disponible cuando la conexión segura esté lista',
  ready: 'Listo', settingUp: 'Configurando', shareInternet: 'Compartir esta conexión a Internet', shareInternetDetail: 'Permite que tus otros dispositivos usen esta conexión a Internet',
  sharingStopped: 'Uso compartido de Internet desactivado', sharingStarted: 'Uso compartido de Internet activado', allowLocal: 'Compartir acceso a la red local',
  allowLocalDetail: 'Permite que tus dispositivos Wantastic accedan a una red local o una dirección concreta.', localPlaceholder: '192.168.1.0/24, 10.0.0.25/32',
  enableApply: 'Guardar y activar', disable: 'Desactivar', localUpdated: 'Acceso a la red local actualizado', localDisabled: 'Acceso a la red local desactivado',
  automaticDiscovery: 'Detección automática de la red local', stopInternetRouting: 'Dejar de usar otro dispositivo para Internet',
  connectionActivity: 'Actividad de conexión', live: 'En directo', networkConnected: 'Conexión segura activa', networkDisconnected: 'Conexión segura desactivada',
  directPaths: '{{count}} conexiones directas', devicesAvailable: '{{count}} dispositivos disponibles', waitingNames: 'Esperando la conexión segura',
  localShared: 'Acceso a la red local compartido', localNotShared: 'Acceso a la red local desactivado', noLocalNetworks: 'No se comparten redes locales', now: 'Ahora',
  language: 'Idioma', languageDetail: 'Elige el idioma de Wantastic', account: 'Tu cuenta', accountReady: 'Sesión iniciada', accountReadyDetail: 'Este dispositivo está conectado a tu cuenta de Wantastic.', setupRequired: 'Debes iniciar sesión',
  signInTitle: 'Conectar este dispositivo', signInDetail: 'Inicia sesión de forma segura en tu navegador. Wantastic se conectará automáticamente al terminar.', signIn: 'Iniciar sesión',
  openingBrowser: 'Abriendo el navegador…', browserOpened: 'Termina de iniciar sesión en tu navegador. La aplicación se conectará automáticamente.', signInComplete: 'Sesión iniciada y conexión establecida.',
  advancedSetup: 'Configuración avanzada', advancedDetail: 'Importa un archivo de configuración o pega su contenido.', importConnect: 'Importar y conectar', imported: 'Configuración importada',
  console: 'Consola Wantastic', openConsole: 'Abrir consola', consoleDetail: 'Gestiona tu red en el navegador', thisMac: 'Este Mac', thisPC: 'Este PC', thisDevice: 'Este dispositivo',
  enable: 'Activar', enabled: 'Activado', errorPermission: 'Wantastic necesita acceso de administrador para conectarse. Inténtalo de nuevo y acepta la solicitud del sistema.',
  errorConflict: 'Este ajuste ya se está actualizando. Actualiza la vista e inténtalo de nuevo.', errorUnexpected: 'Wantastic no pudo completar esta acción. Inténtalo de nuevo.',
  previewUnavailable: 'El inicio de sesión no está disponible en la vista previa.', never: 'Nunca',
}

const de: Messages = {
  loadingNetwork: 'Dein Netzwerk wird geladen', startingConnection: 'Sichere Verbindung wird gestartet', privateNetwork: 'Privates Netzwerk',
  settings: 'Einstellungen', close: 'Schließen', back: 'Zurück', more: 'Weitere Optionen', dismiss: 'Meldung schließen', mainNavigation: 'Hauptnavigation',
  online: 'Online', offline: 'Offline', connectedTo: 'Mit Wantastic verbunden', readyToConnect: 'Bereit zum Verbinden', signInToContinue: 'Anmelden, um dieses Gerät zu verbinden',
  connect: 'Verbinden', disconnect: 'Trennen', connected: 'Verbunden', disconnected: 'Getrennt',
  privateAddressUnavailable: 'Private Adresse wird vorbereitet', directSummary: '{{count}} von {{total}} direkt',
  devices: 'Geräte', network: 'Netzwerk', activity: 'Aktivität', namesReady: 'Gerätenamen verfügbar', namesPreparing: 'Gerätenamen werden eingerichtet',
  searchDevices: 'Geräte suchen', availableDevices: 'Verfügbare Geräte', joinNetwork: 'Dieses Gerät verbinden',
  joinNetworkDetail: 'Öffne die Einstellungen und melde dich an, um dieses Gerät zu deinem Netzwerk hinzuzufügen.', noDevices: 'Keine Geräte gefunden',
  differentSearch: 'Versuche eine andere Suche.', devicesAppear: 'Deine Geräte erscheinen hier, sobald sie online sind.', waitingAddress: 'Private Adresse wird vorbereitet',
  direct: 'Direkt', protectedRelay: 'Geschützte Verbindung', device: 'Gerät', info: 'Info', connection: 'Verbindung', actions: 'Aktionen',
  networkName: 'Netzwerkname', notAvailable: 'Nicht verfügbar', ipAddress: 'IP-Adresse', directConnection: 'Direkte Verbindung', findingDirect: 'Direkte Verbindung wird gesucht',
  lastSeen: 'Zuletzt gesehen', traffic: 'Datenverkehr', directActive: 'Direkte Verbindung aktiv', findingDirectPath: 'Beste Verbindung wird gesucht', relayActive: 'Geschützte Verbindung aktiv',
  directAvailable: 'Daten fließen direkt zwischen den Geräten', relayProtected: 'Daten bleiben über Wantastic verschlüsselt',
  pingDevice: 'Verbindung prüfen', pingSummary: '{{average}} ms im Mittel · {{loss}}% Verlust', noReplies: 'Keine Antwort · 100% Verlust', pingPrompt: 'Kurzen Verbindungstest starten',
  pingedDevice: 'Verbindung zu {{name}} geprüft', useInternetThrough: 'Internet über dieses Gerät nutzen', useInternetDetail: 'Internetverkehr über dieses Gerät leiten',
  internetUnavailable: 'Dieses Gerät teilt seine Internetverbindung nicht', usingInternetThrough: 'Internet läuft jetzt über {{name}}', copyAddress: 'IP-Adresse kopieren',
  pingHistory: 'Verbindungsverlauf: {{loss}}% Paketverlust', samples: '{{count}} Prüfungen', average: 'Ø {{value}} ms', unreachable: 'nicht erreichbar', noReply: 'Keine Antwort',
  networkControls: 'Netzwerksteuerung', deviceNames: 'Gerätenamen', namesReadyDetail: 'Geräte über ihren Namen erreichen', namesPreparingDetail: 'Verfügbar, sobald die sichere Verbindung bereit ist',
  ready: 'Bereit', settingUp: 'Wird eingerichtet', shareInternet: 'Diese Internetverbindung teilen', shareInternetDetail: 'Anderen Geräten erlauben, diese Internetverbindung zu nutzen',
  sharingStopped: 'Internetfreigabe ausgeschaltet', sharingStarted: 'Internetfreigabe eingeschaltet', allowLocal: 'Lokalen Netzwerkzugriff teilen',
  allowLocalDetail: 'Wantastic-Geräten Zugriff auf ein lokales Netzwerk oder eine einzelne Adresse geben.', localPlaceholder: '192.168.1.0/24, 10.0.0.25/32',
  enableApply: 'Speichern und aktivieren', disable: 'Deaktivieren', localUpdated: 'Lokaler Netzwerkzugriff aktualisiert', localDisabled: 'Lokaler Netzwerkzugriff deaktiviert',
  automaticDiscovery: 'Automatische Erkennung des lokalen Netzwerks', stopInternetRouting: 'Anderes Gerät nicht mehr für Internet nutzen',
  connectionActivity: 'Verbindungsaktivität', live: 'Live', networkConnected: 'Sichere Verbindung aktiv', networkDisconnected: 'Sichere Verbindung aus',
  directPaths: '{{count}} direkte Verbindungen', devicesAvailable: '{{count}} Geräte verfügbar', waitingNames: 'Warten auf die sichere Verbindung',
  localShared: 'Lokaler Netzwerkzugriff geteilt', localNotShared: 'Lokaler Netzwerkzugriff aus', noLocalNetworks: 'Keine lokalen Netzwerke geteilt', now: 'Jetzt',
  language: 'Sprache', languageDetail: 'Wähle die Sprache für Wantastic', account: 'Dein Konto', accountReady: 'Angemeldet', accountReadyDetail: 'Dieses Gerät ist mit deinem Wantastic-Konto verbunden.', setupRequired: 'Anmeldung erforderlich',
  signInTitle: 'Dieses Gerät verbinden', signInDetail: 'Melde dich sicher im Browser an. Wantastic verbindet sich danach automatisch.', signIn: 'Anmelden',
  openingBrowser: 'Browser wird geöffnet…', browserOpened: 'Schließe die Anmeldung im Browser ab. Die App verbindet sich automatisch.', signInComplete: 'Angemeldet und verbunden.',
  advancedSetup: 'Erweiterte Einrichtung', advancedDetail: 'Konfigurationsdatei importieren oder Inhalt hier einfügen.', importConnect: 'Importieren und verbinden', imported: 'Konfiguration importiert',
  console: 'Wantastic Console', openConsole: 'Console öffnen', consoleDetail: 'Netzwerk im Browser verwalten', thisMac: 'Dieser Mac', thisPC: 'Dieser PC', thisDevice: 'Dieses Gerät',
  enable: 'Aktivieren', enabled: 'Aktiviert', errorPermission: 'Wantastic benötigt Administratorzugriff zum Verbinden. Versuche es erneut und bestätige die Systemabfrage.',
  errorConflict: 'Diese Einstellung wird bereits aktualisiert. Aktualisiere die Ansicht und versuche es erneut.', errorUnexpected: 'Wantastic konnte die Aktion nicht abschließen. Versuche es erneut.',
  previewUnavailable: 'Die Anmeldung ist in der Vorschau nicht verfügbar.', never: 'Nie',
}

const ar: Messages = {
  loadingNetwork: 'جارٍ تحميل شبكتك', startingConnection: 'جارٍ بدء اتصالك الآمن', privateNetwork: 'شبكة خاصة',
  settings: 'الإعدادات', close: 'إغلاق', back: 'رجوع', more: 'خيارات إضافية', dismiss: 'إغلاق الرسالة', mainNavigation: 'التنقل الرئيسي',
  online: 'متصل', offline: 'غير متصل', connectedTo: 'متصل بـ Wantastic', readyToConnect: 'جاهز للاتصال', signInToContinue: 'سجّل الدخول لتوصيل هذا الجهاز',
  connect: 'اتصال', disconnect: 'قطع الاتصال', connected: 'تم الاتصال', disconnected: 'تم قطع الاتصال',
  privateAddressUnavailable: 'جارٍ إعداد العنوان الخاص', directSummary: '{{count}} من {{total}} مباشر',
  devices: 'الأجهزة', network: 'الشبكة', activity: 'النشاط', namesReady: 'أسماء الأجهزة جاهزة', namesPreparing: 'جارٍ إعداد أسماء الأجهزة',
  searchDevices: 'البحث عن أجهزة', availableDevices: 'الأجهزة المتاحة', joinNetwork: 'توصيل هذا الجهاز',
  joinNetworkDetail: 'افتح الإعدادات وسجّل الدخول لإضافة هذا الجهاز إلى شبكتك.', noDevices: 'لم يتم العثور على أجهزة',
  differentSearch: 'جرّب بحثاً آخر.', devicesAppear: 'ستظهر أجهزتك هنا عندما تصبح متصلة.', waitingAddress: 'في انتظار عنوان خاص',
  direct: 'مباشر', protectedRelay: 'اتصال محمي', device: 'الجهاز', info: 'المعلومات', connection: 'الاتصال', actions: 'الإجراءات',
  networkName: 'اسم الشبكة', notAvailable: 'غير متاح', ipAddress: 'عنوان IP', directConnection: 'اتصال مباشر', findingDirect: 'جارٍ البحث عن اتصال مباشر',
  lastSeen: 'آخر ظهور', traffic: 'حركة البيانات', directActive: 'الاتصال المباشر نشط', findingDirectPath: 'جارٍ البحث عن أفضل اتصال', relayActive: 'الاتصال المحمي نشط',
  directAvailable: 'تنتقل البيانات مباشرة بين الأجهزة', relayProtected: 'تبقى البيانات مشفرة عبر Wantastic',
  pingDevice: 'فحص الاتصال', pingSummary: 'متوسط {{average}} مللي ثانية · فقدان {{loss}}٪', noReplies: 'لا توجد استجابة · فقدان 100٪', pingPrompt: 'تشغيل فحص اتصال سريع',
  pingedDevice: 'تم فحص الاتصال بـ {{name}}', useInternetThrough: 'استخدام الإنترنت عبر هذا الجهاز', useInternetDetail: 'تمرير حركة الإنترنت عبر هذا الجهاز',
  internetUnavailable: 'هذا الجهاز لا يشارك اتصال الإنترنت', usingInternetThrough: 'يمر الإنترنت الآن عبر {{name}}', copyAddress: 'نسخ عنوان IP',
  pingHistory: 'سجل الاتصال: فقدان {{loss}}٪', samples: '{{count}} فحوصات', average: 'متوسط {{value}} مللي ثانية', unreachable: 'يتعذر الوصول', noReply: 'لا توجد استجابة',
  networkControls: 'عناصر تحكم الشبكة', deviceNames: 'أسماء الأجهزة', namesReadyDetail: 'الوصول إلى أجهزتك بالاسم', namesPreparingDetail: 'تتوفر عند جاهزية الاتصال الآمن',
  ready: 'جاهز', settingUp: 'جارٍ الإعداد', shareInternet: 'مشاركة اتصال الإنترنت هذا', shareInternetDetail: 'السماح لأجهزتك الأخرى باستخدام اتصال الإنترنت هذا',
  sharingStopped: 'تم إيقاف مشاركة الإنترنت', sharingStarted: 'تم تشغيل مشاركة الإنترنت', allowLocal: 'مشاركة الوصول إلى الشبكة المحلية',
  allowLocalDetail: 'السماح لأجهزة Wantastic بالوصول إلى شبكة محلية أو عنوان محدد.', localPlaceholder: '192.168.1.0/24, 10.0.0.25/32',
  enableApply: 'حفظ وتفعيل', disable: 'تعطيل', localUpdated: 'تم تحديث الوصول إلى الشبكة المحلية', localDisabled: 'تم تعطيل الوصول إلى الشبكة المحلية',
  automaticDiscovery: 'اكتشاف الشبكة المحلية تلقائياً', stopInternetRouting: 'إيقاف استخدام جهاز آخر للإنترنت',
  connectionActivity: 'نشاط الاتصال', live: 'مباشر', networkConnected: 'الاتصال الآمن نشط', networkDisconnected: 'الاتصال الآمن متوقف',
  directPaths: '{{count}} اتصالات مباشرة', devicesAvailable: '{{count}} أجهزة متاحة', waitingNames: 'في انتظار الاتصال الآمن',
  localShared: 'تمت مشاركة الوصول إلى الشبكة المحلية', localNotShared: 'الوصول إلى الشبكة المحلية متوقف', noLocalNetworks: 'لا توجد شبكات محلية مشتركة', now: 'الآن',
  language: 'اللغة', languageDetail: 'اختر لغة Wantastic', account: 'حسابك', accountReady: 'تم تسجيل الدخول', accountReadyDetail: 'هذا الجهاز متصل بحساب Wantastic الخاص بك.', setupRequired: 'تسجيل الدخول مطلوب',
  signInTitle: 'توصيل هذا الجهاز', signInDetail: 'سجّل الدخول بأمان في متصفحك. سيتصل Wantastic تلقائياً عند الانتهاء.', signIn: 'تسجيل الدخول',
  openingBrowser: 'جارٍ فتح المتصفح…', browserOpened: 'أكمل تسجيل الدخول في متصفحك. سيتصل التطبيق تلقائياً.', signInComplete: 'تم تسجيل الدخول والاتصال.',
  advancedSetup: 'إعداد متقدم', advancedDetail: 'استورد ملف إعداد أو الصق محتواه.', importConnect: 'استيراد واتصال', imported: 'تم استيراد الإعداد',
  console: 'لوحة Wantastic', openConsole: 'فتح لوحة التحكم', consoleDetail: 'إدارة شبكتك في المتصفح', thisMac: 'جهاز Mac هذا', thisPC: 'جهاز PC هذا', thisDevice: 'هذا الجهاز',
  enable: 'تفعيل', enabled: 'مفعّل', errorPermission: 'يحتاج Wantastic إلى صلاحية المسؤول للاتصال. حاول مجدداً ووافق على طلب النظام.',
  errorConflict: 'يجري تحديث هذا الإعداد بالفعل. حدّث الصفحة وحاول مجدداً.', errorUnexpected: 'تعذر على Wantastic إكمال الإجراء. حاول مجدداً.',
  previewUnavailable: 'تسجيل الدخول غير متاح في وضع المعاينة.', never: 'أبداً',
}

const messages: Record<Language, Messages> = { en, fr, es, de, ar }

export type Translate = (key: keyof Messages, values?: Record<string, string | number>) => string

export function detectLanguage(): Language {
  const previewLanguage = new URLSearchParams(window.location.search).get('lang')
  if (previewLanguage && previewLanguage in messages) return previewLanguage as Language
  const saved = window.localStorage.getItem('wantastic-language')
  if (saved && saved in messages) return saved as Language
  const preferred = window.navigator.languages?.[0] || window.navigator.language || 'en'
  const code = preferred.toLowerCase().split('-')[0]
  return code in messages ? code as Language : 'en'
}

export function translate(language: Language): Translate {
  return (key, values = {}) => Object.entries(values).reduce(
    (text, [name, value]) => text.split(`{{${name}}}`).join(String(value)),
    messages[language][key] || en[key],
  )
}

export const I18nContext = createContext<{ language: Language; setLanguage: (language: Language) => void; t: Translate }>({
  language: 'en', setLanguage: () => undefined, t: translate('en'),
})

export function useI18n() { return useContext(I18nContext) }
