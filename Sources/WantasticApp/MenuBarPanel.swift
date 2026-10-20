import AppKit
import CoreImage.CIFilterBuiltins
import CryptoKit
import OSLog
import SwiftUI
import WantasticCore
#if !WANTASTIC_XCODE_APP
import WantasticTunnel
#endif

private enum TrayPage {
    case network
    case settings
}

private enum SettingsSection: String, CaseIterable, Identifiable {
    case general
    case network
    case account
    case configs

    var id: String { rawValue }
}

private struct DesktopClaimConfiguration: Decodable {
    let claimed: Bool
    let assignedIP: String?
    let serverKey: String?
    let endpoint: String?
    let allowedIPs: [String]?
    let dnsServers: [String]?
    let persistentKeepalive: Int?
    let mtu: Int?
    let listenPort: Int?

    enum CodingKeys: String, CodingKey {
        case claimed
        case assignedIP = "assigned_ip"
        case serverKey = "server_key"
        case endpoint
        case allowedIPs = "allowed_ips"
        case dnsServers = "dns_servers"
        case persistentKeepalive = "persistent_keepalive"
        case mtu
        case listenPort = "listen_port"
    }
}

private struct PendingDesktopClaim: Codable {
    let privateKey: String
    let publicKey: String
    let serverURL: String
}

private enum DesktopSetupError: Error {
    case invalidConsoleURL
    case invalidInput
    case claimRejected
    case claimTimedOut
    case invalidClaimResponse
}

private enum DesktopSetupCopy {
    private static let values: [String: [AppLanguage: String]] = [
        "open_claim": [.english: "Open claim page", .spanish: "Abrir página de vinculación", .arabic: "فتح صفحة ربط الجهاز", .french: "Ouvrir la page d’association", .german: "Verknüpfungsseite öffnen"],
        "login": [.english: "Log in", .spanish: "Iniciar sesión", .arabic: "تسجيل الدخول", .french: "Se connecter", .german: "Anmelden"],
        "login_title": [.english: "Log in to Wantastic", .spanish: "Inicia sesión en Wantastic", .arabic: "تسجيل الدخول إلى Wantastic", .french: "Connexion à Wantastic", .german: "Bei Wantastic anmelden"],
        "login_hint": [.english: "Scan the code or continue in your browser. This Mac connects automatically after approval.", .spanish: "Escanea el código o continúa en el navegador. Este Mac se conectará automáticamente.", .arabic: "امسح الرمز أو تابع في المتصفح. سيتصل هذا الـ Mac تلقائيا بعد الموافقة.", .french: "Scannez le code ou continuez dans le navigateur. Ce Mac se connectera automatiquement.", .german: "Scanne den Code oder fahre im Browser fort. Dieser Mac verbindet sich danach automatisch."],
        "manual_setup": [.english: "Use connection details", .spanish: "Usar datos de conexión", .arabic: "استخدام تفاصيل الاتصال", .french: "Utiliser les détails de connexion", .german: "Verbindungsdaten verwenden"],
        "general": [.english: "General", .spanish: "General", .arabic: "عام", .french: "Général", .german: "Allgemein"],
        "network": [.english: "Network", .spanish: "Red", .arabic: "الشبكة", .french: "Réseau", .german: "Netzwerk"],
        "account": [.english: "Account", .spanish: "Cuenta", .arabic: "الحساب", .french: "Compte", .german: "Konto"],
        "configs": [.english: "Configs", .spanish: "Config.", .arabic: "الإعداد", .french: "Config.", .german: "Konfig."],
        "config_title": [.english: "Connection details", .spanish: "Datos de conexión", .arabic: "تفاصيل الاتصال", .french: "Détails de connexion", .german: "Verbindungsdaten"],
        "config_hint": [.english: "Paste the connection details provided by your administrator.", .spanish: "Pega los datos de conexión proporcionados por tu administrador.", .arabic: "الصق تفاصيل الاتصال المقدمة من المسؤول.", .french: "Collez les détails de connexion fournis par votre administrateur.", .german: "Füge die Verbindungsdaten deiner Administration ein."],
        "config_placeholder": [.english: "Paste connection details", .spanish: "Pegar datos de conexión", .arabic: "الصق تفاصيل الاتصال", .french: "Coller les détails de connexion", .german: "Verbindungsdaten einfügen"],
        "connect": [.english: "Connect", .spanish: "Conectar", .arabic: "اتصال", .french: "Se connecter", .german: "Verbinden"],
        "setup_title": [.english: "Connect this Mac", .spanish: "Conectar este Mac", .arabic: "توصيل هذا الـ Mac", .french: "Connecter ce Mac", .german: "Diesen Mac verbinden"],
        "setup_hint": [.english: "Use the claim page, or paste an access key or connection configuration.", .spanish: "Usa la página de vinculación o pega una clave de acceso o configuración.", .arabic: "استخدم صفحة الربط أو الصق مفتاح وصول أو إعداد اتصال.", .french: "Utilisez la page d’association ou collez une clé d’accès ou une configuration.", .german: "Nutze die Verknüpfungsseite oder füge einen Zugangsschlüssel bzw. eine Konfiguration ein."],
        "connect_pasted": [.english: "Connect pasted setup", .spanish: "Conectar datos pegados", .arabic: "الاتصال بالإعداد الملصق", .french: "Connecter les données collées", .german: "Eingefügte Daten verbinden"],
        "claim_waiting": [.english: "Finish in your browser. Wantastic will connect automatically.", .spanish: "Termina en el navegador. Wantastic se conectará automáticamente.", .arabic: "أكمل في المتصفح. سيتصل Wantastic تلقائيا.", .french: "Terminez dans le navigateur. Wantastic se connectera automatiquement.", .german: "Schließe den Vorgang im Browser ab. Wantastic verbindet sich automatisch."],
        "claim_saved": [.english: "Device claimed. Connection settings were saved.", .spanish: "Dispositivo vinculado. Se guardó la configuración.", .arabic: "تم ربط الجهاز وحفظ إعدادات الاتصال.", .french: "Appareil associé. La configuration a été enregistrée.", .german: "Gerät verknüpft. Verbindungseinstellungen wurden gespeichert."],
        "connecting_key": [.english: "Checking the pasted setup…", .spanish: "Comprobando los datos pegados…", .arabic: "جارٍ التحقق من الإعداد الملصق…", .french: "Vérification des données collées…", .german: "Eingefügte Daten werden geprüft…"],
        "invalid_setup": [.english: "Paste a valid access key, claim link, or connection configuration.", .spanish: "Pega una clave, enlace o configuración válidos.", .arabic: "الصق مفتاحا أو رابطا أو إعداد اتصال صالحا.", .french: "Collez une clé, un lien ou une configuration valide.", .german: "Füge einen gültigen Schlüssel, Link oder eine Konfiguration ein."],
        "claim_timeout": [.english: "The claim expired. Open a new claim page.", .spanish: "La vinculación caducó. Abre una página nueva.", .arabic: "انتهت مهلة الربط. افتح صفحة ربط جديدة.", .french: "L’association a expiré. Ouvrez une nouvelle page.", .german: "Die Verknüpfung ist abgelaufen. Öffne eine neue Seite."],
        "setup_failed": [.english: "Setup could not be completed. Check the value and try again.", .spanish: "No se pudo completar la configuración. Comprueba los datos.", .arabic: "تعذر إكمال الإعداد. تحقق من البيانات وحاول مجددا.", .french: "Impossible de terminer la configuration. Vérifiez les données.", .german: "Die Einrichtung konnte nicht abgeschlossen werden. Prüfe die Eingabe."],
        "retry_connection": [.english: "Retry connection", .spanish: "Reintentar conexión", .arabic: "إعادة محاولة الاتصال", .french: "Réessayer la connexion", .german: "Verbindung erneut versuchen"],
        "open_console": [.english: "Console", .spanish: "Consola", .arabic: "وحدة التحكم", .french: "Console", .german: "Konsole"]
    ]

    static func text(_ key: String, language: AppLanguage) -> String {
        values[key]?[language] ?? values[key]?[.english] ?? key
    }
}

struct MenuBarPanel: View {
    @EnvironmentObject private var tunnelController: TunnelController
    @State private var page: TrayPage = .network
    @State private var settingsSection: SettingsSection = .general
    @State private var registered = false
    @State private var peers: [P2PPeerRecord] = []
    @State private var selectedPeerID: UInt32?
    @State private var search = ""
    @State private var pingingPeerID: UInt32?
    @State private var pingResults: [UInt32: PingResult] = [:]
    @State private var pingErrors: [UInt32: String] = [:]
    @State private var scanningPeerID: UInt32?
    @State private var scannedServices: [UInt32: [NetworkService]] = [:]
    @State private var serviceScanErrors: [UInt32: String] = [:]
    @State private var exitNodeError = ""
    @State private var exitNodeWorking = false
    @State private var peersLoading = false
    @State private var peerLoadFailed = false
    @State private var setupInput = ""
    @State private var setupStatus = ""
    @State private var setupWorking = false
    @State private var activeClaimURL: URL?
    @State private var localAccessCandidates: [MacLocalAccessRoute] = []
    @State private var selectedLocalRoutes = Set<String>()
    @State private var localAccessEnabled = false
    @State private var localAccessWorking = false
    @State private var localAccessMessage = ""
    @ScaledMetric(relativeTo: .body) private var panelWidth: CGFloat = 350
    @ScaledMetric(relativeTo: .body) private var deviceRowHeight: CGFloat = 52
    @AppStorage("consoleURL") private var consoleURL = "https://console.wantastic.app"
    @AppStorage("language") private var language = AppLanguage.english.rawValue
    @AppStorage("registeredConsoleHost") private var registeredConsoleHost = ""
    @AppStorage("configurationMode") private var configurationMode = "registered"
    @AppStorage("selectedExitNodePeerID") private var selectedExitNodePeerID = 0

    private let logger = Logger(subsystem: "app.wantastic.desktop", category: "tray")

    private var selectedLanguage: AppLanguage { AppLanguage(rawValue: language) ?? .english }
    private func copy(_ key: String) -> String { AppCopy.text(key, language: selectedLanguage) }
    private func setupCopy(_ key: String) -> String { DesktopSetupCopy.text(key, language: selectedLanguage) }

    private var canConnect: Bool {
        registered && tunnelController.profileReady && tunnelController.state != .connecting
    }

    private var connectionTitle: String {
        if tunnelController.state == .connecting { return copy("connecting") }
        return tunnelController.state == .connected ? copy("online") : copy("offline")
    }

    private var connectionDetail: String {
        if !tunnelController.statusMessage.isEmpty { return tunnelController.statusMessage }
        if let key = tunnelController.statusCopyKey { return copy(key) }
        return registered ? copy("registered_tunnel_offline") : setupCopy("setup_hint")
    }

    private var connectionToggle: Binding<Bool> {
        Binding(
            get: { tunnelController.state == .connected || tunnelController.state == .connecting },
            set: { enabled in
                guard canConnect else { return }
                Task {
                    if enabled { await connectTunnel() }
                    else { tunnelController.disconnect() }
                }
            }
        )
    }

    private var filteredPeers: [P2PPeerRecord] {
        let ordered = peers.sorted { peerDisplayName($0).localizedStandardCompare(peerDisplayName($1)) == .orderedAscending }
        guard !search.isEmpty else { return ordered }
        return ordered.filter {
            peerDisplayName($0).localizedCaseInsensitiveContains(search) ||
            ($0.assignedIPv4?.localizedCaseInsensitiveContains(search) ?? false)
        }
    }

    private var offeredExitPeers: [P2PPeerRecord] { peers.filter(\.offersExitNode) }
    private var selectedExitPeer: P2PPeerRecord? {
        offeredExitPeers.first { Int($0.id) == selectedExitNodePeerID }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider().padding(.bottom, 10)
            if page == .settings {
                settingsPanel
            } else if registered {
                networkPanel
            } else {
                setupPanel
            }
            Divider().padding(.top, 10)
            footer
        }
        .padding(12)
        .frame(width: panelWidth)
        .fixedSize(horizontal: false, vertical: true)
        .environment(\.layoutDirection, selectedLanguage == .arabic ? .rightToLeft : .leftToRight)
        .task {
#if DEBUG
            let preview = ProcessInfo.processInfo.environment["WANTASTIC_UI_PREVIEW"]
            if preview == "network" || preview == "1" {
                registered = true
                return
            }
#endif
            await restoreAndConnect()
        }
        .task(id: tunnelController.state) {
            guard tunnelController.state == .connected else {
                peers = []
                return
            }
            while !Task.isCancelled, tunnelController.state == .connected {
                await refreshPeers()
                await refreshLocalAccessStatus()
                do { try await Task.sleep(for: .seconds(5)) }
                catch { return }
            }
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 11) {
            ConnectionBrandMark(state: tunnelController.state)
                .frame(width: 32, height: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text("Wantastic").font(.system(size: 15, weight: .semibold, design: .rounded))
                Text(connectionTitle)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(ConnectionStatusStyle.color(for: tunnelController.state))
            }
            Spacer(minLength: 8)
            if registered {
                Toggle("", isOn: connectionToggle)
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .controlSize(.regular)
                    .disabled(!canConnect)
                    .help(connectionToggle.wrappedValue ? copy("disconnect") : copy("connect"))
            }
        }
        .padding(.horizontal, 2)
        .padding(.bottom, 10)
    }

    private var networkPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            if tunnelController.state != .connected || !setupStatus.isEmpty {
                statusMessage
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.primary.opacity(0.055), in: RoundedRectangle(cornerRadius: 11))
            }
            if tunnelController.state != .connected {
                Button(setupCopy("retry_connection")) { Task { await connectTunnel() } }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .disabled(setupWorking || !tunnelController.profileReady)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }

            Menu {
                Button { Task { await changeExitNode(to: nil) } } label: {
                    if selectedExitNodePeerID == 0 { Label(copy("none"), systemImage: "checkmark") }
                    else { Text(copy("none")) }
                }
                if !offeredExitPeers.isEmpty { Divider() }
                ForEach(offeredExitPeers, id: \.id) { peer in
                    Button { Task { await changeExitNode(to: peer) } } label: {
                        if Int(peer.id) == selectedExitNodePeerID {
                            Label(peerDisplayName(peer), systemImage: "checkmark")
                        } else {
                            Text(peerDisplayName(peer))
                        }
                    }
                }
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "globe")
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                        .frame(width: 18)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(copy("exit_node")).font(.system(size: 12, weight: .medium))
                        Text(selectedExitPeer.map(peerDisplayName) ?? copy("none"))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.system(size: 9, weight: .semibold)).foregroundStyle(.tertiary)
                }
                .padding(.horizontal, 11)
                .frame(height: 46)
                .background(Color.primary.opacity(0.055), in: RoundedRectangle(cornerRadius: 11))
                .contentShape(Rectangle())
            }
            .menuStyle(.borderlessButton)
            .disabled(tunnelController.state != .connected || exitNodeWorking)

            TextField(copy("search_devices"), text: $search)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12))
                .disabled(tunnelController.state != .connected)

            HStack {
                Text(copy("your_network")).font(.system(size: 12, weight: .semibold))
                Spacer()
                if tunnelController.state == .connected {
                    Text("\(peers.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    Button { Task { await refreshPeers() } } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .buttonStyle(.plain)
                    .help(copy("refresh_devices"))
                }
            }

            Group {
                if tunnelController.state != .connected {
                    trayEmptyState(title: copy("offline"), systemImage: "network.slash",
                                   description: nil)
                } else if peersLoading && peers.isEmpty {
                    ProgressView(copy("connecting")).controlSize(.small)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if peerLoadFailed && peers.isEmpty {
                    trayEmptyState(title: copy("connection_failed"), systemImage: "wifi.exclamationmark",
                                   description: copy("refresh_devices"))
                } else if filteredPeers.isEmpty {
                    trayEmptyState(title: search.isEmpty ? copy("no_devices") : copy("no_matching_devices"),
                                   systemImage: "desktopcomputer",
                                   description: search.isEmpty ? copy("no_online_devices") : nil)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(filteredPeers, id: \.id) { peer in
                                peerRow(peer)
                                if peer.id != filteredPeers.last?.id { Divider().padding(.leading, 20) }
                            }
                        }
                    }
                    .scrollIndicators(.automatic)
                }
            }
            .frame(height: listHeight)
            .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 11))
            if !exitNodeError.isEmpty { Text(exitNodeError).font(.caption).foregroundStyle(.red) }
        }
    }

    private var setupPanel: some View {
        VStack(alignment: .center, spacing: 12) {
            Text(setupCopy("login_title"))
                .font(.system(size: 16, weight: .semibold, design: .rounded))
            Text(setupCopy("login_hint"))
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)

            Group {
                if let activeClaimURL, let image = claimQRCode(for: activeClaimURL) {
                    Image(nsImage: image)
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 132, height: 132)
                        .padding(9)
                        .background(Color.white, in: RoundedRectangle(cornerRadius: 13))
                        .accessibilityLabel(setupCopy("login"))
                } else {
                    ProgressView().controlSize(.small).frame(width: 150, height: 150)
                }
            }

            Button(setupCopy("login")) { openClaimPage() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .frame(width: 190)
                .disabled(activeClaimURL == nil)

            if !setupStatus.isEmpty {
                Text(setupStatus).font(.caption).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
    }

    private var settingsPanel: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Button { page = .network } label: { Image(systemName: "chevron.left") }
                    .buttonStyle(.plain)
                Text(copy("settings")).font(.system(size: 14, weight: .semibold))
            }
            .padding(.bottom, 12)

            settingsTabBar
                .padding(.horizontal, -12)

            ScrollView {
                Group {
                    switch settingsSection {
                    case .general: generalSettings
                    case .network: networkSettings
                    case .account: accountSettings
                    case .configs: configsSettings
                    }
                }
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .padding(.horizontal, 2)
                .padding(.vertical, 14)
            }
            .scrollIndicators(.automatic)
            .frame(maxWidth: .infinity, minHeight: 258, maxHeight: 340, alignment: .top)
        }
        .frame(maxWidth: .infinity, minHeight: 330, alignment: .topLeading)
        .task {
            refreshLocalAccessCandidates()
            await refreshLocalAccessStatus()
        }
    }

    private var settingsTabBar: some View {
        HStack(spacing: 0) {
            settingsTab(.general, title: setupCopy("general"), systemImage: "gearshape")
            Divider().frame(height: 28)
            settingsTab(.network, title: setupCopy("network"), systemImage: "network")
            Divider().frame(height: 28)
            settingsTab(.account, title: setupCopy("account"), systemImage: "person.crop.circle")
            Divider().frame(height: 28)
            settingsTab(.configs, title: setupCopy("configs"), systemImage: "doc.text")
        }
        .frame(maxWidth: .infinity)
        .background(Color.primary.opacity(0.035))
        .overlay(alignment: .top) { Divider() }
        .overlay(alignment: .bottom) { Divider() }
    }

    private func settingsTab(
        _ section: SettingsSection,
        title: String,
        systemImage: String
    ) -> some View {
        Button {
            settingsSection = section
        } label: {
            Label(title, systemImage: systemImage)
                .font(.system(size: 11, weight: settingsSection == section ? .semibold : .regular))
                .lineLimit(1)
                .minimumScaleFactor(0.8)
                .foregroundStyle(settingsSection == section ? Color.primary : Color.secondary)
                .frame(maxWidth: .infinity, minHeight: 38)
                .contentShape(Rectangle())
                .overlay(alignment: .bottom) {
                    Rectangle()
                        .fill(settingsSection == section ? Color.accentColor : Color.clear)
                        .frame(height: 2)
                }
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
    }

    private var generalSettings: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                Text(copy("console_address"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                TextField(copy("console_address"), text: $consoleURL)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: .infinity)
            }
            .padding(.vertical, 10)

            Divider()

            HStack(spacing: 12) {
                Text(copy("language"))
                    .font(.system(size: 12, weight: .medium))
                Spacer(minLength: 12)
                Picker("", selection: $language) {
                    ForEach(AppLanguage.allCases) { item in Text(item.name).tag(item.rawValue) }
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .fixedSize()
            }
            .padding(.vertical, 10)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var networkSettings: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(copy("local_network_access")).font(.system(size: 12, weight: .semibold))
            if localAccessCandidates.isEmpty {
                Text(copy("no_private_networks_hint")).font(.caption).foregroundStyle(.secondary)
            } else {
                ForEach(localAccessCandidates, id: \.prefix.description) { route in
                    Toggle(isOn: Binding(
                        get: { selectedLocalRoutes.contains(route.prefix.description) },
                        set: { selected in
                            if selected { selectedLocalRoutes.insert(route.prefix.description) }
                            else { selectedLocalRoutes.remove(route.prefix.description) }
                        })) {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(route.prefix.description).font(.system(.caption, design: .monospaced))
                            Text(route.interfaceName).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    .disabled(localAccessEnabled || tunnelController.state != .connected || localAccessWorking)
                }
            }
            Button(localAccessEnabled ? copy("stop_local_access") : copy("allow_local_access")) {
                Task { await toggleLocalAccess() }
            }
            .controlSize(.small)
            .disabled(localAccessWorking || tunnelController.state != .connected ||
                      (!localAccessEnabled && selectedLocalRoutes.isEmpty))
            if !localAccessMessage.isEmpty {
                Text(localAccessMessage).font(.caption2).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var accountSettings: some View {
        VStack(alignment: .leading, spacing: 10) {
            if registered {
                Label(connectionTitle, systemImage: "checkmark.shield")
                    .font(.system(size: 12, weight: .medium))
                Button(copy("remove_credentials"), role: .destructive) {
                    Task { await removeSavedConfiguration() }
                }
                .controlSize(.small)
            } else {
                setupPanel
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var configsSettings: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(setupCopy("config_title"))
                .font(.system(size: 12, weight: .semibold))
            Text(setupCopy("config_hint"))
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ZStack(alignment: .topLeading) {
                TextEditor(text: $setupInput)
                    .font(.system(.caption, design: .monospaced))
                    .scrollContentBackground(.hidden)
                    .padding(6)
                if setupInput.isEmpty {
                    Text(setupCopy("config_placeholder"))
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .padding(.horizontal, 11)
                        .padding(.vertical, 13)
                        .allowsHitTesting(false)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 112)
            .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.primary.opacity(0.11), lineWidth: 1)
            }

            Button {
                Task { await connectPastedSetup() }
            } label: {
                HStack(spacing: 7) {
                    if setupWorking { ProgressView().controlSize(.small) }
                    Text(setupCopy("connect"))
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(setupWorking || setupInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

            if !setupStatus.isEmpty {
                Text(setupStatus)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var statusMessage: some View {
        HStack(alignment: .top, spacing: 7) {
            Image(systemName: tunnelController.state == .connected ? "checkmark.shield" : "info.circle")
                .foregroundStyle(ConnectionStatusStyle.color(for: tunnelController.state))
            Text(setupStatus.isEmpty ? connectionDetail : setupStatus)
                .font(.caption)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var footer: some View {
        HStack(spacing: 12) {
            Button {
                if let url = try? normalizedConsoleBaseURL(consoleURL) { NSWorkspace.shared.open(url) }
            } label: {
                Label(setupCopy("open_console"), systemImage: "globe")
                    .font(.system(size: 12, weight: .medium))
            }
            .buttonStyle(.plain)
            Spacer()
            Button { page = page == .settings ? .network : .settings } label: {
                Image(systemName: page == .settings ? "chevron.left" : "gearshape")
            }
            .buttonStyle(.plain)
            .help(copy("settings"))
            Button { NSApp.terminate(nil) } label: { Image(systemName: "power") }
                .buttonStyle(.plain)
                .help(copy("quit"))
        }
        .padding(.top, 9)
    }

    private var listHeight: CGFloat {
        guard tunnelController.state == .connected else { return deviceRowHeight + 22 }
        let expandedRows = selectedPeerID == nil ? 0 : 42
        return min(max(CGFloat(filteredPeers.count) * deviceRowHeight + CGFloat(expandedRows),
                       deviceRowHeight + 22), deviceRowHeight * 6 + 42)
    }

    private func trayEmptyState(title: String, systemImage: String, description: String?) -> some View {
        VStack(spacing: 5) {
            Label(title, systemImage: systemImage).font(.subheadline.weight(.medium))
            if let description {
                Text(description).font(.caption).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).lineLimit(3)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(.horizontal, 8)
    }

    private func peerRow(_ peer: P2PPeerRecord) -> some View {
        let selected = selectedPeerID == peer.id
        let reachable = peer.direct || peer.udpReachable
        return VStack(alignment: .leading, spacing: 6) {
            Button { selectedPeerID = selected ? nil : peer.id } label: {
                HStack(spacing: 8) {
                    Image(systemName: reachable ? "network" : "network.slash")
                        .foregroundStyle(reachable ? Color.green : Color.secondary)
                        .frame(width: 16)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(peerDisplayName(peer)).font(.body.weight(.medium)).lineLimit(1)
                        Text("\(peer.assignedIPv4 ?? copy("address_unavailable")) · \(copy(peer.direct ? "direct" : (peer.udpReachable ? "p2p_reachable" : "path_unconfirmed")))")
                            .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer()
                    if let result = pingResults[peer.id] {
                        Text(result.reachable ? "\(result.averageMS) ms" : copy("ping_unreachable"))
                            .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                    }
                    Image(systemName: selected ? "chevron.up" : "chevron.down")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
                .contentShape(Rectangle())
                .padding(.vertical, 6)
            }
            .buttonStyle(.plain)
            if selected {
                HStack(spacing: 8) {
                    Button(copy("ping")) { Task { await ping(peer) } }
                    Button(copy("scan_services")) { Task { await scanServices(peer) } }
                    if let address = peer.assignedIPv4 {
                        Button(copy("copy_ip")) {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(address, forType: .string)
                        }
                    }
                }
                .controlSize(.mini)
                .disabled(peer.assignedIPv4 == nil || pingingPeerID != nil || scanningPeerID != nil)
                if pingingPeerID == peer.id { ProgressView(copy("pinging_device")).controlSize(.small) }
                if scanningPeerID == peer.id { ProgressView(copy("scanning_services")).controlSize(.small) }
                if let services = scannedServices[peer.id] {
                    ForEach(services) { service in
                        if let address = peer.assignedIPv4,
                           let url = ServiceActionURL.make(address: address, service: service) {
                            Button { NSWorkspace.shared.open(url) } label: {
                                Label("\(serviceTitle(service.kind)) · \(service.port)", systemImage: serviceIcon(service.kind))
                            }
                            .buttonStyle(.link).font(.caption)
                        }
                    }
                }
                if let error = pingErrors[peer.id] ?? serviceScanErrors[peer.id] {
                    Text(error).font(.caption2).foregroundStyle(.red)
                }
            }
        }
    }

    private func peerDisplayName(_ peer: P2PPeerRecord) -> String { "\(copy("device")) \(peer.id)" }

    private func serviceTitle(_ kind: ServiceKind) -> String {
        switch kind {
        case .web: copy("service_web")
        case .secureShell: "SSH"
        case .remoteDesktop: copy("service_remote_desktop")
        case .other: copy("services")
        }
    }

    private func serviceIcon(_ kind: ServiceKind) -> String {
        switch kind {
        case .web: "safari"
        case .secureShell: "terminal"
        case .remoteDesktop: "rectangle.connected.to.line.below"
        case .other: "network"
        }
    }

    @MainActor
    private func restoreAndConnect() async {
        guard !registeredConsoleHost.isEmpty else {
            await resumePendingClaimIfNeeded()
            return
        }
        let host = registeredConsoleHost
        do {
            let manual = try ManualWireGuardConfigurationStore().load(consoleHost: host)
            let account = try RegisteredDeviceStore().load(consoleHost: host)
            if (configurationMode == "manual" || account == nil), let manual {
                registered = true
                configurationMode = "manual"
                try await tunnelController.configureManualProfile(consoleHost: host,
                                                                  serverAddress: manual.endpointHost)
                await connectTunnel()
                return
            }
            if let account {
                registered = true
                configurationMode = "registered"
                try await tunnelController.configureProfile(consoleHost: host,
                                                            serverAddress: account.configuration.endpointHost)
                await connectTunnel()
                return
            }
            registered = false
            await resumePendingClaimIfNeeded()
        } catch {
            registered = Self.hasSavedConfiguration(host: host)
            setupStatus = connectionFailureMessage(error)
            logger.error("Restore/connect failed: \(String(describing: error), privacy: .public)")
        }
    }

    @MainActor
    private func connectTunnel() async {
        guard registered, tunnelController.profileReady else {
            setupStatus = connectionDetail
            return
        }
        setupWorking = true
        defer { setupWorking = false }
        do {
            try await tunnelController.connect()
            setupStatus = copy("starting_secure_connection")
        } catch {
            setupStatus = connectionFailureMessage(error)
            logger.error("Tunnel activation failed: \(String(describing: error), privacy: .public)")
        }
    }

    private func connectionFailureMessage(_ error: Error) -> String {
        if !tunnelController.statusMessage.isEmpty { return tunnelController.statusMessage }
        if let key = tunnelController.statusCopyKey { return copy(key) }
        return error.localizedDescription
    }

    private func openClaimPage() {
        guard let activeClaimURL, SecureWebNavigationPolicy.allows(activeClaimURL) else { return }
        NSWorkspace.shared.open(activeClaimURL)
        setupStatus = setupCopy("claim_waiting")
    }

    @MainActor
    private func resumePendingClaimIfNeeded() async {
        guard let baseURL = try? normalizedConsoleBaseURL(consoleURL), let host = baseURL.host else {
            setupStatus = setupCopy("setup_failed")
            return
        }
        let pending: PendingDesktopClaim
        let storedData: Data?
        do {
            storedData = try CredentialVault().read(account: pendingClaimAccount(host))
        } catch {
            setupStatus = setupCopy("setup_failed")
            logger.error("Could not read pending claim: \(String(describing: error), privacy: .public)")
            return
        }
        if let storedData,
           let saved = try? JSONDecoder().decode(PendingDesktopClaim.self, from: storedData),
           saved.serverURL == baseURL.absoluteString {
            pending = saved
        } else {
            let privateKey = Curve25519.KeyAgreement.PrivateKey()
            pending = PendingDesktopClaim(
                privateKey: privateKey.rawRepresentation.base64EncodedString(),
                publicKey: privateKey.publicKey.rawRepresentation.base64EncodedString(),
                serverURL: baseURL.absoluteString)
            do { try savePendingClaim(pending, host: host) }
            catch {
                setupStatus = setupCopy("setup_failed")
                logger.error("Could not save pending claim: \(String(describing: error), privacy: .public)")
                return
            }
        }
        activeClaimURL = makeClaimURL(baseURL: baseURL, publicKey: pending.publicKey)
        guard activeClaimURL != nil else {
            setupStatus = setupCopy("setup_failed")
            return
        }
        setupWorking = true
        defer { setupWorking = false }
        do {
            let claim = try await waitForClaim(baseURL: baseURL, publicKey: pending.publicKey)
            let configuration = try makeClaimedConfiguration(privateKey: pending.privateKey, claim: claim)
            await activateManualConfiguration(configuration, baseURL: baseURL)
        } catch {
            setupStatus = error is DesktopSetupError ? setupCopy("claim_timeout") : setupCopy("setup_failed")
        }
    }

    private func claimQRCode(for url: URL) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(url.absoluteString.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        let context = CIContext(options: [.useSoftwareRenderer: false])
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: scaled.extent.width, height: scaled.extent.height))
    }

    @MainActor
    private func connectPastedSetup() async {
        guard !setupWorking else { return }
        let raw = setupInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty, raw.utf8.count <= 64 * 1024 else {
            setupStatus = setupCopy("invalid_setup")
            return
        }
        setupWorking = true
        setupStatus = setupCopy("connecting_key")
        defer { setupWorking = false }
        do {
            var baseURL = try normalizedConsoleBaseURL(consoleURL)
            if raw.contains("[Interface]") && raw.contains("[Peer]") {
                let configuration = try WireGuardConfiguration.parse(raw)
                setupInput = ""
                await activateManualConfiguration(configuration, baseURL: baseURL)
                return
            }
            if let object = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any] {
                if let server = object["server_url"] as? String { baseURL = try normalizedConsoleBaseURL(server) }
                if let config = object["config"] as? String {
                    let configuration = try WireGuardConfiguration.parse(config)
                    setupInput = ""
                    await activateManualConfiguration(configuration, baseURL: baseURL)
                    return
                }
                if let privateValue = object["private_key"] as? String,
                   let privateData = Data(base64Encoded: privateValue), privateData.count == 32,
                   let publicValue = object["public_key"] as? String {
                    let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateData)
                    guard privateKey.publicKey.rawRepresentation.base64EncodedString() == publicValue else {
                        throw DesktopSetupError.invalidInput
                    }
                    let pending = PendingDesktopClaim(privateKey: privateValue, publicKey: publicValue,
                                                      serverURL: baseURL.absoluteString)
                    try savePendingClaim(pending, host: baseURL.host ?? "")
                    if let claimURL = makeClaimURL(baseURL: baseURL, publicKey: publicValue) {
                        NSWorkspace.shared.open(claimURL)
                    }
                    setupStatus = setupCopy("claim_waiting")
                    let claim = try await waitForClaim(baseURL: baseURL, publicKey: publicValue)
                    let configuration = try makeClaimedConfiguration(privateKey: privateValue, claim: claim)
                    setupInput = ""
                    await activateManualConfiguration(configuration, baseURL: baseURL)
                    return
                }
                if let token = (object["access_token"] ?? object["token"]) as? String {
                    try await registerAndConnect(accessToken: token, baseURL: baseURL)
                    setupInput = ""
                    return
                }
                if let claimLink = object["claim_url"] as? String,
                   let url = URL(string: claimLink), SecureWebNavigationPolicy.allows(url) {
                    NSWorkspace.shared.open(url)
                    setupStatus = setupCopy("claim_waiting")
                    return
                }
            }
            if let url = URL(string: raw), SecureWebNavigationPolicy.allows(url) {
                NSWorkspace.shared.open(url)
                setupStatus = setupCopy("claim_waiting")
                return
            }
            try await registerAndConnect(accessToken: raw, baseURL: baseURL)
            setupInput = ""
        } catch {
            setupStatus = setupCopy("setup_failed")
            logger.error("Pasted setup failed: \(String(describing: error), privacy: .public)")
        }
    }

    @MainActor
    private func registerAndConnect(accessToken: String, baseURL: URL) async throws {
        let raw = accessToken.trimmingCharacters(in: .whitespacesAndNewlines)
        let token = raw.lowercased().hasPrefix("bearer ")
            ? String(raw.dropFirst(7)).trimmingCharacters(in: .whitespacesAndNewlines) : raw
        guard !token.isEmpty, token.utf8.count <= 16 * 1024, let host = baseURL.host else {
            throw DesktopSetupError.invalidInput
        }
        let deviceID = try DeviceIdentity.hashedPlatformIdentifier()
        let device = try await DeviceRegistrationClient(baseURL: baseURL)
            .register(accessToken: token, deviceID: deviceID)
        try RegisteredDeviceStore().save(device, consoleHost: host)
        configurationMode = "registered"
        registeredConsoleHost = host
        registered = true
        try? CredentialVault().delete(account: pendingClaimAccount(host))
        try await tunnelController.configureProfile(consoleHost: host,
                                                    serverAddress: device.configuration.endpointHost)
        do {
            try await tunnelController.connect()
            setupStatus = copy("starting_secure_connection")
        } catch {
            setupStatus = setupCopy("claim_saved") + " " + connectionFailureMessage(error)
        }
    }

    @MainActor
    private func activateManualConfiguration(_ configuration: WireGuardConfiguration, baseURL: URL) async {
        guard let host = baseURL.host else {
            setupStatus = setupCopy("setup_failed")
            return
        }
        do {
            try ManualWireGuardConfigurationStore().save(configuration, consoleHost: host)
            configurationMode = "manual"
            registeredConsoleHost = host
            registered = true
            activeClaimURL = nil
            try? CredentialVault().delete(account: pendingClaimAccount(host))
            try await tunnelController.configureManualProfile(consoleHost: host,
                                                              serverAddress: configuration.endpointHost)
            do {
                try await tunnelController.connect()
                setupStatus = copy("starting_secure_connection")
            } catch {
                setupStatus = setupCopy("claim_saved") + " " + connectionFailureMessage(error)
                logger.error("Claim saved; tunnel activation failed: \(String(describing: error), privacy: .public)")
            }
        } catch {
            setupStatus = setupCopy("setup_failed")
            logger.error("Saving claimed configuration failed: \(String(describing: error), privacy: .public)")
        }
    }

    private func normalizedConsoleBaseURL(_ raw: String) throws -> URL {
        guard var components = URLComponents(string: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              components.scheme?.lowercased() == "https", components.host != nil,
              components.user == nil, components.password == nil else {
            throw DesktopSetupError.invalidConsoleURL
        }
        components.path = ""
        components.query = nil
        components.fragment = nil
        guard let url = components.url else { throw DesktopSetupError.invalidConsoleURL }
        return url
    }

    private func makeClaimURL(baseURL: URL, publicKey: String) -> URL? {
        // URLComponents intentionally leaves `+` unescaped in query values.
        // Base64 WireGuard keys can contain `+`, which form-style decoders turn
        // into spaces. Encode values using RFC 3986's unreserved set instead.
        let unreserved = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        guard let encodedKey = publicKey.addingPercentEncoding(withAllowedCharacters: unreserved),
              let encodedServer = baseURL.absoluteString.addingPercentEncoding(
                withAllowedCharacters: unreserved)
        else { return nil }
        let encoded = "claim_public_key=\(encodedKey)&wantastic_server=\(encodedServer)"
        return URL(string: "\(baseURL.absoluteString)/#desktop?\(encoded)")
    }

    private func savePendingClaim(_ pending: PendingDesktopClaim, host: String) throws {
        guard !host.isEmpty else { throw DesktopSetupError.invalidConsoleURL }
        try CredentialVault().write(JSONEncoder().encode(pending), account: pendingClaimAccount(host))
    }

    private func pendingClaimAccount(_ host: String) -> String {
        "pending-claim:\(host.lowercased())"
    }

    private func waitForClaim(baseURL: URL, publicKey: String) async throws -> DesktopClaimConfiguration {
        let deviceID = try DeviceIdentity.hashedPlatformIdentifier()
        let deadline = Date().addingTimeInterval(10 * 60)
        while Date() < deadline {
            do {
                if let claim = try await fetchClaim(baseURL: baseURL, deviceID: deviceID, publicKey: publicKey),
                   claim.claimed { return claim }
            } catch DesktopSetupError.claimRejected {
                throw DesktopSetupError.claimRejected
            } catch let error as URLError where [
                .timedOut, .networkConnectionLost, .notConnectedToInternet,
                .cannotConnectToHost, .dnsLookupFailed
            ].contains(error.code) {}
            try await Task.sleep(for: .seconds(4))
        }
        throw DesktopSetupError.claimTimedOut
    }

    private func fetchClaim(baseURL: URL, deviceID: String,
                            publicKey: String) async throws -> DesktopClaimConfiguration? {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            throw DesktopSetupError.invalidConsoleURL
        }
        components.path = "/api/agent/claim-config"
        components.queryItems = [URLQueryItem(name: "public_key", value: publicKey)]
        guard let url = components.url else { throw DesktopSetupError.invalidConsoleURL }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 20
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let timestamp = String(Int(Date().timeIntervalSince1970))
        request.setValue(timestamp, forHTTPHeaderField: "x-wantastic-ts")
        request.setValue(deviceID, forHTTPHeaderField: "x-wantastic-device")
        let message = Data("\(timestamp):\(deviceID)".utf8)
        let key = SymmetricKey(data: Data("wantastic_cipher_v_1_0_0".utf8))
        let signature = HMAC<SHA256>.authenticationCode(for: message, using: key)
            .map { String(format: "%02x", $0) }.joined()
        request.setValue(signature, forHTTPHeaderField: "x-wantastic-sig")
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.urlCache = nil
        sessionConfiguration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let session = URLSession(configuration: sessionConfiguration)
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, data.count <= 1_048_576 else {
            throw DesktopSetupError.invalidClaimResponse
        }
        switch http.statusCode {
        case 200: return try JSONDecoder().decode(DesktopClaimConfiguration.self, from: data)
        case 204, 404, 408, 409, 425, 429, 500...599: return nil
        case 401, 403: throw DesktopSetupError.claimRejected
        default: throw DesktopSetupError.invalidClaimResponse
        }
    }

    private func makeClaimedConfiguration(privateKey: String,
                                          claim: DesktopClaimConfiguration) throws -> WireGuardConfiguration {
        guard claim.claimed,
              let address = claim.assignedIP?.trimmingCharacters(in: .whitespacesAndNewlines), !address.isEmpty,
              let serverKey = claim.serverKey?.trimmingCharacters(in: .whitespacesAndNewlines), !serverKey.isEmpty,
              var endpoint = claim.endpoint?.trimmingCharacters(in: .whitespacesAndNewlines), !endpoint.isEmpty,
              let allowedIPs = claim.allowedIPs, !allowedIPs.isEmpty else {
            throw DesktopSetupError.invalidClaimResponse
        }
        if URLComponents(string: "wg://\(endpoint)")?.port == nil {
            endpoint += ":\(claim.listenPort.flatMap { $0 > 0 ? $0 : nil } ?? 51820)"
        }
        var lines = ["[Interface]", "PrivateKey = \(privateKey)", "Address = \(address)"]
        let dns = (claim.dnsServers ?? []).filter { !$0.isEmpty }
        if !dns.isEmpty { lines.append("DNS = \(dns.joined(separator: ", "))") }
        lines.append("MTU = \(claim.mtu.flatMap { $0 > 0 ? $0 : nil } ?? 1420)")
        lines += ["", "[Peer]", "PublicKey = \(serverKey)", "Endpoint = \(endpoint)",
                  "AllowedIPs = \(allowedIPs.joined(separator: ", "))",
                  "PersistentKeepalive = \(claim.persistentKeepalive.flatMap { $0 > 0 ? $0 : nil } ?? 25)"]
        return try WireGuardConfiguration.parse(lines.joined(separator: "\n"))
    }

    @MainActor
    private func refreshPeers() async {
        guard tunnelController.state == .connected else { peers = []; return }
        peersLoading = true
        defer { peersLoading = false }
        do {
            peers = try await tunnelController.p2pDevices()
            peerLoadFailed = false
            if selectedExitNodePeerID != 0,
               !peers.contains(where: { Int($0.id) == selectedExitNodePeerID && $0.offersExitNode }) {
                selectedExitNodePeerID = 0
            }
        } catch { peerLoadFailed = true }
    }

    @MainActor
    private func changeExitNode(to peer: P2PPeerRecord?) async {
        guard tunnelController.state == .connected, !exitNodeWorking else { return }
        exitNodeWorking = true
        exitNodeError = ""
        defer { exitNodeWorking = false }
        do {
            try await tunnelController.setExitNode(peerID: peer?.id)
            selectedExitNodePeerID = peer.map { Int($0.id) } ?? 0
        } catch TunnelRPCError.peerDoesNotOfferExitNode {
            selectedExitNodePeerID = 0
            exitNodeError = copy("peer_not_exit_node")
        } catch { exitNodeError = copy("exit_node_request_failed") }
    }

    @MainActor
    private func ping(_ peer: P2PPeerRecord) async {
        guard let address = peer.assignedIPv4, pingingPeerID == nil, scanningPeerID == nil else { return }
        pingingPeerID = peer.id
        pingErrors[peer.id] = nil
        defer { pingingPeerID = nil }
        do {
            pingResults[peer.id] = try await NativePingService.ping(
                target: peerDisplayName(peer), address: address, sampleCount: 6)
        } catch { pingErrors[peer.id] = copy("ping_failed") }
    }

    @MainActor
    private func scanServices(_ peer: P2PPeerRecord) async {
        guard let address = peer.assignedIPv4, scanningPeerID == nil, pingingPeerID == nil else { return }
        scanningPeerID = peer.id
        serviceScanErrors[peer.id] = nil
        defer { scanningPeerID = nil }
        do { scannedServices[peer.id] = try await TCPServiceScanner.scan(address: address) }
        catch { serviceScanErrors[peer.id] = copy("service_scan_failed") }
    }

    private func refreshLocalAccessCandidates() {
        do {
            localAccessCandidates = try MacDeviceCollector.privateLANRouteCandidates()
            selectedLocalRoutes.formIntersection(Set(localAccessCandidates.map { $0.prefix.description }))
        } catch {
            localAccessCandidates = []
            localAccessMessage = copy("local_access_discovery_failed")
        }
    }

    @MainActor
    private func refreshLocalAccessStatus() async {
        guard tunnelController.state == .connected else { localAccessEnabled = false; return }
        localAccessEnabled = (try? await tunnelController.localAccessEnabled()) ?? false
    }

    @MainActor
    private func toggleLocalAccess() async {
        localAccessWorking = true
        localAccessMessage = ""
        defer { localAccessWorking = false }
        do {
            if localAccessEnabled {
                try await tunnelController.setLocalAccess(routes: nil)
                localAccessEnabled = false
            } else {
                try await tunnelController.setLocalAccess(routes: selectedLocalRoutes.sorted())
                localAccessEnabled = true
            }
        } catch TunnelRPCError.localAccessApprovalRequired {
            localAccessMessage = copy("local_access_approval")
        } catch { localAccessMessage = copy("local_access_failed") }
    }

    @MainActor
    private func removeSavedConfiguration() async {
        let host = registeredConsoleHost
        tunnelController.disconnect()
        try? RegisteredDeviceStore().remove(consoleHost: host)
        try? ManualWireGuardConfigurationStore().remove(consoleHost: host)
        try? CredentialVault().delete(account: pendingClaimAccount(host))
        try? await tunnelController.removeProfile()
        registeredConsoleHost = ""
        configurationMode = "registered"
        registered = false
        peers = []
        setupStatus = ""
        page = .network
    }

    private static func hasSavedConfiguration(host: String) -> Bool {
        guard !host.isEmpty else { return false }
        return (try? RegisteredDeviceStore().load(consoleHost: host)) != nil ||
            (try? ManualWireGuardConfigurationStore().load(consoleHost: host)) != nil
    }
}
