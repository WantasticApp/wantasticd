import Foundation
import Combine
import NetworkExtension
import WantasticCore

/// Owns the user's VPN profile and activates its embedded system extension
/// through macOS before a tunnel connection is requested.
@MainActor
public final class TunnelController: ObservableObject {
    @Published public private(set) var state: ConnectionState = .disconnected
    @Published public private(set) var statusCopyKey: String? = "tunnel_extension_not_installed"
    @Published public private(set) var statusMessage = ""
    @Published public private(set) var profileReady = false

    private var manager: NETunnelProviderManager?
    private var statusPollingTask: Task<Void, Never>?

    public init() {}

    public func refresh() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first { candidate in
                guard let tunnel = candidate.protocolConfiguration as? NETunnelProviderProtocol else { return false }
                return TunnelProfilePolicy.isWantastic(providerBundleIdentifier: tunnel.providerBundleIdentifier)
            }
            guard let manager else {
                profileReady = false
                state = .disconnected
                setStatus(copyKey: "tunnel_extension_not_installed")
                return
            }
            profileReady = true
            switch manager.connection.status {
            case .connected: state = .connected
            case .connecting, .reasserting: state = .connecting
            case .disconnecting, .disconnected, .invalid: state = .disconnected
            @unknown default: state = .failed
            }
            setStatus(copyKey: "tunnel_profile_ready")
        } catch {
            state = .failed
            setStatus(error: error)
        }
    }

    /// Saves a non-secret provider profile. The provider resolves the actual
    /// registered configuration from the shared Keychain using this host key.
    public func configureProfile(consoleHost: String, serverAddress: String) async throws {
        try await configureProfile(consoleHost: consoleHost, serverAddress: serverAddress,
                                   configurationSource: "registered")
    }

    public func configureManualProfile(consoleHost: String, serverAddress: String) async throws {
        try await configureProfile(consoleHost: consoleHost, serverAddress: serverAddress,
                                   configurationSource: "manual")
    }

    private func configureProfile(consoleHost: String, serverAddress: String,
                                  configurationSource: String) async throws {
        let host = consoleHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !host.isEmpty, !host.contains("/"), !host.contains("@"),
              !serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              ["registered", "manual"].contains(configurationSource) else {
            throw TunnelProfileError.invalidConfiguration
        }
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let profile = managers.first { candidate in
                guard let tunnel = candidate.protocolConfiguration as? NETunnelProviderProtocol else { return false }
                return TunnelProfilePolicy.isWantastic(providerBundleIdentifier: tunnel.providerBundleIdentifier)
            } ?? NETunnelProviderManager()
            let tunnelProtocol = NETunnelProviderProtocol()
            tunnelProtocol.providerBundleIdentifier = TunnelProfilePolicy.providerBundleIdentifier
            tunnelProtocol.serverAddress = serverAddress
            tunnelProtocol.providerConfiguration = ["consoleHost": host,
                                                    "configurationSource": configurationSource]
            profile.protocolConfiguration = tunnelProtocol
            profile.localizedDescription = "Wantastic"
            profile.isEnabled = true
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                profile.saveToPreferences { error in
                    if let error { continuation.resume(throwing: error) }
                    else { continuation.resume() }
                }
            }
            manager = profile
            profileReady = true
            setStatus(copyKey: "tunnel_profile_ready")
        } catch {
            profileReady = false
            state = .failed
            setStatus(error: error)
            throw error
        }
    }

    public func connect() async throws {
        guard profileReady, let manager,
              let tunnel = manager.protocolConfiguration as? NETunnelProviderProtocol,
              TunnelProfilePolicy.isWantastic(providerBundleIdentifier: tunnel.providerBundleIdentifier) else {
            throw WantasticError.tunnelUnavailable
        }
        state = .connecting
        do {
            setStatus(copyKey: "requesting_extension_approval")
            let activation = try await SystemExtensionActivator.shared.activate { [weak self] in
                self?.setStatus(copyKey: "approve_extension_in_settings")
            }
            guard activation == .active else {
                setStatus(copyKey: "restart_to_enable_extension")
                throw TunnelControllerError.restartRequired
            }
            setStatus(copyKey: "starting_secure_connection")
            try manager.connection.startVPNTunnel()
            statusPollingTask?.cancel()
            statusPollingTask = Task { [weak self] in
                for _ in 0..<30 {
                    do { try await Task.sleep(for: .seconds(1)) }
                    catch { return }
                    await self?.refresh()
                    guard self?.state == .connecting else { return }
                }
            }
        } catch TunnelControllerError.restartRequired {
            state = .needsApproval
            setStatus(copyKey: TunnelControllerError.restartRequired.statusCopyKey)
            throw TunnelControllerError.restartRequired
        } catch {
            state = .failed
            setStatus(error: error)
            throw error
        }
    }

    private func setStatus(copyKey: String) {
        statusCopyKey = copyKey
        statusMessage = ""
    }

    private func setStatus(error: Error) {
        statusCopyKey = nil
        statusMessage = error.localizedDescription
    }

    public func disconnect() {
        statusPollingTask?.cancel()
        statusPollingTask = nil
        manager?.connection.stopVPNTunnel()
        state = .disconnected
    }

    /// Sends one bounded WUSP request through the connected packet provider.
    /// The provider forwards it over the authenticated tunnel peer and returns
    /// only the matching WUSP response.
    public func sendWUSPRequest(_ request: WUSPRequest,
                                timeout: Duration = .seconds(25)) async throws -> WUSPResponse {
        let envelope = try await sendProviderRequest(
            TunnelProviderRPCRequest(request: request), timeout: timeout)
        if let code = envelope.errorCode { throw TunnelRPCError.provider(code) }
        guard let response = envelope.response else { throw TunnelRPCError.invalidResponse }
        return response
    }

    public func p2pDevices(timeout: Duration = .seconds(15)) async throws -> [P2PPeerRecord] {
        let envelope = try await sendProviderRequest(
            TunnelProviderRPCRequest(operation: .p2pSnapshot), timeout: timeout)
        if let code = envelope.errorCode { throw TunnelRPCError.provider(code) }
        guard let peers = envelope.p2pPeers else { throw TunnelRPCError.invalidResponse }
        return peers
    }

    public func requestDirectConnection(to peerID: UInt32,
                                        timeout: Duration = .seconds(15)) async throws {
        let envelope = try await sendProviderRequest(
            TunnelProviderRPCRequest(operation: .p2pPunch(peerID: peerID)), timeout: timeout)
        if let code = envelope.errorCode { throw TunnelRPCError.provider(code) }
        guard envelope.accepted == true else { throw TunnelRPCError.invalidResponse }
    }

    public func setExitNode(peerID: UInt32?) async throws {
        let envelope = try await sendProviderRequest(
            TunnelProviderRPCRequest(operation: .exitNodeSelection(peerID: peerID)),
            timeout: .seconds(15))
        if let code = envelope.errorCode {
            if code == "peer_not_exit_node" { throw TunnelRPCError.peerDoesNotOfferExitNode }
            throw TunnelRPCError.provider(code)
        }
        guard envelope.accepted == true else { throw TunnelRPCError.invalidResponse }
    }

    public func setLocalAccess(routes: [String]?) async throws {
        let operation: TunnelProviderRPCOperation
        if let routes {
            guard state == .connected, !routes.isEmpty else {
                throw TunnelRPCError.tunnelUnavailable
            }
            let registration = MacLocalAccessHelperRegistration()
            if registration.state == .notRegistered { try registration.register() }
            guard registration.state == .enabled else {
                registration.openApprovalSettings()
                throw TunnelRPCError.localAccessApprovalRequired
            }
            operation = .localAccessEnable(routes: routes)
        } else {
            operation = .localAccessDisable
        }
        let envelope = try await sendProviderRequest(
            TunnelProviderRPCRequest(operation: operation), timeout: .seconds(30))
        if let code = envelope.errorCode {
            switch code {
            case "local_access_unavailable": throw TunnelRPCError.localAccessUnavailable
            case "local_access_failed": throw TunnelRPCError.localAccessFailed
            default: throw TunnelRPCError.provider(code)
            }
        }
        guard envelope.accepted == true else { throw TunnelRPCError.invalidResponse }
    }

    public func localAccessEnabled() async throws -> Bool {
        let envelope = try await sendProviderRequest(
            TunnelProviderRPCRequest(operation: .localAccessStatus), timeout: .seconds(10))
        if let code = envelope.errorCode {
            if code == "local_access_unavailable" { throw TunnelRPCError.localAccessUnavailable }
            throw TunnelRPCError.provider(code)
        }
        guard let enabled = envelope.accepted else { throw TunnelRPCError.invalidResponse }
        return enabled
    }

    private func sendProviderRequest(_ request: TunnelProviderRPCRequest,
                                     timeout: Duration) async throws -> TunnelProviderRPCResponse {
        guard state == .connected,
              let session = manager?.connection as? NETunnelProviderSession else {
            throw TunnelRPCError.tunnelUnavailable
        }
        let message = try TunnelProviderRPCCodec.encode(request)
        let responseData = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data, Error>) in
            let completion = TunnelRPCCompletion(continuation)
            let components = timeout.components
            let seconds = min(max(components.seconds, 0), 60)
            let nanoseconds = Int(min(seconds * 1_000_000_000
                + max(components.attoseconds / 1_000_000_000, 0), 60_000_000_000))
            DispatchQueue.global().asyncAfter(deadline: .now() + .nanoseconds(nanoseconds)) {
                completion.resolve(.failure(TunnelRPCError.timedOut))
            }
            do {
                try session.sendProviderMessage(message) { data in
                    guard let data else {
                        completion.resolve(.failure(TunnelRPCError.emptyResponse))
                        return
                    }
                    completion.resolve(.success(data))
                }
            } catch {
                completion.resolve(.failure(error))
            }
        }
        return try TunnelProviderRPCCodec.decodeResponse(responseData)
    }

    public func removeProfile() async throws {
        statusPollingTask?.cancel()
        statusPollingTask = nil
        let profiles = try await NETunnelProviderManager.loadAllFromPreferences()
        guard let profile = profiles.first(where: { candidate in
            guard let tunnel = candidate.protocolConfiguration as? NETunnelProviderProtocol else { return false }
            return TunnelProfilePolicy.isWantastic(providerBundleIdentifier: tunnel.providerBundleIdentifier)
        }) else {
            manager = nil
            profileReady = false
            state = .disconnected
            return
        }
        profile.connection.stopVPNTunnel()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            profile.removeFromPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
        manager = nil
        profileReady = false
        state = .disconnected
    }
}

public enum TunnelProfileError: Error, Equatable {
    case invalidConfiguration
}

public enum TunnelControllerError: Error, Equatable {
    case restartRequired

    public var statusCopyKey: String {
        switch self {
        case .restartRequired: "restart_to_enable_extension"
        }
    }
}

public enum TunnelRPCError: Error, Equatable {
    case tunnelUnavailable
    case sendFailed
    case timedOut
    case emptyResponse
    case invalidResponse
    case peerDoesNotOfferExitNode
    case localAccessApprovalRequired
    case localAccessUnavailable
    case localAccessFailed
    case provider(String)
}

private final class TunnelRPCCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?

    init(_ continuation: CheckedContinuation<Data, Error>) {
        self.continuation = continuation
    }

    func resolve(_ result: Result<Data, Error>) {
        lock.lock()
        let current = continuation
        continuation = nil
        lock.unlock()
        current?.resume(with: result)
    }
}
