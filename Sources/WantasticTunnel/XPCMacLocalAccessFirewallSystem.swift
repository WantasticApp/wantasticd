import Foundation
import WantasticCore

/// Calls the authorized LaunchDaemon through a code-signature-constrained
/// privileged Mach service. No fallback executes local commands in the app or
/// Network Extension process.
public final class XPCMacLocalAccessFirewallSystem: MacLocalAccessFirewallSystem, @unchecked Sendable {
    private static let maximumPlanBytes = 64 * 1024
    private static let requestTimeout: DispatchTimeInterval = .seconds(10)
    private let machServiceName: String

    public init(machServiceName: String = MacLocalAccessHelperService.machServiceName) {
        self.machServiceName = machServiceName
    }

    public func ipv4ForwardingEnabled() async throws -> Bool {
        try await call { remote, reply in
            remote.readIPv4Forwarding { value, error in
                if let error { reply(.failure(error)) }
                else if let value { reply(.success(value.boolValue)) }
                else { reply(.failure(Self.invalidReply("missing forwarding state"))) }
            }
        }
    }

    public func setIPv4Forwarding(_ enabled: Bool) async throws {
        try await callVoid { remote, reply in
            remote.writeIPv4Forwarding(enabled) { error in
                if let error { reply(.failure(error)) } else { reply(.success(())) }
            }
        }
    }

    public func packetFilterEnabled() async throws -> Bool {
        try await call { remote, reply in
            remote.readPacketFilterEnabled { value, error in
                if let error { reply(.failure(error)) }
                else if let value { reply(.success(value.boolValue)) }
                else { reply(.failure(Self.invalidReply("missing packet-filter state"))) }
            }
        }
    }

    public func enablePacketFilter() async throws -> String {
        try await call { remote, reply in
            remote.enablePacketFilter { token, error in
                if let error { reply(.failure(error)) }
                else if let token, !(token as String).isEmpty { reply(.success(token as String)) }
                else { reply(.failure(Self.invalidReply("missing packet-filter token"))) }
            }
        }
    }

    public func apply(_ plan: MacLocalAccessFirewallPlan) async throws {
        let request = try JSONEncoder().encode(MacLocalAccessFirewallPlanRequest(plan: plan))
        guard request.count <= Self.maximumPlanBytes else {
            throw Self.invalidReply("firewall plan exceeds the service limit")
        }
        try await callVoid { remote, reply in
            remote.applyFirewallPlan(request as NSData) { error in
                if let error { reply(.failure(error)) } else { reply(.success(())) }
            }
        }
    }

    public func flushOwnedAnchor() async throws {
        try await callVoid { remote, reply in
            remote.flushWantasticAnchor { error in
                if let error { reply(.failure(error)) } else { reply(.success(())) }
            }
        }
    }

    public func releasePacketFilter(token: String) async throws {
        guard !token.isEmpty, token.utf8.count <= 128,
              token.utf8.allSatisfy({ (48...57).contains($0) }) else {
            throw Self.invalidReply("invalid packet-filter token")
        }
        try await callVoid { remote, reply in
            remote.releasePacketFilterToken(token as NSString) { error in
                if let error { reply(.failure(error)) } else { reply(.success(())) }
            }
        }
    }

    public func restoreWantasticOwnedState() async throws {
        try await callVoid { remote, reply in
            remote.restoreWantasticOwnedState { error in
                if let error { reply(.failure(error)) } else { reply(.success(())) }
            }
        }
    }

    public func scheduleSystemReboot() async throws {
        try await callVoid { remote, reply in
            remote.scheduleSystemReboot { error in
                if let error { reply(.failure(error)) } else { reply(.success(())) }
            }
        }
    }

    private func call<Value: Sendable>(
        _ invoke: @escaping @Sendable (
            MacLocalAccessHelperXPCProtocol,
            @escaping @Sendable (Result<Value, Error>) -> Void
        ) -> Void
    ) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            let gate = XPCReplyGate(continuation)
            let connection = XPCConnectionHandle(NSXPCConnection(
                machServiceName: machServiceName,
                options: .privileged))
            connection.value.remoteObjectInterface = NSXPCInterface(
                with: MacLocalAccessHelperXPCProtocol.self)
            do {
                connection.value.setCodeSigningRequirement(try CodeSignatureRequirement.pinnedPeer(
                    identifier: MacLocalAccessHelperService.helperBundleIdentifier))
            } catch {
                gate.finish(.failure(error))
                connection.value.invalidate()
                return
            }
            connection.value.interruptionHandler = {
                gate.finish(.failure(Self.serviceUnavailable("connection interrupted")))
            }
            connection.value.invalidationHandler = {
                gate.finish(.failure(Self.serviceUnavailable("connection invalidated")))
            }
            connection.value.resume()
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + Self.requestTimeout) {
                gate.finish(.failure(Self.serviceUnavailable("helper request timed out")))
                connection.value.invalidate()
            }
            let object = connection.value.remoteObjectProxyWithErrorHandler { error in
                gate.finish(.failure(error))
                connection.value.invalidate()
            }
            guard let remote = object as? MacLocalAccessHelperXPCProtocol else {
                gate.finish(.failure(Self.serviceUnavailable("invalid helper interface")))
                connection.value.invalidate()
                return
            }
            invoke(remote) { result in
                gate.finish(result)
                connection.value.invalidate()
            }
        }
    }

    private func callVoid(
        _ invoke: @escaping @Sendable (
            MacLocalAccessHelperXPCProtocol,
            @escaping @Sendable (Result<Void, Error>) -> Void
        ) -> Void
    ) async throws {
        try await call(invoke)
    }

    private static func serviceUnavailable(_ message: String) -> NSError {
        NSError(domain: "app.wantastic.local-access-helper", code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
    }

    private static func invalidReply(_ message: String) -> NSError {
        NSError(domain: "app.wantastic.local-access-helper", code: 2,
                userInfo: [NSLocalizedDescriptionKey: message])
    }
}

private final class XPCConnectionHandle: @unchecked Sendable {
    let value: NSXPCConnection

    init(_ value: NSXPCConnection) { self.value = value }
}

private final class XPCReplyGate<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?

    init(_ continuation: CheckedContinuation<Value, Error>) {
        self.continuation = continuation
    }

    func finish(_ result: Result<Value, Error>) {
        let continuation = lock.withLock { () -> CheckedContinuation<Value, Error>? in
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume(with: result)
    }
}
