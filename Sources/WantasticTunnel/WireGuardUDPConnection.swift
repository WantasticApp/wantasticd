import Foundation
import Network
import WantasticCore

public enum WireGuardUDPError: Error, Equatable {
    case invalidEndpoint
    case notReady
    case closed
    case emptyDatagram
    case oversizedDatagram
}

/// One connected UDP path for a WireGuard peer. A serial callback queue keeps
/// Network.framework callbacks ordered; packet/session mutation stays with the
/// caller, which must serialize `receive` and `send` operations.
public final class WireGuardUDPConnection: WireGuardDatagramChannel, @unchecked Sendable {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var ready = false
    private var closed = false
    private var started = false

    public init(host: String, port: UInt16) throws {
        guard !host.isEmpty, port > 0,
              let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw WireGuardUDPError.invalidEndpoint
        }
        connection = NWConnection(to: .hostPort(host: NWEndpoint.Host(host), port: nwPort), using: .udp)
        queue = DispatchQueue(label: "app.wantastic.wireguard.udp.\(UUID().uuidString)")
    }

    public func start(timeout: TimeInterval) async throws {
        if isReady() { return }
        guard beginStart() else { throw WireGuardUDPError.closed }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let gate = ContinuationGate<Void>(continuation)
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.markReady()
                    gate.resolve(.success(()))
                case let .failed(error): gate.resolve(.failure(error))
                case .cancelled: gate.resolve(.failure(WireGuardUDPError.closed))
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + max(0.1, timeout)) { [weak self] in
                if gate.resolve(.failure(URLError(.timedOut))) {
                    self?.cancel()
                }
            }
        }
    }

    public func start() async throws { try await start(timeout: 10) }

    public func send(_ datagram: Data) async throws {
        guard !datagram.isEmpty else { throw WireGuardUDPError.emptyDatagram }
        guard datagram.count <= 65_535 else { throw WireGuardUDPError.oversizedDatagram }
        guard isReady() else { throw WireGuardUDPError.notReady }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: datagram, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            })
        }
    }

    public func receive() async throws -> Data {
        guard isReady() else { throw WireGuardUDPError.notReady }

        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            connection.receiveMessage { content, _, _, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let content, !content.isEmpty {
                    guard content.count <= 65_535 else {
                        continuation.resume(throwing: WireGuardUDPError.oversizedDatagram)
                        return
                    }
                    continuation.resume(returning: content)
                } else {
                    continuation.resume(throwing: WireGuardUDPError.emptyDatagram)
                }
            }
        }
    }

    public func localEndpoint() -> P2PEndpoint? {
        guard isReady(), let path = connection.currentPath,
              case let .hostPort(host, port) = path.localEndpoint,
              port.rawValue > 0 else { return nil }
        let rawPort = port.rawValue
        let address: Data
        switch host {
        case let .ipv4(value): address = value.rawValue
        case let .ipv6(value): address = value.rawValue
        case .name: return nil
        @unknown default: return nil
        }
        guard !address.isEmpty, rawPort > 0 else { return nil }
        return P2PEndpoint(address: address, port: rawPort)
    }

    /// Opens a second UDP flow to a peer while explicitly reusing the local
    /// endpoint bound by the authenticated coordinator flow. This is required
    /// for NAT hole punching: a new ephemeral source port would create a
    /// different mapping and make the advertised candidate unusable.
    public func openP2PPunchPath(to endpoint: P2PEndpoint,
                                 timeout: TimeInterval = 10) async throws -> WireGuardP2PPunchPath {
        guard isReady(), let path = connection.currentPath,
              case let .hostPort(localHost, localPort)? = path.localEndpoint,
              localPort.rawValue > 0, endpoint.port > 0 else {
            throw WireGuardUDPError.notReady
        }
        let remoteHost: NWEndpoint.Host
        if let ipv4 = IPv4Address(endpoint.address) {
            remoteHost = .ipv4(ipv4)
        } else if let ipv6 = IPv6Address(endpoint.address) {
            remoteHost = .ipv6(ipv6)
        } else {
            throw WireGuardUDPError.invalidEndpoint
        }
        guard let remotePort = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw WireGuardUDPError.invalidEndpoint
        }
        let parameters = NWParameters.udp
        parameters.requiredLocalEndpoint = .hostPort(host: localHost, port: localPort)
        parameters.allowLocalEndpointReuse = true
        parameters.includePeerToPeer = true
        let direct = NWConnection(to: .hostPort(host: remoteHost, port: remotePort), using: parameters)
        let boundAddress = localAddress(localHost)
        guard boundAddress.count == 4 || boundAddress.count == 16 else {
            direct.cancel()
            throw WireGuardUDPError.invalidEndpoint
        }
        let punchPath = WireGuardP2PPunchPath(connection: direct, queue: queue,
                                              localEndpoint: P2PEndpoint(address: boundAddress,
                                                                         port: localPort.rawValue))
        try await punchPath.start(timeout: timeout)
        return punchPath
    }

    private func localAddress(_ host: NWEndpoint.Host) -> Data {
        switch host {
        case let .ipv4(address): return address.rawValue
        case let .ipv6(address): return address.rawValue
        case .name: return Data()
        @unknown default: return Data()
        }
    }

    public func cancel() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        lock.unlock()
        connection.stateUpdateHandler = nil
        connection.cancel()
    }

    public func close() async { cancel() }

    private func beginStart() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !closed, !ready, !started else { return false }
        started = true
        return true
    }

    private func markReady() {
        lock.lock()
        ready = true
        lock.unlock()
    }

    private func isReady() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return ready && !closed
    }
}

/// A peer-specific UDP flow pinned to the coordinator flow's bound local port.
/// The caller owns its lifecycle and should close it when punching times out.
public actor WireGuardP2PPunchPath: P2PPunchPath {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private var started = false
    private var closed = false
    public nonisolated let localEndpoint: P2PEndpoint

    fileprivate init(connection: NWConnection, queue: DispatchQueue,
                     localEndpoint: P2PEndpoint) {
        self.connection = connection
        self.queue = queue
        self.localEndpoint = localEndpoint
    }

    public func start(timeout: TimeInterval) async throws {
        if started, !closed { return }
        guard !closed else { throw WireGuardUDPError.closed }
        started = true
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let gate = ContinuationGate<Void>(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: gate.resolve(.success(()))
                case let .failed(error): gate.resolve(.failure(error))
                case .cancelled: gate.resolve(.failure(WireGuardUDPError.closed))
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + max(0.1, timeout)) { [weak self] in
                if gate.resolve(.failure(URLError(.timedOut))) {
                    Task { await self?.cancel() }
                }
            }
        }
        guard let path = connection.currentPath,
              case let .hostPort(_, boundPort) = path.localEndpoint,
              boundPort.rawValue == localEndpoint.port else {
            cancel()
            throw WireGuardUDPError.invalidEndpoint
        }
    }

    public func start() async throws { try await start(timeout: 10) }

    public func send(_ datagram: Data) async throws {
        guard started, !closed else { throw WireGuardUDPError.notReady }
        guard !datagram.isEmpty else { throw WireGuardUDPError.emptyDatagram }
        guard datagram.count <= 65_535 else { throw WireGuardUDPError.oversizedDatagram }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: datagram, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            })
        }
    }

    public func receive() async throws -> Data {
        guard started, !closed else { throw WireGuardUDPError.notReady }
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            connection.receiveMessage { content, _, _, error in
                if let error { continuation.resume(throwing: error) }
                else if let content, !content.isEmpty, content.count <= 65_535 {
                    continuation.resume(returning: content)
                }
                else if let content, content.count > 65_535 {
                    continuation.resume(throwing: WireGuardUDPError.oversizedDatagram)
                }
                else { continuation.resume(throwing: WireGuardUDPError.emptyDatagram) }
            }
        }
    }

    public func close() async { cancel() }

    public func cancel() {
        guard !closed else { return }
        closed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
    }
}

private final class ContinuationGate<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?

    init(_ continuation: CheckedContinuation<Value, Error>) {
        self.continuation = continuation
    }

    @discardableResult
    func resolve(_ result: Result<Value, Error>) -> Bool {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(with: result)
        return continuation != nil
    }
}
