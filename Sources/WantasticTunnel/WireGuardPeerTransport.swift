import Foundation
import WantasticCore

enum WireGuardTimerPolicy {
    static let rekeyAfterSeconds: TimeInterval = 120
    static let rejectAfterSeconds: TimeInterval = 300
    static let directSessionStaleAfterSeconds: TimeInterval = 240
    static let rekeyRetrySeconds: TimeInterval = 2
    static let retryJitterSeconds: TimeInterval = 0.334

    static func retryDelay(jitter: TimeInterval) -> TimeInterval {
        rekeyRetrySeconds + min(max(jitter, 0), retryJitterSeconds)
    }

    static func shouldSendKeepalive(lastActivity: Date, now: Date,
                                    interval: TimeInterval) -> Bool {
        interval > 0 && now.timeIntervalSince(lastActivity) >= interval
    }

    static func keepaliveDelay(lastActivity: Date, now: Date,
                               interval: TimeInterval) -> TimeInterval {
        max(0.2, interval - now.timeIntervalSince(lastActivity))
    }
}

public enum WireGuardPeerTransportError: Error, Equatable {
    case alreadyWaitingForHandshake
    case handshakeTimedOut
    case closed
}

/// Drives one authenticated WireGuard peer session over a connected UDP path.
/// Routing and packet-flow policy deliberately remain outside this type.
public actor WireGuardPeerTransport: WUSPControlChannel, WUSPTransferStreamChannel,
    P2PControlChannel, TunnelControlPayloadSender {
    private static let maximumBufferedEvents = 128
    private let connection: any WireGuardDatagramChannel
    private let localPrivateKey: Data
    private let peerPublicKey: Data
    private let presharedKey: Data
    private let mtu: Int
    private let keepaliveInterval: TimeInterval
    private let rekeyAfterSeconds: TimeInterval
    private let maximumSessionAge: TimeInterval?
    private var session: WireGuardPeerSession
    private var activeSession: WireGuardPeerSession?
    private var previousSession: WireGuardPeerSession?
    private var activeSessionCreatedAt: Date?
    private var previousSessionExpiry: Date?
    private var receiveTask: Task<Void, Never>?
    private var handshakeRetryTask: Task<Void, Never>?
    private var rekeyTask: Task<Void, Never>?
    private var keepaliveTask: Task<Void, Never>?
    private var handshakeTimeoutTask: Task<Void, Never>?
    private var sessionExpiryTask: Task<Void, Never>?
    private var handshakeWaiter: CheckedContinuation<Void, Error>?
    private var continuation: AsyncStream<WireGuardPeerSessionEvent>.Continuation?
    private var wuspContinuation: AsyncStream<Data>.Continuation?
    private var wuspTransferContinuation: AsyncStream<Data>.Continuation?
    private var inboundWUSPRequestHandler: (@Sendable (Data) async -> Data?)?
    private var p2pContinuation: AsyncStream<Data>.Continuation?
    private var inboundWUSPAssembler = WUSPControlFragmentAssembler()
    private var started = false
    private var stopped = false
    private var lastAuthenticatedActivity = Date()
    private var nextWUSPMessageID: UInt64 = 1

    public private(set) var droppedTransferFrameCount = 0

    public let events: AsyncStream<WireGuardPeerSessionEvent>
    public let wuspControlPayloads: AsyncStream<Data>
    public let wuspTransferStreamPayloads: AsyncStream<Data>
    public let p2pControlPayloads: AsyncStream<Data>

    public init(configuration: WireGuardConfiguration) throws {
        let connection = try WireGuardUDPConnection(host: configuration.endpointHost,
                                                    port: configuration.endpointPort)
        try self.init(configuration: configuration, connection: connection,
                      rekeyAfterSeconds: WireGuardTimerPolicy.rekeyAfterSeconds,
                      maximumSessionAge: nil)
    }

    init(configuration: WireGuardConfiguration, rekeyAfterSeconds: TimeInterval,
         maximumSessionAge: TimeInterval? = nil) throws {
        let connection = try WireGuardUDPConnection(host: configuration.endpointHost,
                                                    port: configuration.endpointPort)
        try self.init(configuration: configuration, connection: connection,
                      rekeyAfterSeconds: rekeyAfterSeconds,
                      maximumSessionAge: maximumSessionAge)
    }

    init(configuration: WireGuardConfiguration, connection: any WireGuardDatagramChannel,
         rekeyAfterSeconds: TimeInterval = WireGuardTimerPolicy.rekeyAfterSeconds,
         maximumSessionAge: TimeInterval? = nil) throws {
        guard rekeyAfterSeconds > 0 else { throw WireGuardConfigError.invalidValue }
        guard maximumSessionAge.map({ $0 > 0 }) ?? true else { throw WireGuardConfigError.invalidValue }
        guard let privateKey = Data(base64Encoded: configuration.privateKey),
              let peerKey = Data(base64Encoded: configuration.peerPublicKey) else {
            throw WireGuardConfigError.invalidKey
        }
        let presharedKey: Data
        if let encoded = configuration.peerPresharedKey {
            guard let decoded = Data(base64Encoded: encoded) else { throw WireGuardConfigError.invalidKey }
            presharedKey = decoded
        } else {
            presharedKey = Data(repeating: 0, count: 32)
        }
        guard presharedKey.count == 32 else { throw WireGuardConfigError.invalidKey }
        self.localPrivateKey = privateKey
        self.peerPublicKey = peerKey
        self.presharedKey = presharedKey
        self.mtu = configuration.mtu
        self.keepaliveInterval = TimeInterval(configuration.persistentKeepalive)
        self.rekeyAfterSeconds = rekeyAfterSeconds
        self.maximumSessionAge = maximumSessionAge
        self.session = try Self.makeSession(localPrivateKey: privateKey, peerPublicKey: peerKey,
                                            presharedKey: presharedKey, mtu: configuration.mtu)
        self.connection = connection
        let (stream, continuation) = AsyncStream<WireGuardPeerSessionEvent>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.maximumBufferedEvents))
        self.events = stream
        self.continuation = continuation
        let (wuspStream, wuspContinuation) = AsyncStream<Data>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.maximumBufferedEvents))
        self.wuspControlPayloads = wuspStream
        self.wuspContinuation = wuspContinuation
        let (wuspTransferStream, wuspTransferContinuation) = AsyncStream<Data>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.maximumBufferedEvents))
        self.wuspTransferStreamPayloads = wuspTransferStream
        self.wuspTransferContinuation = wuspTransferContinuation
        let (p2pStream, p2pContinuation) = AsyncStream<Data>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.maximumBufferedEvents))
        self.p2pControlPayloads = p2pStream
        self.p2pContinuation = p2pContinuation
    }

    public func start() async throws {
        guard !started else { return }
        guard !stopped else { throw WireGuardUDPError.closed }
        started = true
        do {
            try await connection.start()
            let initiation = try session.begin(timestamp: Self.tai64nNow())
            try await connection.send(initiation)
            receiveTask = Task { [weak self] in await self?.receiveLoop() }
            handshakeRetryTask = Task { [weak self] in await self?.handshakeRetryLoop() }
        } catch {
            started = false
            stopped = true
            Task { await connection.close() }
            continuation?.finish()
            wuspContinuation?.finish()
            wuspTransferContinuation?.finish()
            p2pContinuation?.finish()
            throw error
        }
    }

    public func sendTransportPacket(_ packet: Data) async throws {
        try await sendAuthenticatedPayload(packet, messageType: .transport)
    }

    public func sendWUSPControlPayload(_ payload: Data) async throws {
        let messageID = nextWUSPMessageID
        nextWUSPMessageID = nextWUSPMessageID == UInt64.max ? 1 : nextWUSPMessageID + 1
        let fragments = try WUSPControlFragmentCodec.fragment(payload, messageID: messageID)
        for fragment in fragments {
            try await sendAuthenticatedPayload(fragment, messageType: .wuspControl)
        }
    }

    /// Sends one Go-compatible transfer frame directly as authenticated
    /// WireGuard type-8 data. Transfer framing already bounds chunks; applying
    /// the control-fragment wrapper here would break Go's stream decoder.
    public func sendWUSPTransferStreamFrame(_ frame: WUSPTransferStreamFrame) async throws {
        let payload = try WUSPTransferStreamCodec.encode(frame)
        guard payload.count <= WUSPControlFragmentCodec.maximumDatagramPayload else {
            throw WUSPControlFragmentError.tooLarge
        }
        try await sendAuthenticatedPayload(payload, messageType: .wuspControl)
    }

    public func setInboundWUSPRequestHandler(
        _ handler: @escaping @Sendable (Data) async -> Data?
    ) {
        inboundWUSPRequestHandler = handler
    }

    /// Sends the deployed Go type-6 datagram directly to the configured
    /// coordinator endpoint. The message payload is intentionally not wrapped
    /// in type-8 WireGuard control encryption; peer punch MACs authenticate
    /// their short-form payloads separately.
    public func sendP2PControlPayload(_ payload: Data) async throws {
        guard started, !stopped else { throw WireGuardPeerTransportError.closed }
        try await connection.send(P2PProtocolCodec.encodeDatagram(payload: payload))
    }

    public func localEndpoint() -> P2PEndpoint? {
        if let connection = connection as? WireGuardUDPConnection {
            return connection.localEndpoint()
        }
        if let connection = connection as? any P2PPunchPath {
            return connection.localEndpoint
        }
        return nil
    }

    public func openP2PPunchPath(to endpoint: P2PEndpoint) async throws -> any P2PPunchPath {
        guard let connection = connection as? WireGuardUDPConnection else {
            throw WireGuardUDPError.notReady
        }
        return try await connection.openP2PPunchPath(to: endpoint)
    }

    public func sendWUSPRequest(_ request: WUSPWireRequest) async throws {
        try await sendWUSPControlPayload(WUSPTransportCodec.encode(request))
    }

    public func sendTUNControlPayload(_ payload: Data) async throws {
        guard payload.count <= WUSPControlFragmentCodec.maximumDatagramPayload else {
            throw WUSPControlFragmentError.tooLarge
        }
        try await sendAuthenticatedPayload(payload, messageType: .tunnelControl)
    }

    private func sendAuthenticatedPayload(_ payload: Data,
                                          messageType: WireGuardEncryptedMessageType) async throws {
        guard var activeSession, let activeSessionCreatedAt else {
            throw WireGuardPeerSessionError.invalidState
        }
        guard Date().timeIntervalSince(activeSessionCreatedAt) < WireGuardTimerPolicy.rejectAfterSeconds else {
            stop()
            throw WireGuardPeerTransportError.closed
        }
        let datagram = try activeSession.encrypt(payload, messageType: messageType)
        self.activeSession = activeSession
        try await connection.send(datagram)
        lastAuthenticatedActivity = Date()
    }

    public func waitUntilEstablished(timeout: Duration = .seconds(30)) async throws {
        if activeSession != nil { return }
        guard started, !stopped else { throw WireGuardPeerTransportError.closed }
        guard handshakeWaiter == nil else {
            throw WireGuardPeerTransportError.alreadyWaitingForHandshake
        }
        try await withCheckedThrowingContinuation { continuation in
            handshakeWaiter = continuation
            handshakeTimeoutTask = Task { [weak self] in
                do { try await Task.sleep(for: timeout) }
                catch { return }
                await self?.timeoutHandshake()
            }
        }
    }

    public func stop() {
        receiveTask?.cancel()
        receiveTask = nil
        handshakeRetryTask?.cancel()
        handshakeRetryTask = nil
        rekeyTask?.cancel()
        rekeyTask = nil
        keepaliveTask?.cancel()
        keepaliveTask = nil
        handshakeTimeoutTask?.cancel()
        handshakeTimeoutTask = nil
        sessionExpiryTask?.cancel()
        sessionExpiryTask = nil
        finishHandshakeWaiter(throwing: WireGuardPeerTransportError.closed)
        activeSession = nil
        previousSession = nil
        activeSessionCreatedAt = nil
        previousSessionExpiry = nil
        Task { await connection.close() }
        continuation?.finish()
        continuation = nil
        wuspContinuation?.finish()
        wuspContinuation = nil
        wuspTransferContinuation?.finish()
        wuspTransferContinuation = nil
        p2pContinuation?.finish()
        p2pContinuation = nil
        started = false
        stopped = true
    }

    private func receiveLoop() async {
        while !Task.isCancelled {
            let datagram: Data
            do {
                datagram = try await connection.receive()
            } catch {
                stop()
                return
            }

            do {
                if let p2pPayload = try? P2PProtocolCodec.decodeDatagram(datagram) {
                    p2pContinuation?.yield(p2pPayload)
                    continue
                }
                let event = try receive(datagram)
                switch event {
                case let .retransmitHandshake(packet):
                    try await connection.send(packet)
                case .established:
                    previousSession = activeSession
                    previousSessionExpiry = activeSessionCreatedAt.map {
                        $0.addingTimeInterval(WireGuardTimerPolicy.rejectAfterSeconds)
                    }
                    activeSession = session
                    let sessionCreatedAt = Date()
                    activeSessionCreatedAt = sessionCreatedAt
                    scheduleSessionExpiry(at: sessionCreatedAt)
                    lastAuthenticatedActivity = Date()
                    handshakeRetryTask?.cancel()
                    handshakeRetryTask = nil
                    finishHandshakeWaiter()
                    if rekeyTask == nil {
                        rekeyTask = Task { [weak self] in await self?.rekeyLoop() }
                    }
                    if keepaliveInterval > 0, keepaliveTask == nil {
                        keepaliveTask = Task { [weak self] in await self?.keepaliveLoop() }
                    }
                case let .received(messageType, _, plaintext):
                    lastAuthenticatedActivity = Date()
                    if messageType == .wuspControl,
                       let payload = try inboundWUSPAssembler.consume(plaintext) {
                        continuation?.yield(.wuspControlPayload(payload))
                        if Self.isTransferStreamFrame(payload) {
                            guard (try? WUSPTransferStreamCodec.decode(payload)) != nil else { continue }
                            if case .dropped? = wuspTransferContinuation?.yield(payload) {
                                droppedTransferFrameCount += 1
                            }
                            continue
                        }
                        if inboundWUSPRequestHandler != nil,
                           (try? WUSPTransportCodec.decodeRequest(payload)) != nil {
                            if let response = await inboundWUSPRequestHandler?(payload) {
                                try await sendWUSPControlPayload(response)
                            }
                        } else {
                            wuspContinuation?.yield(payload)
                        }
                    }
                case .wuspControlPayload:
                    break
                }
                continuation?.yield(event)
            } catch WireGuardPeerTransportError.closed {
                stop()
                return
            } catch {
                // Unauthenticated or malformed UDP input is discarded. It
                // must not be able to tear down an otherwise healthy peer.
                continue
            }
        }
    }

    private static func isTransferStreamFrame(_ payload: Data) -> Bool {
        payload.count >= 2 && payload[payload.startIndex] == 0x53 &&
            payload[payload.index(after: payload.startIndex)] == 1
    }

    private func timeoutHandshake() {
        guard activeSession == nil else { return }
        finishHandshakeWaiter(throwing: WireGuardPeerTransportError.handshakeTimedOut)
        stop()
    }

    private func scheduleSessionExpiry(at createdAt: Date) {
        sessionExpiryTask?.cancel()
        guard let maximumSessionAge else { return }
        sessionExpiryTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(maximumSessionAge)) }
            catch { return }
            await self?.expireSession(createdAt: createdAt)
        }
    }

    private func expireSession(createdAt: Date) {
        guard activeSessionCreatedAt == createdAt else { return }
        stop()
    }

    private func finishHandshakeWaiter(throwing error: Error? = nil) {
        handshakeTimeoutTask?.cancel()
        handshakeTimeoutTask = nil
        let waiter = handshakeWaiter
        handshakeWaiter = nil
        if let error { waiter?.resume(throwing: error) }
        else { waiter?.resume() }
    }

    /// Retransmits a fresh initiation on the same cadence as the bundled Go
    /// implementation. A cookie retry still uses the same in-flight Noise
    /// transcript; a timeout starts a new transcript and sender index.
    private func handshakeRetryLoop() async {
        while !Task.isCancelled, !stopped, !session.isEstablished {
            let jitter = Double.random(in: 0...WireGuardTimerPolicy.retryJitterSeconds)
            do { try await Task.sleep(for: .seconds(WireGuardTimerPolicy.retryDelay(jitter: jitter))) }
            catch { return }
            guard !Task.isCancelled, !stopped, !session.isEstablished else { return }
            do {
                session = try Self.makeSession(localPrivateKey: localPrivateKey,
                                               peerPublicKey: peerPublicKey,
                                               presharedKey: presharedKey,
                                               mtu: mtu)
                let initiation = try session.begin(timestamp: Self.tai64nNow())
                try await connection.send(initiation)
            } catch {
                stop()
                return
            }
        }
    }

    private func rekeyLoop() async {
        while !Task.isCancelled, !stopped {
            do { try await Task.sleep(for: .seconds(rekeyAfterSeconds)) }
            catch { return }
            guard !Task.isCancelled, !stopped, activeSession != nil else { return }
            do {
                session = try Self.makeSession(localPrivateKey: localPrivateKey,
                                               peerPublicKey: peerPublicKey,
                                               presharedKey: presharedKey,
                                               mtu: mtu)
                let initiation = try session.begin(timestamp: Self.tai64nNow())
                try await connection.send(initiation)
                let retryTask = Task { [weak self] in
                    guard let self else { return }
                    await self.handshakeRetryLoop()
                }
                handshakeRetryTask = retryTask
                await retryTask.value
            } catch {
                stop()
                return
            }
        }
    }

    /// Sends an empty authenticated transport packet only after the configured
    /// keepalive interval elapses without any authenticated traffic.
    private func keepaliveLoop() async {
        while !Task.isCancelled, !stopped, activeSession != nil {
            let now = Date()
            let remaining = WireGuardTimerPolicy.keepaliveDelay(lastActivity: lastAuthenticatedActivity,
                                                                now: now,
                                                                interval: keepaliveInterval)
            do { try await Task.sleep(for: .seconds(max(0.2, remaining))) }
            catch { return }
            guard !Task.isCancelled, !stopped, activeSession != nil else { return }
            guard WireGuardTimerPolicy.shouldSendKeepalive(lastActivity: lastAuthenticatedActivity,
                                                           now: Date(),
                                                           interval: keepaliveInterval) else { continue }
            do {
                guard var activeSession else { return }
                let datagram = try activeSession.encrypt(Data())
                self.activeSession = activeSession
                try await connection.send(datagram)
                lastAuthenticatedActivity = Date()
            } catch {
                stop()
                return
            }
        }
    }

    private func receive(_ datagram: Data) throws -> WireGuardPeerSessionEvent {
        if datagram.first == 2 || datagram.first == 3 {
            return try session.receive(datagram)
        }
        if let created = activeSessionCreatedAt,
           Date().timeIntervalSince(created) >= WireGuardTimerPolicy.rejectAfterSeconds {
            throw WireGuardPeerTransportError.closed
        }
        if var activeSession {
            do {
                let event = try activeSession.receive(datagram)
                self.activeSession = activeSession
                return event
            } catch {
                if let previousSessionExpiry, Date() >= previousSessionExpiry {
                    previousSession = nil
                    self.previousSessionExpiry = nil
                }
                guard var previousSession else { throw error }
                let event = try previousSession.receive(datagram)
                self.previousSession = previousSession
                return event
            }
        }
        return try session.receive(datagram)
    }

    private static func makeSession(localPrivateKey: Data, peerPublicKey: Data,
                                    presharedKey: Data, mtu: Int) throws -> WireGuardPeerSession {
        try WireGuardPeerSession(localPrivateKey: localPrivateKey,
                                 peerStaticPublicKey: peerPublicKey,
                                 presharedKey: presharedKey,
                                 localSenderIndex: senderIndex(), mtu: mtu)
    }

    private static func senderIndex() -> UInt32 {
        var index: UInt32 = 0
        while index == 0 { index = UInt32.random(in: 1...UInt32.max) }
        return index
    }

    private static func tai64nNow() -> Data {
        let now = Date().timeIntervalSince1970
        let seconds = UInt64(now.rounded(.down)) &+ 0x4000_0000_0000_000a
        let nanos = UInt32((now - floor(now)) * 1_000_000_000)
        var data = Data()
        data.append(contentsOf: withUnsafeBytes(of: seconds.bigEndian, Array.init))
        data.append(contentsOf: withUnsafeBytes(of: nanos.bigEndian, Array.init))
        return data
    }
}
