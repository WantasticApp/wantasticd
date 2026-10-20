import Foundation

public struct P2PCoordinatorSnapshot: Equatable, Sendable {
    public let assignedID: UInt32
    public let observedEndpoint: P2PEndpoint?
    public let peers: [P2PPeerRecord]
    public let authenticatedReachablePeerIDs: Set<UInt32>
    public let directPeerIDs: Set<UInt32>

    public init(assignedID: UInt32 = 0, observedEndpoint: P2PEndpoint? = nil,
                peers: [P2PPeerRecord] = [], authenticatedReachablePeerIDs: Set<UInt32> = [],
                directPeerIDs: Set<UInt32> = []) {
        self.assignedID = assignedID
        self.observedEndpoint = observedEndpoint
        self.peers = peers
        self.authenticatedReachablePeerIDs = authenticatedReachablePeerIDs
        self.directPeerIDs = directPeerIDs
    }
}

/// An authenticated UDP path retained for a fresh WireGuard handshake. The
/// receiver owns the channel and must close it if promotion is rejected.
public struct P2PAuthenticatedPathCandidate: Sendable {
    public let peer: P2PPeerRecord
    public let endpoint: P2PEndpoint
    public let channel: any P2PPunchPath

    public init(peer: P2PPeerRecord, endpoint: P2PEndpoint, channel: any P2PPunchPath) {
        self.peer = peer
        self.endpoint = endpoint
        self.channel = channel
    }
}

public enum P2PCoordinatorError: Error, Equatable {
    case invalidKey
    case invalidLocalEndpoint
    case notRunning
    case peerUnavailable
}

/// Implements Go-compatible P2P registration, peer-list refresh, and
/// authenticated shared-port UDP punching. A successful punch reports direct
/// UDP reachability only; the WireGuard data path must still be promoted.
public actor P2PCoordinator {
    private struct AuthenticatedReachability {
        let publicKey: Data
        let verifiedAt: Date
    }

    private static let reachabilityTTL: TimeInterval = 30
    private let channel: any P2PControlChannel
    private let localKey: WireGuardKeyAgreement
    private let publicKey: Data
    private let serverPublicKey: Data?
    private let localEndpoint: P2PEndpoint
    private let candidates: [P2PEndpoint]
    private var receiveTask: Task<Void, Never>?
    private var refreshTask: Task<Void, Never>?
    private var punchTasks: [UInt32: Task<Void, Never>] = [:]
    private var punchTokens: [UInt32: UUID] = [:]
    private var authenticatedReachability: [UInt32: AuthenticatedReachability] = [:]
    private var isRunning = false
    private var current = P2PCoordinatorSnapshot()
    private let updateContinuation: AsyncStream<P2PCoordinatorSnapshot>.Continuation
    private let pathCandidateContinuation: AsyncStream<P2PAuthenticatedPathCandidate>.Continuation

    public let updates: AsyncStream<P2PCoordinatorSnapshot>
    public let authenticatedPathCandidates: AsyncStream<P2PAuthenticatedPathCandidate>

    public init(channel: any P2PControlChannel, privateKey: Data,
                publicKey: Data, serverPublicKey: Data? = nil,
                localEndpoint: P2PEndpoint, candidates: [P2PEndpoint] = []) throws {
        guard publicKey.count == 32, serverPublicKey == nil || serverPublicKey?.count == 32 else {
            throw P2PCoordinatorError.invalidKey
        }
        guard let localKey = try? WireGuardKeyAgreement(privateKey: privateKey),
              localKey.publicKey == publicKey else { throw P2PCoordinatorError.invalidKey }
        guard localEndpoint.port > 0, Self.ipv6Address(localEndpoint.address) != nil else {
            throw P2PCoordinatorError.invalidLocalEndpoint
        }
        self.channel = channel
        self.localKey = localKey
        self.publicKey = publicKey
        self.serverPublicKey = serverPublicKey
        self.localEndpoint = localEndpoint
        self.candidates = candidates.filter { $0.port > 0 && Self.ipv6Address($0.address) != nil }
        let (stream, continuation) = AsyncStream<P2PCoordinatorSnapshot>.makeStream()
        updates = stream
        updateContinuation = continuation
        let (candidateStream, candidateContinuation) =
            AsyncStream<P2PAuthenticatedPathCandidate>.makeStream()
        authenticatedPathCandidates = candidateStream
        pathCandidateContinuation = candidateContinuation
    }

    public var snapshot: P2PCoordinatorSnapshot { current }

    public func start() async throws {
        guard !isRunning else { return }
        isRunning = true
        let payloads = channel.p2pControlPayloads
        receiveTask = Task { [weak self] in
            for await payload in payloads {
                guard !Task.isCancelled else { return }
                await self?.receive(payload)
            }
        }
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(5)) }
                catch { return }
                await self?.refresh()
            }
        }
        do { try await register() }
        catch {
            close()
            throw error
        }
    }

    public func close() {
        guard isRunning else { return }
        isRunning = false
        receiveTask?.cancel()
        refreshTask?.cancel()
        punchTasks.values.forEach { $0.cancel() }
        punchTasks.removeAll()
        receiveTask = nil
        refreshTask = nil
        updateContinuation.finish()
        pathCandidateContinuation.finish()
    }

    public func requestDirectConnection(to peerID: UInt32) async throws {
        guard isRunning else { throw P2PCoordinatorError.notRunning }
        guard let peer = current.peers.first(where: { $0.id == peerID }), peer.p2pCapable,
              peer.assignedIPv4 != nil, peer.publicKey != serverPublicKey else {
            throw P2PCoordinatorError.peerUnavailable
        }
        let message = try P2PMessage(subtype: P2PMessageSubtype.punchRequest,
                                     publicKey: publicKey, targetID: peerID)
        try await channel.sendP2PControlPayload(P2PProtocolCodec.encode(message))
    }

    public func markDirectSession(_ peerID: UInt32, established: Bool) {
        guard current.peers.contains(where: { $0.id == peerID }) else { return }
        var directIDs = current.directPeerIDs
        if established { directIDs.insert(peerID) }
        else { directIDs.remove(peerID) }
        current = P2PCoordinatorSnapshot(assignedID: current.assignedID,
                                         observedEndpoint: current.observedEndpoint,
                                         peers: current.peers,
                                         authenticatedReachablePeerIDs: current.authenticatedReachablePeerIDs,
                                         directPeerIDs: directIDs)
        updateContinuation.yield(current)
    }

    private func register() async throws {
        let endpointAddress = Self.ipv6Address(localEndpoint.address)!
        let message = try P2PMessage(subtype: P2PMessageSubtype.register,
                                     publicKey: publicKey,
                                     localAddress: endpointAddress,
                                     localPort: localEndpoint.port,
                                     payload: P2PProtocolCodec.encodeCandidates(candidates))
        try await channel.sendP2PControlPayload(P2PProtocolCodec.encode(message))
    }

    private func refresh() async {
        guard isRunning else { return }
        if current.assignedID == 0 {
            try? await register()
        } else {
            let request = try? P2PMessage(subtype: P2PMessageSubtype.peerList,
                                          publicKey: publicKey)
            if let request, let encoded = try? P2PProtocolCodec.encode(request) {
                try? await channel.sendP2PControlPayload(encoded)
            }
        }
    }

    private func receive(_ payload: Data) async {
        guard isRunning,
              let message = try? P2PProtocolCodec.decodeMessage(payload) else { return }
        switch message.subtype {
        case P2PMessageSubtype.registerAck:
            guard message.targetID > 0 else { return }
            let observed = Self.endpoint(address: message.observedAddress, port: message.observedPort)
            current = P2PCoordinatorSnapshot(assignedID: message.targetID,
                                             observedEndpoint: observed,
                                             peers: current.peers,
                                             authenticatedReachablePeerIDs: current.authenticatedReachablePeerIDs,
                                             directPeerIDs: current.directPeerIDs)
            updateContinuation.yield(current)
            let request = try? P2PMessage(subtype: P2PMessageSubtype.peerList,
                                          publicKey: publicKey)
            if let request, let encoded = try? P2PProtocolCodec.encode(request) {
                try? await channel.sendP2PControlPayload(encoded)
            }
        case P2PMessageSubtype.peerList:
            guard let records = try? P2PPeerDirectoryCodec.decode(message.payload) else { return }
            let peers = records.filter { record in
                record.publicKey != publicKey && record.publicKey != serverPublicKey
            }
            let peerKeys = Dictionary(uniqueKeysWithValues: peers.map { ($0.id, $0.publicKey) })
            let freshnessCutoff = Date().addingTimeInterval(-Self.reachabilityTTL)
            authenticatedReachability = authenticatedReachability.filter { id, reachability in
                peerKeys[id] == reachability.publicKey && reachability.verifiedAt >= freshnessCutoff
            }
            current = P2PCoordinatorSnapshot(assignedID: current.assignedID,
                                             observedEndpoint: current.observedEndpoint,
                                             peers: peers,
                                             authenticatedReachablePeerIDs: Set(authenticatedReachability.keys),
                                             directPeerIDs: current.directPeerIDs.intersection(Set(peerKeys.keys)))
            updateContinuation.yield(current)
        case P2PMessageSubtype.punchRelay:
            guard let peer = current.peers.first(where: { $0.id == message.targetID }),
                  peer.p2pCapable, peer.publicKey == message.publicKey,
                  peer.publicKey != publicKey, peer.publicKey != serverPublicKey,
                  message.payload.count >= 4 else { return }
            punchTasks[peer.id]?.cancel()
            let token = UUID()
            punchTokens[peer.id] = token
            punchTasks[peer.id] = Task { [weak self] in
                await self?.performPunch(message, peer: peer, token: token)
            }
        default:
            break
        }
    }

    private func performPunch(_ relay: P2PMessage, peer: P2PPeerRecord, token: UUID) async {
        defer {
            if punchTokens[peer.id] == token {
                punchTasks[peer.id] = nil
                punchTokens[peer.id] = nil
            }
        }
        guard isRunning, let assigned = Self.ipv4Bytes(peer.assignedIPv4),
              relay.payload.prefix(4) == assigned,
              let sharedSecret = try? localKey.sharedSecret(with: peer.publicKey),
              let packet = try? P2PPunchCodec.encode(nonce: relay.nonce,
                                                     sharedSecret: sharedSecret),
              let outerPacket = try? P2PPunchCodec.encodeOuter(packet) else { return }
        let candidates = P2PProtocolCodec.decodeCandidates(relay.payload, offset: 4)
        let observed = Self.endpoint(address: relay.observedAddress, port: relay.observedPort)
        let local = Self.endpoint(address: relay.localAddress, port: relay.localPort)
        let targets = P2PPunchCodec.buildTargets(candidates: candidates,
                                                 observed: observed, local: local,
                                                 assignedOverlayAddress: assigned)
        guard !targets.isEmpty else { return }

        let paths = await withTaskGroup(of: (P2PEndpoint, (any P2PPunchPath)?).self) { group in
            for target in targets {
                group.addTask { [channel] in
                    (target, try? await channel.openP2PPunchPath(to: target))
                }
            }
            var opened: [(P2PEndpoint, any P2PPunchPath)] = []
            for await (target, path) in group {
                if let path { opened.append((target, path)) }
            }
            return opened
        }
        guard !paths.isEmpty, !Task.isCancelled, isRunning else {
            for (_, path) in paths { await path.close() }
            return
        }

        let latch = PunchReachabilityLatch()
        let readers = paths.map { target, path in
            Task {
                while !Task.isCancelled {
                    guard let datagram = try? await path.receive(),
                          let payload = try? P2PProtocolCodec.decodeDatagram(datagram) else { return }
                    guard P2PPunchCodec.verify(payload, nonce: relay.nonce,
                                               sharedSecret: sharedSecret) else { continue }
                    try? await path.send(outerPacket)
                    await latch.resolve(target, path: path)
                    return
                }
            }
        }

        for _ in 0..<32 where !Task.isCancelled {
            if await latch.candidate != nil { break }
            for (_, path) in paths {
                guard !Task.isCancelled else { break }
                try? await path.send(outerPacket)
            }
            do { try await Task.sleep(for: .milliseconds(125)) }
            catch { break }
        }
        let candidate = await latch.candidate
        readers.forEach { $0.cancel() }
        for (target, path) in paths where target != candidate?.endpoint {
            await path.close()
        }
        guard let candidate else {
            for (_, path) in paths { await path.close() }
            return
        }
        guard isRunning, !Task.isCancelled,
              let livePeer = current.peers.first(where: { $0.id == peer.id }),
              livePeer.publicKey == peer.publicKey else {
            await candidate.path.close()
            return
        }
        authenticatedReachability[peer.id] = AuthenticatedReachability(
            publicKey: livePeer.publicKey, verifiedAt: Date())
        current = P2PCoordinatorSnapshot(assignedID: current.assignedID,
                                         observedEndpoint: current.observedEndpoint,
                                         peers: current.peers,
                                         authenticatedReachablePeerIDs: Set(authenticatedReachability.keys),
                                         directPeerIDs: current.directPeerIDs)
        updateContinuation.yield(current)
        pathCandidateContinuation.yield(P2PAuthenticatedPathCandidate(
            peer: livePeer, endpoint: candidate.endpoint, channel: candidate.path))
    }

    private static func endpoint(address: Data, port: UInt16) -> P2PEndpoint? {
        guard port > 0, let normalized = ipv6Address(address),
              normalized.contains(where: { $0 != 0 }) else { return nil }
        let result = normalized.count == 16 && normalized.prefix(10).allSatisfy({ $0 == 0 }) &&
            normalized[10] == 0xff && normalized[11] == 0xff
            ? Data(normalized.suffix(4)) : normalized
        return P2PEndpoint(address: result, port: port)
    }

    private static func ipv6Address(_ address: Data) -> Data? {
        if address.count == 16 { return address }
        guard address.count == 4 else { return nil }
        return Data(repeating: 0, count: 10) + Data([0xff, 0xff]) + address
    }

    private static func ipv4Bytes(_ address: String?) -> Data? {
        guard let address else { return nil }
        let components = address.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4 else { return nil }
        var bytes: [UInt8] = []
        for component in components {
            guard let value = UInt8(component), String(value) == component else { return nil }
            bytes.append(value)
        }
        return Data(bytes)
    }
}

private actor PunchReachabilityLatch {
    struct Candidate: Sendable {
        let endpoint: P2PEndpoint
        let path: any P2PPunchPath
    }

    private(set) var candidate: Candidate?

    func resolve(_ endpoint: P2PEndpoint, path: any P2PPunchPath) {
        guard candidate == nil else { return }
        candidate = Candidate(endpoint: endpoint, path: path)
    }
}
