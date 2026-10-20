import Darwin
import Foundation
import NetworkExtension
import WantasticCore

/// Starts only after loading the registered config from the shared Keychain
/// and completing a fresh authenticated WireGuard handshake with the endpoint.
public final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private struct DirectPeer {
        let peer: P2PPeerRecord
        let transport: WireGuardPeerTransport
    }

    private let stateLock = NSLock()
    private var peer: WireGuardPeerTransport?
    private var rpcDispatcher: TunnelProviderRPCDispatcher?
    private var p2pCoordinator: P2PCoordinator?
    private var wuspTransport: WUSPRequestTransport?
    private var transferManager: WUSPTransferSessionManager?
    private var transferTask: Task<Void, Never>?
    private var localAccessManager: MacLocalAccessProviderManager?
    private var eventTask: Task<Void, Never>?
    private var onboardingTask: Task<Void, Never>?
    private var pathCandidateTask: Task<Void, Never>?
    private var directEventTasks: [UInt32: Task<Void, Never>] = [:]
    private var directPeers: [UInt32: DirectPeer] = [:]
    private var pendingDirectTransports: [UInt32: WireGuardPeerTransport] = [:]
    private var localAccessRouteTable = TunnelLocalAccessRouteTable()
    private var exitNodePublicKey: Data?
    private var stopped = false

    public override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        setStopped(false)
        let completion = StartCompletion(completionHandler)
        Task {
            do {
                try await startSecureTunnel()
                completion.call(nil)
            } catch {
                await stopPeer()
                setStopped(true)
                completion.call(error)
            }
        }
    }

    public override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        setStopped(true)
        cancelEventTask()
        let completion = StopCompletion(completionHandler)
        Task {
            await stopPeer()
            completion.call()
        }
    }

    private func startSecureTunnel() async throws {
        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = tunnelProtocol.providerConfiguration,
              let consoleHost = providerConfiguration["consoleHost"] as? String,
              !consoleHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ProviderError.missingConfiguration
        }
        let configuration: WireGuardConfiguration
        switch providerConfiguration["configurationSource"] as? String ?? "registered" {
        case "registered":
            guard let registered = try RegisteredDeviceStore().load(consoleHost: consoleHost) else {
                throw ProviderError.registrationMissing
            }
            configuration = registered.configuration
        case "manual":
            guard let manual = try ManualWireGuardConfigurationStore().load(consoleHost: consoleHost) else {
                throw ProviderError.registrationMissing
            }
            configuration = manual
        default:
            throw ProviderError.missingConfiguration
        }

        guard !isStopped() else { throw WireGuardPeerTransportError.closed }
        let transport = try WireGuardPeerTransport(configuration: configuration)
        guard let applicationSupport = FileManager.default.urls(for: .applicationSupportDirectory,
                                                                 in: .userDomainMask).first else {
            throw ProviderError.transferStorageUnavailable
        }
        let transferDirectory = applicationSupport
            .appendingPathComponent("Wantastic/Transfers", isDirectory: true)
        let transferManager = WUSPTransferSessionManager(channel: transport,
                                                          directory: transferDirectory)
        let wuspAgent = try MacWUSPAgentDispatcher(consoleHost: consoleHost,
                                                   eventSender: { payload in
            Task {
                try? await transport.sendWUSPControlPayload(payload)
            }
        }, asyncOperationHandler: { commandPath, _, _ in
            switch commandPath {
            case "Device.Reboot()":
                try await XPCMacLocalAccessFirewallSystem().scheduleSystemReboot()
                return nil
            case "Device.FactoryReset()":
                return nil
            default:
                throw MacWUSPOperationError.unsupported
            }
        }, transferManager: transferManager)
        await transport.setInboundWUSPRequestHandler { [weak self] payload in
            let request = try? WUSPTransportCodec.decodeRequest(payload)
            let responsePayload = await wuspAgent.handleAsync(payload)
            if request?.method == .operate,
               request?.metadata["wusp.operation_command_path"] == "Device.FactoryReset()",
               let responsePayload,
               let response = try? WUSPTransportCodec.decodeResponse(responsePayload),
               response.error.isEmpty {
                Task { [weak self] in
                    try? await Task.sleep(for: .seconds(2))
                    self?.cancelTunnelWithError(nil)
                }
            }
            return responsePayload
        }
        setPeer(transport)
        startTransferPump(using: transport, manager: transferManager)
        try await transport.start()
        try await transport.waitUntilEstablished(timeout: .seconds(30))
        guard !isStopped() else { throw WireGuardPeerTransportError.closed }
        let wuspTransport = WUSPRequestTransport(channel: transport, deviceID: "local-tunnel-peer")
        let localAccessManager = MacLocalAccessProviderManager(configuration: configuration,
                                                               sender: transport)
        guard installRPCDispatcher(wuspTransport: wuspTransport,
                                   p2pCoordinator: nil,
                                   tunnelControlSender: transport,
                                   localAccessManager: localAccessManager) else {
            throw WireGuardPeerTransportError.closed
        }

        let settings = try TunnelNetworkSettingsBuilder.build(configuration)
        try await apply(settings)
        guard !isStopped() else { throw WireGuardPeerTransportError.closed }
        stateLock.withLock {
            localAccessRouteTable = TunnelLocalAccessRouteTable()
            exitNodePublicKey = nil
        }
        await startP2PCoordination(using: transport, configuration: configuration)
        startEventPump(transport, configuration: configuration)
        if let deviceID = try? DeviceIdentity.hashedPlatformIdentifier() {
            startOnboardingLoop(using: transport, deviceID: deviceID)
        }
        readNextPackets(using: transport)
    }

    private func startP2PCoordination(using transport: WireGuardPeerTransport,
                                      configuration: WireGuardConfiguration) async {
        guard let localEndpoint = await transport.localEndpoint(),
              let privateKey = Data(base64Encoded: configuration.privateKey),
              let key = try? WireGuardKeyAgreement(base64PrivateKey: configuration.privateKey),
              let serverKey = Data(base64Encoded: configuration.peerPublicKey) else { return }
        let hostCandidates = (try? MacDeviceCollector.p2pCandidates(udpPort: localEndpoint.port)) ?? []
        let candidates = ([localEndpoint] + hostCandidates).reduce(into: [P2PEndpoint]()) { values, item in
            if !values.contains(item) { values.append(item) }
        }
        guard let coordinator = try? P2PCoordinator(channel: transport,
                                                    privateKey: privateKey,
                                                    publicKey: key.publicKey,
                                                    serverPublicKey: serverKey,
                                                    localEndpoint: localEndpoint,
                                                    candidates: candidates),
              !isStopped() else { return }
        let pathCandidates = await coordinator.authenticatedPathCandidates
        do {
            try await coordinator.start()
            guard installP2PCoordinator(coordinator) else {
                await coordinator.close()
                return
            }
            startPathCandidatePump(pathCandidates, coordinator: coordinator,
                                   baseConfiguration: configuration)
        }
        catch {
            await coordinator.close()
        }
    }

    public override func handleAppMessage(_ messageData: Data,
                                          completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler else { return }
        let reply = ProviderMessageReply(completionHandler)
        stateLock.lock()
        let dispatcher = rpcDispatcher
        stateLock.unlock()
        Task {
            let response = await dispatcher?.dispatch(messageData)
                ?? (try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(errorCode: "tunnel_not_ready")))
            reply.respond(response)
        }
    }

    private func apply(_ settings: NEPacketTunnelNetworkSettings) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            setTunnelNetworkSettings(settings) { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }

    private func startEventPump(_ transport: WireGuardPeerTransport,
                                configuration: WireGuardConfiguration) {
        cancelEventTask()
        let task = Task { [weak self] in
            for await event in transport.events {
                guard let self, !Task.isCancelled else { return }
                guard case let .received(messageType, _, payload) = event else { continue }
                if messageType == .transport, let family = Self.packetFamily(payload) {
                    self.packetFlow.writePackets([payload], withProtocols: [NSNumber(value: family)])
                } else if messageType == .tunnelControl {
                    // This event pump is attached only to the configured hub
                    // peer. Peer-specific direct transports never apply routes.
                    try? await self.applyTunnelControl(payload, configuration: configuration)
                }
            }
            guard let self, !Task.isCancelled else { return }
            self.cancelTunnelWithError(ProviderError.peerTransportClosed)
        }
        setEventTask(task)
    }

    private func applyTunnelControl(_ payload: Data,
                                    configuration: WireGuardConfiguration) async throws {
        guard !isStopped() else { return }
        let message = try TunnelControlCodec.decodePaddedWireGuardPayload(payload)
        var proposed = stateLock.withLock { localAccessRouteTable }
        let previousExit = stateLock.withLock { exitNodePublicKey }
        let routeChange = try proposed.apply(message)
        var proposedExit = previousExit
        switch message {
        case let .useExitNodeRouting(publicKey):
            guard publicKey.count == 32, !publicKey.allSatisfy({ $0 == 0 }) else {
                throw TunnelControlError.malformed
            }
            proposedExit = publicKey
        case .revokeExitNodeRouting:
            proposedExit = nil
        default:
            break
        }
        guard routeChange != nil || proposedExit != previousExit else { return }
        let exitRoutes: [String]
        if proposedExit == nil { exitRoutes = [] }
        else { exitRoutes = try TunnelExitRoutePolicy.routeTargets(for: configuration.addresses) }
        let settings = try TunnelNetworkSettingsBuilder.build(
            configuration,
            localAccessRoutes: proposed.routes,
            exitNodeRoutes: exitRoutes)
        try await apply(settings)
        stateLock.withLock {
            localAccessRouteTable = proposed
            exitNodePublicKey = proposedExit
        }
    }

    private func readNextPackets(using transport: WireGuardPeerTransport) {
        guard !isStopped() else { return }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, !self.isStopped() else { return }
            Task {
                for (packet, proto) in zip(packets, protocols) {
                    guard !self.isStopped() else { return }
                    guard let family = Self.packetFamily(packet), family == proto.int32Value else { continue }
                    do {
                        try await self.sendPacket(packet, using: transport)
                    }
                    catch {
                        self.cancelTunnelWithError(error)
                        return
                    }
                }
                self.readNextPackets(using: transport)
            }
        }
    }

    private func sendPacket(_ packet: Data, using relayTransport: WireGuardPeerTransport) async throws {
        let directPeer = directPeerRoute(for: packet)
        var directSend: PacketFlowRouteSender.Send?
        if let directPeer {
            let directTransport = directPeer.transport
            directSend = { (packet: Data) async throws -> Void in
                try await directTransport.sendTransportPacket(packet)
            }
        }
        let relay: PacketFlowRouteSender.Send = { (packet: Data) async throws -> Void in
            try await relayTransport.sendTransportPacket(packet)
        }
        let onDirectFailure: @Sendable () async -> Void = { [weak self] in
            guard let self, let directPeer else { return }
            await self.directPeerSendFailed(directPeer)
        }
        try await PacketFlowRouteSender.send(packet, directly: directSend,
                                              relay: relay,
                                              onDirectFailure: onDirectFailure)
    }

    private func stopPeer() async {
        let localAccess = stateLock.withLock { localAccessManager }
        do { try await localAccess?.disable() }
        catch { /* Keep forwarding if the controller may still hold an advertised route. */ }
        let transferState = stateLock.withLock { () -> (WUSPTransferSessionManager?, Task<Void, Never>?) in
            let manager = transferManager
            let task = transferTask
            transferManager = nil
            transferTask = nil
            return (manager, task)
        }
        transferState.1?.cancel()
        await transferState.0?.close()
        let (_, coordinator, currentPeer, directPeers, pendingDirect, onboardingTask) =
            takePeerAndRequestTransport()
        onboardingTask?.cancel()
        await coordinator?.close()
        await currentPeer?.stop()
        for directPeer in directPeers { await directPeer.transport.stop() }
        for transport in pendingDirect { await transport.stop() }
    }

    private func startTransferPump(using transport: WireGuardPeerTransport,
                                   manager: WUSPTransferSessionManager) {
        let task = Task {
            let frames = transport.wuspTransferStreamPayloads
            for await payload in frames {
                guard !Task.isCancelled else { return }
                guard let frame = try? WUSPTransferStreamCodec.decode(payload) else { continue }
                await manager.receive(frame)
            }
        }
        stateLock.withLock {
            transferManager = manager
            transferTask?.cancel()
            transferTask = task
        }
    }

    private func takePeerAndRequestTransport() ->
        (TunnelProviderRPCDispatcher?, P2PCoordinator?, WireGuardPeerTransport?,
         [DirectPeer], [WireGuardPeerTransport], Task<Void, Never>?) {
        stateLock.lock()
        let rpc = rpcDispatcher
        rpcDispatcher = nil
        localAccessManager = nil
        let coordinator = p2pCoordinator
        p2pCoordinator = nil
        wuspTransport = nil
        let currentPeer = peer
        peer = nil
        let directPeers = Array(self.directPeers.values)
        self.directPeers.removeAll()
        let pendingDirect = Array(pendingDirectTransports.values)
        pendingDirectTransports.removeAll()
        let candidateTask = pathCandidateTask
        pathCandidateTask = nil
        let directTasks = Array(directEventTasks.values)
        directEventTasks.removeAll()
        let onboardingTask = self.onboardingTask
        self.onboardingTask = nil
        stateLock.unlock()
        candidateTask?.cancel()
        directTasks.forEach { $0.cancel() }
        return (rpc, coordinator, currentPeer, directPeers, pendingDirect, onboardingTask)
    }

    private func isStopped() -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return stopped
    }

    private func setStopped(_ value: Bool) {
        stateLock.lock()
        stopped = value
        stateLock.unlock()
    }

    private func setPeer(_ value: WireGuardPeerTransport?) {
        stateLock.lock()
        peer = value
        stateLock.unlock()
    }

    @discardableResult
    private func installRPCDispatcher(wuspTransport: WUSPRequestTransport,
                                      p2pCoordinator: P2PCoordinator?,
                                      tunnelControlSender: (any TunnelControlPayloadSender)?,
                                      localAccessManager: MacLocalAccessProviderManager? = nil) -> Bool {
        stateLock.lock()
        guard !stopped else {
            stateLock.unlock()
            return false
        }
        self.wuspTransport = wuspTransport
        self.p2pCoordinator = p2pCoordinator
        self.localAccessManager = localAccessManager
        rpcDispatcher = TunnelProviderRPCDispatcher(transport: wuspTransport,
                                                     deviceID: "local-tunnel-peer",
                                                     p2pCoordinator: p2pCoordinator,
                                                     tunnelControlSender: tunnelControlSender,
                                                     localAccessManager: localAccessManager)
        stateLock.unlock()
        return true
    }

    private func installP2PCoordinator(_ value: P2PCoordinator) -> Bool {
        stateLock.lock()
        guard !stopped, let wuspTransport, let peer else {
            stateLock.unlock()
            return false
        }
        p2pCoordinator = value
        rpcDispatcher = TunnelProviderRPCDispatcher(transport: wuspTransport,
                                                     deviceID: "local-tunnel-peer",
                                                     p2pCoordinator: value,
                                                     tunnelControlSender: peer,
                                                     localAccessManager: localAccessManager)
        stateLock.unlock()
        return true
    }

    private func setEventTask(_ value: Task<Void, Never>?) {
        stateLock.lock()
        eventTask = value
        stateLock.unlock()
    }

    private func startPathCandidatePump(
        _ candidates: AsyncStream<P2PAuthenticatedPathCandidate>,
        coordinator: P2PCoordinator,
        baseConfiguration: WireGuardConfiguration
    ) {
        let task = Task { [weak self] in
            for await candidate in candidates {
                guard let self, !Task.isCancelled else { return }
                await self.promoteDirectCandidate(candidate, coordinator: coordinator,
                                                  baseConfiguration: baseConfiguration)
            }
        }
        stateLock.lock()
        pathCandidateTask?.cancel()
        pathCandidateTask = task
        stateLock.unlock()
    }

    private func startOnboardingLoop(using transport: WireGuardPeerTransport, deviceID: String) {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
        let osVersion = ProcessInfo.processInfo.operatingSystemVersion
        let softwareVersion = "Wantastic \(version) (macOS \(osVersion.majorVersion).\(osVersion.minorVersion).\(osVersion.patchVersion))"
        let task = Task { [weak self] in
            var eventID = UInt64.random(in: 1...UInt64.max)
            while let self, !Task.isCancelled, !self.isStopped() {
                if let payload = try? WUSPAgentEventCodec.encodeOnBoardRequest(
                    id: eventID,
                    serialNumber: deviceID,
                    manufacturer: "Wantastic",
                    productClass: "WantasticDesktopMac",
                    softwareVersion: softwareVersion
                ) {
                    try? await transport.sendWUSPControlPayload(payload)
                }
                eventID = eventID == UInt64.max ? 1 : eventID + 1
                do { try await Task.sleep(for: .seconds(45)) }
                catch { return }
            }
        }
        stateLock.withLock {
            guard !stopped else {
                task.cancel()
                return
            }
            onboardingTask?.cancel()
            onboardingTask = task
        }
    }

    private func promoteDirectCandidate(_ candidate: P2PAuthenticatedPathCandidate,
                                        coordinator: P2PCoordinator,
                                        baseConfiguration: WireGuardConfiguration) async {
        guard !isStopped(), let assignedIPv4 = candidate.peer.assignedIPv4,
              let directConfiguration = try? baseConfiguration.directPeer(
                publicKey: candidate.peer.publicKey, endpoint: candidate.endpoint,
                assignedIPv4: assignedIPv4),
              let directTransport = try? WireGuardPeerTransport(
                configuration: directConfiguration, connection: candidate.channel,
                maximumSessionAge: WireGuardTimerPolicy.directSessionStaleAfterSeconds) else {
            await candidate.channel.close()
            return
        }
        guard registerPendingDirect(directTransport, peerID: candidate.peer.id) else {
            await directTransport.stop()
            return
        }
        do {
            try await directTransport.start()
            try await directTransport.waitUntilEstablished(timeout: .seconds(8))
        } catch {
            removePendingDirect(peerID: candidate.peer.id, transport: directTransport)
            await directTransport.stop()
            await coordinator.markDirectSession(candidate.peer.id, established: false)
            return
        }
        guard !isStopped() else {
            await directTransport.stop()
            return
        }

        let installed = installDirect(directTransport, peer: candidate.peer)
        guard installed.succeeded else {
            await directTransport.stop()
            return
        }
        if let previous = installed.previous { await previous.transport.stop() }
        await coordinator.markDirectSession(candidate.peer.id, established: true)
        startDirectEventPump(directTransport, peerID: candidate.peer.id,
                             assignedIPv4: assignedIPv4, coordinator: coordinator)
    }

    private func startDirectEventPump(_ transport: WireGuardPeerTransport, peerID: UInt32,
                                     assignedIPv4: String, coordinator: P2PCoordinator) {
        let task = Task { [weak self] in
            for await event in transport.events {
                guard let self, !Task.isCancelled else { return }
                guard case let .received(messageType: .transport, _, packet) = event,
                      TunnelPeerPacketPolicy.acceptsIPv4(packet, sourceAddress: assignedIPv4) else {
                    continue
                }
                self.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
            }
            guard let self, !Task.isCancelled else { return }
            await self.directPeerEnded(peerID, transport: transport, coordinator: coordinator)
        }
        stateLock.lock()
        directEventTasks[peerID]?.cancel()
        directEventTasks[peerID] = task
        stateLock.unlock()
    }

    private func directPeerEnded(_ peerID: UInt32, transport: WireGuardPeerTransport,
                                 coordinator: P2PCoordinator) async {
        guard let direct = stateLock.withLock({ directPeers[peerID] }),
              ObjectIdentifier(direct.transport) == ObjectIdentifier(transport) else { return }
        await retireDirect(direct, coordinator: coordinator)
    }

    private func directPeerSendFailed(_ direct: DirectPeer) async {
        let coordinator = stateLock.withLock { p2pCoordinator }
        await retireDirect(direct, coordinator: coordinator)
    }

    private func retireDirect(_ direct: DirectPeer,
                              coordinator: P2PCoordinator?) async {
        guard removeDirect(direct.peer.id, transport: direct.transport) else { return }
        await coordinator?.markDirectSession(direct.peer.id, established: false)
        await direct.transport.stop()
    }

    private func registerPendingDirect(_ transport: WireGuardPeerTransport, peerID: UInt32) -> Bool {
        stateLock.withLock {
            guard !stopped else { return false }
            pendingDirectTransports[peerID] = transport
            return true
        }
    }

    private func removePendingDirect(peerID: UInt32, transport: WireGuardPeerTransport) {
        stateLock.withLock {
            guard let pending = pendingDirectTransports[peerID],
                  ObjectIdentifier(pending) == ObjectIdentifier(transport) else { return }
            pendingDirectTransports[peerID] = nil
        }
    }

    private func installDirect(_ transport: WireGuardPeerTransport, peer: P2PPeerRecord)
        -> (succeeded: Bool, previous: DirectPeer?) {
        stateLock.withLock {
            pendingDirectTransports[peer.id] = nil
            guard !stopped else { return (false, nil) }
            return (true, directPeers.updateValue(DirectPeer(peer: peer, transport: transport),
                                                   forKey: peer.id))
        }
    }

    private func removeDirect(_ peerID: UInt32, transport: WireGuardPeerTransport) -> Bool {
        stateLock.withLock {
            guard let current = directPeers[peerID],
                  ObjectIdentifier(current.transport) == ObjectIdentifier(transport) else {
                return false
            }
            directPeers[peerID] = nil
            directEventTasks[peerID] = nil
            return true
        }
    }

    private func directPeerRoute(for packet: Data) -> DirectPeer? {
        let packet = Data(packet)
        guard packet.count >= 20, packet[0] >> 4 == 4 else { return nil }
        let destination = packet.subdata(in: 16..<20).map(String.init).joined(separator: ".")
        stateLock.lock()
        defer { stateLock.unlock() }
        return directPeers.values.first { $0.peer.assignedIPv4 == destination }
    }

    private func cancelEventTask() {
        stateLock.lock()
        let task = eventTask
        eventTask = nil
        stateLock.unlock()
        task?.cancel()
    }

    private static func packetFamily(_ packet: Data) -> Int32? {
        guard let first = packet.first else { return nil }
        switch first >> 4 {
        case 4: return AF_INET
        case 6: return AF_INET6
        default: return nil
        }
    }
}

private final class StartCompletion: @unchecked Sendable {
    private let completion: (Error?) -> Void
    init(_ completion: @escaping (Error?) -> Void) { self.completion = completion }
    func call(_ error: Error?) { completion(error) }
}

private final class StopCompletion: @unchecked Sendable {
    private let completion: () -> Void
    init(_ completion: @escaping () -> Void) { self.completion = completion }
    func call() { completion() }
}

private final class ProviderMessageReply: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Data?) -> Void)?

    init(_ completion: @escaping (Data?) -> Void) { self.completion = completion }

    func respond(_ data: Data?) {
        lock.lock()
        let callback = completion
        completion = nil
        lock.unlock()
        callback?(data)
    }
}

private enum ProviderError: LocalizedError {
    case missingConfiguration
    case registrationMissing
    case peerTransportClosed
    case transferStorageUnavailable

    var errorDescription: String? {
        switch self {
        case .missingConfiguration: "The Wantastic tunnel profile is missing its account configuration."
        case .registrationMissing: "This Mac has not completed device setup. Sign in again."
        case .peerTransportClosed: "The secure connection to the Wantastic network ended."
        case .transferStorageUnavailable: "Wantastic could not locate its private transfer storage."
        }
    }
}
