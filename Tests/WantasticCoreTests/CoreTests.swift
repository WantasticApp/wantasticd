import Testing
import CryptoKit
import Darwin
import Foundation
import Network
@testable import WantasticCore
@testable import WantasticTunnel
@testable import WantasticLocalAccessHelperCore

@Test func consoleLoginValidatesSecureConsoleOriginWithoutGeneratingClaimLinks() throws {
    let url = try #require(URL(string: "https://console.example.test"))
    let login = try ConsoleLogin(baseURL: url)
    #expect(login.baseURL == url)
}

@Test func embeddedConsoleAllowsOnlyCredentialFreeHTTPSNavigation() throws {
    #expect(SecureWebNavigationPolicy.allows(URL(string: "https://console.example.test/devices")))
    #expect(SecureWebNavigationPolicy.allows(URL(string: "https://login.example.test/oauth/callback")))
    #expect(!SecureWebNavigationPolicy.allows(URL(string: "http://console.example.test")))
    #expect(!SecureWebNavigationPolicy.allows(URL(string: "file:///etc/passwd")))
    #expect(!SecureWebNavigationPolicy.allows(URL(string: "javascript:alert(1)")))
    #expect(!SecureWebNavigationPolicy.allows(URL(string: "https://user:secret@console.example.test")))
}

@Test func xpcPeerSigningRequirementPinsExpectedBundleAndCertificate() throws {
    let requirement = try CodeSignatureRequirement.peerRequirement(
        identifier: MacLocalAccessHelperService.helperBundleIdentifier,
        certificateSHA1: "0123456789ABCDEF0123456789ABCDEF01234567")
    #expect(requirement == "identifier \"app.wantastic.desktop.local-access-helper\" and certificate leaf = H\"0123456789ABCDEF0123456789ABCDEF01234567\"")
    let clientRequirement = try CodeSignatureRequirement.peerRequirement(
        identifiers: [MacLocalAccessHelperService.appBundleIdentifier,
                     MacLocalAccessHelperService.networkExtensionBundleIdentifier],
        certificateSHA1: "0123456789ABCDEF0123456789ABCDEF01234567")
    #expect(clientRequirement.contains("identifier \"app.wantastic.desktop\""))
    #expect(clientRequirement.contains(" or identifier \"app.wantastic.desktop.network-extension\""))
    #expect(clientRequirement.components(separatedBy: "certificate leaf").count == 3)
    #expect(throws: CodeSignatureRequirementError.invalidIdentifier) {
        try CodeSignatureRequirement.peerRequirement(
            identifier: "app.wantastic.desktop;exec", certificateSHA1: String(repeating: "A", count: 40))
    }
    #expect(throws: CodeSignatureRequirementError.signingInformationUnavailable) {
        try CodeSignatureRequirement.peerRequirement(
            identifier: "app.wantastic.desktop", certificateSHA1: "not-a-fingerprint")
    }
}

@Test func nativeWireGuardUDPConnectionExchangesLoopbackDatagram() async throws {
    let listener = try NWListener(using: .udp, on: .any)
    let queue = DispatchQueue(label: "wantastic.tests.udp.echo")
    let listenerReady = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let port = listener.port?.rawValue else {
                    continuation.resume(throwing: WireGuardUDPError.invalidEndpoint)
                    return
                }
                continuation.resume(returning: port)
            case let .failed(error): continuation.resume(throwing: error)
            default: break
            }
        }
        listener.newConnectionHandler = { connection in
            connection.start(queue: queue)
            connection.receiveMessage { data, _, _, error in
                guard error == nil, let data else { return }
                connection.send(content: data, completion: .contentProcessed { _ in connection.cancel() })
            }
        }
        listener.start(queue: queue)
    }
    defer { listener.cancel() }

    let client = try WireGuardUDPConnection(host: "127.0.0.1", port: listenerReady)
    defer { client.cancel() }
    try await client.start()
    let payload = Data("wantastic-udp-loopback".utf8)
    try await client.send(payload)
    let echoed = try await client.receive()
    #expect(echoed == payload)
}

@Test func p2pPunchUDPPathReusesCoordinatorLocalPortAndExchangesDatagrams() async throws {
    let (coordinatorListener, coordinatorPort) = try await makeLoopbackUDPListener(echo: false)
    let (peerListener, peerPort) = try await makeLoopbackUDPListener(echo: true)
    defer {
        coordinatorListener.cancel()
        peerListener.cancel()
    }

    let coordinator = try WireGuardUDPConnection(host: "127.0.0.1", port: coordinatorPort)
    defer { coordinator.cancel() }
    try await coordinator.start()
    let mappedLocalEndpoint = try #require(coordinator.localEndpoint())
    let peerEndpoint = P2PEndpoint(address: Data([127, 0, 0, 1]), port: peerPort)
    let punchPath = try await coordinator.openP2PPunchPath(to: peerEndpoint)
    let probe = Data([P2PMessageSubtype.punchPacket]) + Data(repeating: 0x71, count: 40)
    try await punchPath.send(probe)
    let response = try await punchPath.receive()
    #expect(response == probe)
    #expect(punchPath.localEndpoint.port == mappedLocalEndpoint.port)
    await punchPath.cancel()
}

@Test func wireGuardPeerTimersMatchBundledGoRetryAndPersistentKeepalivePolicy() {
    let now = Date(timeIntervalSince1970: 100)
    #expect(WireGuardTimerPolicy.rekeyAfterSeconds == 120)
    #expect(WireGuardTimerPolicy.rejectAfterSeconds == 300)
    #expect(WireGuardTimerPolicy.retryDelay(jitter: -1) == 2)
    #expect(WireGuardTimerPolicy.retryDelay(jitter: 0.2) == 2.2)
    #expect(WireGuardTimerPolicy.retryDelay(jitter: 1) == 2.334)
    #expect(!WireGuardTimerPolicy.shouldSendKeepalive(lastActivity: now, now: now.addingTimeInterval(24), interval: 25))
    #expect(WireGuardTimerPolicy.shouldSendKeepalive(lastActivity: now, now: now.addingTimeInterval(25), interval: 25))
    #expect(!WireGuardTimerPolicy.shouldSendKeepalive(lastActivity: now, now: now.addingTimeInterval(500), interval: 0))
    #expect(WireGuardTimerPolicy.keepaliveDelay(lastActivity: now, now: now.addingTimeInterval(10), interval: 25) == 15)
}

@Test func nativeWireGuardPeerTransportCompletesAuthenticatedLoopbackHandshake() async throws {
    let clientPrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let peerPrivate = try #require(Data(hexEncoded: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    let clientPublic = try #require(Data(hexEncoded: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let peerPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    let listener = try NWListener(using: .udp, on: .any)
    let queue = DispatchQueue(label: "wantastic.tests.wireguard.responder")
    listener.newConnectionHandler = { connection in
        connection.start(queue: queue)
        connection.receiveMessage { datagram, _, _, error in
            guard error == nil, let datagram,
                  let response = try? makeWireGuardResponderResponse(
                    datagram, peerPrivateKey: peerPrivate, peerPublicKey: peerPublic,
                    clientPublicKey: clientPublic
                  ) else { return }
            connection.send(content: response, completion: .contentProcessed { _ in
                connection.receiveMessage { incoming, _, _, receiveError in
                    guard receiveError == nil, let incoming,
                          let payload = try? P2PProtocolCodec.decodeDatagram(incoming),
                          let reply = try? P2PProtocolCodec.encodeDatagram(payload: payload) else { return }
                    connection.send(content: reply, completion: .contentProcessed { _ in })
                }
            })
        }
    }
    let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let port = listener.port?.rawValue else {
                    continuation.resume(throwing: WireGuardUDPError.invalidEndpoint)
                    return
                }
                continuation.resume(returning: port)
            case let .failed(error): continuation.resume(throwing: error)
            default: break
            }
        }
        listener.start(queue: queue)
    }
    defer { listener.cancel() }

    let configText = """
    [Interface]
    PrivateKey = \(clientPrivate.base64EncodedString())
    Address = 10.255.255.35/32
    [Peer]
    PublicKey = \(peerPublic.base64EncodedString())
    Endpoint = 127.0.0.1:\(port)
    AllowedIPs = 10.255.255.32/27
    PersistentKeepalive = 25
    """
    let transport = try WireGuardPeerTransport(configuration: WireGuardConfiguration.parse(configText))
    try await transport.start()
    try await transport.waitUntilEstablished(timeout: .seconds(5))
    let localEndpoint = await transport.localEndpoint()
    #expect(localEndpoint?.port ?? 0 > 0)
    #expect(localEndpoint?.address.count == 4 || localEndpoint?.address.count == 16)
    let payload = try P2PProtocolCodec.encode(P2PMessage(subtype: P2PMessageSubtype.registerAck,
                                                         targetID: 73))
    let p2pPayloads = await transport.p2pControlPayloads
    let received = Task<Data?, Never> {
        for await message in p2pPayloads { return message }
        return nil
    }
    try await transport.sendP2PControlPayload(payload)
    #expect(await received.value == payload)
    await transport.stop()
}

@Test func authenticatedP2PPunchSocketPromotesToWireGuardPeerSession() async throws {
    let clientPrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let peerPrivate = try #require(Data(hexEncoded: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    let clientPublic = try #require(Data(hexEncoded: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let peerPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    let queue = DispatchQueue(label: "wantastic.tests.p2p.wireguard-promotion")
    let peerListener = try NWListener(using: .udp, on: .any)
    peerListener.newConnectionHandler = { connection in
        connection.start(queue: queue)
        connection.receiveMessage { datagram, _, _, error in
            guard error == nil, let datagram,
                  let response = try? makeWireGuardResponderResponse(
                    datagram, peerPrivateKey: peerPrivate, peerPublicKey: peerPublic,
                    clientPublicKey: clientPublic
                  ) else { return }
            connection.send(content: response, completion: .contentProcessed { _ in })
        }
    }
    let peerPort = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
        peerListener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let port = peerListener.port?.rawValue else {
                    continuation.resume(throwing: WireGuardUDPError.invalidEndpoint)
                    return
                }
                continuation.resume(returning: port)
            case let .failed(error): continuation.resume(throwing: error)
            default: break
            }
        }
        peerListener.start(queue: queue)
    }
    defer { peerListener.cancel() }

    let (coordinatorListener, coordinatorPort) = try await makeLoopbackUDPListener(echo: false)
    defer { coordinatorListener.cancel() }
    let coordinator = try WireGuardUDPConnection(host: "127.0.0.1", port: coordinatorPort)
    defer { coordinator.cancel() }
    try await coordinator.start()
    let coordinatorEndpoint = try #require(coordinator.localEndpoint())
    let peerEndpoint = P2PEndpoint(address: Data([127, 0, 0, 1]), port: peerPort)
    let punchSocket = try await coordinator.openP2PPunchPath(to: peerEndpoint)
    #expect(punchSocket.localEndpoint.port == coordinatorEndpoint.port)

    let relayConfiguration = try WireGuardConfiguration.parse("""
    [Interface]
    PrivateKey = \(clientPrivate.base64EncodedString())
    Address = 10.255.255.35/32
    [Peer]
    PublicKey = \(peerPublic.base64EncodedString())
    Endpoint = 127.0.0.1:\(coordinatorPort)
    AllowedIPs = 10.255.255.32/27
    PersistentKeepalive = 25
    """)
    let directConfiguration = try relayConfiguration.directPeer(
        publicKey: peerPublic, endpoint: peerEndpoint, assignedIPv4: "10.255.255.36")
    let directTransport = try WireGuardPeerTransport(configuration: directConfiguration,
                                                     connection: punchSocket)
    try await directTransport.start()
    try await directTransport.waitUntilEstablished(timeout: .seconds(5))
    await directTransport.stop()
}

@Test func nativeWireGuardPeerTransportSendsFragmentedAuthenticatedWUSP() async throws {
    let clientPrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let peerPrivate = try #require(Data(hexEncoded: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    let clientPublic = try #require(Data(hexEncoded: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let peerPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    let listener = try NWListener(using: .udp, on: .any)
    let queue = DispatchQueue(label: "wantastic.tests.wireguard.wusp-responder")
    let responder = WireGuardWUSPResponder(peerPrivateKey: peerPrivate,
                                           peerPublicKey: peerPublic,
                                           clientPublicKey: clientPublic)
    listener.newConnectionHandler = { connection in responder.accept(connection, queue: queue) }
    let port = try await waitForUDPListener(listener, queue: queue)
    defer { listener.cancel() }

    let config = """
    [Interface]
    PrivateKey = \(clientPrivate.base64EncodedString())
    Address = 10.0.0.2/32
    [Peer]
    PublicKey = \(peerPublic.base64EncodedString())
    Endpoint = 127.0.0.1:\(port)
    AllowedIPs = 10.0.0.0/8
    """
    let transport = try WireGuardPeerTransport(configuration: WireGuardConfiguration.parse(config))
    try await transport.start()
    try await transport.waitUntilEstablished(timeout: .seconds(5))
    let collector = WUSPMessage(fields: [
        WUSPMessageField(path: "Device.DeviceInfo.HostName", value: .string("loopback-mac")),
    ])
    let operationCount = WUSPTestInvocationCounter()
    let operationCredentials = MemoryCredentialPersistence()
    for account in [
        "registered-device:console.example.test",
        "manual-wireguard:console.example.test",
        "wusp-settings:console.example.test:friendly-name",
        "wusp-settings:console.example.test:provisioning-code",
    ] {
        try operationCredentials.write(Data("secret".utf8), account: account)
    }
    let dispatcher = try MacWUSPAgentDispatcher(consoleHost: "console.example.test",
                                                credentials: operationCredentials,
                                                asyncOperationHandler: { commandPath, _, _ in
        guard commandPath == "Device.DeviceInfo.Test()" ||
              commandPath == "Device.FactoryReset()" else {
            throw MacWUSPOperationError.unsupported
        }
        operationCount.increment()
        try await Task.sleep(for: .milliseconds(50))
        return nil
    },
                                                collector: { collector })
    await transport.setInboundWUSPRequestHandler { await dispatcher.handleAsync($0) }

    let request = WUSPWireRequest(
        id: 902, method: .get, metadata: ["wusp.request_sequence": "13"],
        pathCodes: [8_582_781_017_805_368_456], pathInstances: [[]])
    let requestPayload = try WUSPTransportCodec.encode(request)
    try await responder.sendWUSP(requestPayload)
    let responsePayload = try await responder.waitForWUSP(timeout: .seconds(5))
    let response = try WUSPTransportCodec.decodeResponse(responsePayload)
    #expect(response.id == request.id)
    #expect(response.metadata["wusp.response_sequence"] == "13")
    let responseMessage = try WUSPMessageCodec.decode(try #require(response.messageFrame))
    #expect(responseMessage.fields == [
        WUSPMessageField(path: "Device.DeviceInfo.HostName", value: .string("loopback-mac")),
    ])

    let operate = WUSPWireRequest(
        id: 904, method: .operate, objectPath: "Device.DeviceInfo.",
        metadata: [
            "wusp.request_sequence": "14",
            "wusp.operation_command_path": "Device.DeviceInfo.Test()",
        ])
    let operatePayload = try WUSPTransportCodec.encode(operate)
    var operateResponses: [Data] = []
    for _ in 0..<2 {
        try await responder.sendWUSP(operatePayload)
        operateResponses.append(try await responder.waitForWUSP(timeout: .seconds(5)))
    }
    #expect(operateResponses[0] == operateResponses[1])
    #expect(operationCount.value == 1)
    let operateResponse = try WUSPTransportCodec.decodeResponse(operateResponses[1])
    #expect(operateResponse.error.isEmpty)
    #expect(operateResponse.metadata["wusp.response_sequence"] == "14")

    let reset = WUSPWireRequest(
        id: 905, method: .operate, objectPath: "Device.",
        metadata: [
            "wusp.request_sequence": "15",
            "wusp.operation_command_path": "Device.FactoryReset()",
        ])
    try await responder.sendWUSP(WUSPTransportCodec.encode(reset))
    let resetResponse = try WUSPTransportCodec.decodeResponse(
        await responder.waitForWUSP(timeout: .seconds(5)))
    #expect(resetResponse.error.isEmpty)
    #expect(resetResponse.metadata["wusp.response_sequence"] == "15")
    #expect(operationCount.value == 2)
    for account in [
        "registered-device:console.example.test",
        "manual-wireguard:console.example.test",
        "wusp-settings:console.example.test:friendly-name",
        "wusp-settings:console.example.test:provisioning-code",
    ] {
        #expect(try operationCredentials.read(account: account) == nil)
    }

    let replyPayload = Data("response!".utf8)
    let receivedReplies = await transport.wuspControlPayloads
    let replyTask = Task { () throws -> Data in
        for await value in receivedReplies where value == replyPayload { return value }
        throw WireGuardPeerTransportError.closed
    }

    // 2,338 bytes becomes two Go-format fragments. The last fragment is
    // WireGuard-block aligned so this asserts exact payload reassembly without
    // relying on an ambiguous transport-padding length.
    let payload = Data((0..<2_338).map { UInt8(($0 * 31) & 0xff) })
    let received = try await withThrowingTaskGroup(of: Data.self) { group in
        group.addTask { try await responder.waitForWUSP(timeout: .seconds(5)) }
        try await transport.sendWUSPControlPayload(payload)
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
    #expect(received == payload)
    #expect(try await replyTask.value == replyPayload)

    let transferFrame = WUSPTransferStreamFrame(
        sessionID: 44, requestID: 903, method: .upload, phase: .open,
        totalSize: 3, path: "Device.DeviceInfo.SerialNumber", filename: "serial.bin")
    let encodedTransferFrame = try WUSPTransferStreamCodec.encode(transferFrame)
    let transferStream = await transport.wuspTransferStreamPayloads
    let inboundTransfer = try await withThrowingTaskGroup(of: Data.self) { group in
        group.addTask {
            for await frame in transferStream
                where (try? WUSPTransferStreamCodec.decode(frame)) == transferFrame {
                return frame
            }
            throw WireGuardPeerTransportError.closed
        }
        group.addTask {
            try await Task.sleep(for: .seconds(5))
            throw URLError(.timedOut)
        }
        try await responder.sendRawWUSP(encodedTransferFrame)
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
    #expect(try WUSPTransferStreamCodec.decode(inboundTransfer) == transferFrame)
    let outboundTransferReply = Task {
        try await responder.waitForWUSP(timeout: .seconds(5))
    }
    try await transport.sendWUSPTransferStreamFrame(transferFrame)
    #expect(try await outboundTransferReply.value == encodedTransferFrame)

    for sequence in 1...160 {
        let queuedFrame = WUSPTransferStreamFrame(
            sessionID: UInt64(1_000 + sequence), requestID: 904,
            method: .upload, phase: .open, sequence: UInt32(sequence))
        try await responder.sendRawWUSP(WUSPTransferStreamCodec.encode(queuedFrame))
    }
    try await Task.sleep(for: .milliseconds(100))
    #expect(await transport.droppedTransferFrameCount > 0)
    await transport.stop()
}

@Test func nativeWireGuardPeerTransportRekeysWithoutDroppingItsActiveConnection() async throws {
    let clientPrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let peerPrivate = try #require(Data(hexEncoded: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    let clientPublic = try #require(Data(hexEncoded: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let peerPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    let listener = try NWListener(using: .udp, on: .any)
    let queue = DispatchQueue(label: "wantastic.tests.wireguard.rekey-responder")
    listener.newConnectionHandler = { connection in
        startWireGuardResponder(connection, queue: queue,
                                peerPrivateKey: peerPrivate, peerPublicKey: peerPublic,
                                clientPublicKey: clientPublic)
    }
    let port = try await waitForUDPListener(listener, queue: queue)
    defer { listener.cancel() }

    let config = """
    [Interface]
    PrivateKey = \(clientPrivate.base64EncodedString())
    Address = 10.0.0.2/32
    [Peer]
    PublicKey = \(peerPublic.base64EncodedString())
    Endpoint = 127.0.0.1:\(port)
    AllowedIPs = 10.0.0.0/8
    """
    let transport = try WireGuardPeerTransport(configuration: WireGuardConfiguration.parse(config),
                                              rekeyAfterSeconds: 0.04,
                                              maximumSessionAge: 0.14)
    let events = await transport.events
    let counter = WireGuardHandshakeEventCounter()
    let eventMonitor = Task {
        for await event in events {
            if case .established = event {
                _ = await counter.increment()
            }
        }
    }
    try await transport.start()
    try await transport.waitUntilEstablished(timeout: .seconds(3))
    // Stay connected for longer than the configured session limit. Every
    // authenticated rekey must renew the expiry deadline.
    try await Task.sleep(for: .milliseconds(450))
    let establishedCount = await counter.value
    await transport.stop()
    await eventMonitor.value
    #expect(establishedCount >= 5)
}

@Test func nativeWireGuardDirectSessionExpiresWhenHandshakeGoesStale() async throws {
    let clientPrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let peerPrivate = try #require(Data(hexEncoded: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    let clientPublic = try #require(Data(hexEncoded: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let peerPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    let listener = try NWListener(using: .udp, on: .any)
    let queue = DispatchQueue(label: "wantastic.tests.wireguard.stale-direct-responder")
    listener.newConnectionHandler = { connection in
        startWireGuardResponder(connection, queue: queue,
                                peerPrivateKey: peerPrivate, peerPublicKey: peerPublic,
                                clientPublicKey: clientPublic)
    }
    let port = try await waitForUDPListener(listener, queue: queue)
    defer { listener.cancel() }

    let config = """
    [Interface]
    PrivateKey = \(clientPrivate.base64EncodedString())
    Address = 10.0.0.2/32
    [Peer]
    PublicKey = \(peerPublic.base64EncodedString())
    Endpoint = 127.0.0.1:\(port)
    AllowedIPs = 10.0.0.0/8
    """
    let transport = try WireGuardPeerTransport(
        configuration: WireGuardConfiguration.parse(config),
        rekeyAfterSeconds: 30, maximumSessionAge: 0.1)
    let events = await transport.events
    try await transport.start()
    try await transport.waitUntilEstablished(timeout: .seconds(3))

    let closed = await withTaskGroup(of: Bool.self) { group in
        group.addTask { for await _ in events {}; return true }
        group.addTask { try? await Task.sleep(for: .seconds(2)); return false }
        let first = await group.next() ?? false
        group.cancelAll()
        return first
    }
    await transport.stop()
    #expect(closed)
}

private actor WireGuardHandshakeEventCounter {
    private(set) var value = 0

    func increment() -> Int {
        value += 1
        return value
    }
}

private struct WUSPTransportStub: WUSPTransport {
    let response: WUSPResponse

    func send(_ request: WUSPRequest, to deviceID: String) async throws -> WUSPResponse {
        response
    }
}

private struct WUSPTransportFailure: WUSPTransport {
    func send(_ request: WUSPRequest, to deviceID: String) async throws -> WUSPResponse {
        throw WUSPRequestTransportError.channelClosed
    }
}

private final class MockP2PCoordinatorChannel: P2PControlChannel, @unchecked Sendable {
    private let lock = NSLock()
    let p2pControlPayloads: AsyncStream<Data>
    private let continuation: AsyncStream<Data>.Continuation
    private let peerListPayload: Data
    private let punchResponse: Data?
    private var sent: [Data] = []

    init(peerListPayload: Data = Data([0, 0, 0, 0]), punchResponse: Data? = nil) {
        let stream = AsyncStream<Data>.makeStream()
        p2pControlPayloads = stream.stream
        continuation = stream.continuation
        self.peerListPayload = peerListPayload
        self.punchResponse = punchResponse
    }

    func sendP2PControlPayload(_ payload: Data) async throws {
        record(payload)
        guard let request = try? P2PProtocolCodec.decodeMessage(payload) else { return }
        if request.subtype == P2PMessageSubtype.register {
            let acknowledgment = try P2PMessage(
                subtype: P2PMessageSubtype.registerAck,
                observedAddress: Data(repeating: 0, count: 10) + Data([0xff, 0xff, 8, 8, 4, 4]),
                observedPort: 51_821, targetID: 91)
            continuation.yield(try P2PProtocolCodec.encode(acknowledgment))
        } else if request.subtype == P2PMessageSubtype.peerList {
            let list = try P2PMessage(subtype: P2PMessageSubtype.peerList,
                                      payload: peerListPayload)
            continuation.yield(try P2PProtocolCodec.encode(list))
        }
    }

    func openP2PPunchPath(to endpoint: P2PEndpoint) async throws -> any P2PPunchPath {
        guard let punchResponse else { throw WireGuardUDPError.invalidEndpoint }
        return MockP2PPunchPath(localEndpoint: endpoint, response: punchResponse)
    }

    func emit(_ payload: Data) {
        continuation.yield(payload)
    }

    private func record(_ payload: Data) {
        lock.lock()
        sent.append(payload)
        lock.unlock()
    }

    func sentMessages() -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        return sent
    }
}

private actor MockP2PPunchPath: P2PPunchPath {
    nonisolated let localEndpoint: P2PEndpoint
    private let response: Data
    private var received = false
    private var waiter: CheckedContinuation<Data, Error>?
    private var closed = false

    init(localEndpoint: P2PEndpoint, response: Data) {
        self.localEndpoint = localEndpoint
        self.response = response
    }

    func start() async throws {}

    func send(_ datagram: Data) async throws {
        guard !closed else { throw CancellationError() }
        if let waiter {
            self.waiter = nil
            received = true
            waiter.resume(returning: response)
        }
    }

    func receive() async throws -> Data {
        if received { throw CancellationError() }
        guard !closed else { throw CancellationError() }
        return try await withCheckedThrowingContinuation { continuation in
            waiter = continuation
        }
    }

    func close() async {
        closed = true
        waiter?.resume(throwing: CancellationError())
        waiter = nil
    }
}

private func makeP2PPeerListPayload(id: UInt32, publicKey: Data,
                                    assignedIPv4: [UInt8], offersExitNode: Bool = false) -> Data {
    precondition(publicKey.count == 32 && assignedIPv4.count == 4)
    var payload = Data([0, 0, 0, 1])
    appendBigEndian(id, to: &payload)
    payload.append(publicKey)
    payload.append(Data(repeating: 0, count: 16))
    payload.append(contentsOf: [0, 0])
    payload.append(Data(repeating: 0, count: 16))
    payload.append(contentsOf: [0, 0, 1, offersExitNode ? 3 : 1])
    payload.append(contentsOf: assignedIPv4)
    return payload
}

private final class MockTunnelControlPayloadSender: TunnelControlPayloadSender, @unchecked Sendable {
    private let lock = NSLock()
    private var payloads: [Data] = []

    func sendTUNControlPayload(_ payload: Data) async throws {
        lock.withLock { payloads.append(payload) }
    }

    var sentPayloads: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return payloads
    }
}

private final class MockMacLocalAccessFirewallSystem: MacLocalAccessFirewallSystem, @unchecked Sendable {
    private let lock = NSLock()
    private let initialPFEnabled: Bool
    private let initialForwardingEnabled: Bool
    private var pfEnabled: Bool
    private var forwardingEnabled: Bool
    private var loadedRules = ""
    private var failNextOperation: String?
    private var eventLog: [String] = []

    init(pfEnabled: Bool = false, forwardingEnabled: Bool = false) {
        initialPFEnabled = pfEnabled
        initialForwardingEnabled = forwardingEnabled
        self.pfEnabled = pfEnabled
        self.forwardingEnabled = forwardingEnabled
    }

    func failNext(_ operation: String) { lock.withLock { failNextOperation = operation } }

    var events: [String] { lock.withLock { eventLog } }
    var currentRules: String { lock.withLock { loadedRules } }
    var isPFEnabled: Bool { lock.withLock { pfEnabled } }
    var isForwardingEnabled: Bool { lock.withLock { forwardingEnabled } }
    func recordExternal(_ event: String) { lock.withLock { eventLog.append(event) } }

    func ipv4ForwardingEnabled() async throws -> Bool { try lock.withLock { try record("readForwarding", value: forwardingEnabled) } }
    func setIPv4Forwarding(_ enabled: Bool) async throws {
        try lock.withLock {
            try record(enabled ? "forwardingOn" : "forwardingOff")
            forwardingEnabled = enabled
        }
    }
    func packetFilterEnabled() async throws -> Bool { try lock.withLock { try record("readPF", value: pfEnabled) } }
    func enablePacketFilter() async throws -> String {
        try lock.withLock {
            try record("enablePF")
            pfEnabled = true
            return "test-token"
        }
    }
    func apply(_ plan: MacLocalAccessFirewallPlan) async throws {
        try lock.withLock {
            try record("load")
            loadedRules = plan.rules
        }
    }
    func flushOwnedAnchor() async throws {
        try lock.withLock {
            try record("flush")
            loadedRules = ""
        }
    }
    func releasePacketFilter(token: String) async throws {
        try lock.withLock {
            try record("release")
            pfEnabled = false
        }
    }
    func restoreWantasticOwnedState() async throws {
        try lock.withLock {
            try record("restoreOwnedState")
            loadedRules = ""
            pfEnabled = initialPFEnabled
            forwardingEnabled = initialForwardingEnabled
        }
    }

    private func record<T>(_ event: String, value: T) throws -> T {
        try record(event)
        return value
    }

    private func record(_ event: String) throws {
        eventLog.append(event)
        if failNextOperation == event {
            failNextOperation = nil
            throw URLError(.cannotWriteToFile)
        }
    }
}

private final class MockMacLocalAccessRouteSender: TunnelControlPayloadSender, @unchecked Sendable {
    private let lock = NSLock()
    private let system: MockMacLocalAccessFirewallSystem
    private var sent: [Data] = []
    private var failedSendsRemaining = 0

    init(system: MockMacLocalAccessFirewallSystem) { self.system = system }
    func failNext(count: Int = 1) { lock.withLock { failedSendsRemaining = max(0, count) } }
    var payloads: [Data] { lock.withLock { sent } }

    func sendTUNControlPayload(_ payload: Data) async throws {
        let shouldFail = lock.withLock {
            sent.append(payload)
            let result = failedSendsRemaining > 0
            if result { failedSendsRemaining -= 1 }
            return result
        }
        let action = payload.first == TunnelControlAction.setLocalAccessRoutes.rawValue
            ? (payload.count > 1 && payload[1] > 0 ? "advertise" : "withdraw")
            : "unexpected-control"
        system.recordExternal(action)
        if shouldFail { throw URLError(.networkConnectionLost) }
    }
}

private func appendBigEndian(_ value: UInt32, to data: inout Data) {
    data.append(UInt8((value >> 24) & 0xff))
    data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private final class MockWUSPControlChannel: WUSPControlChannel, @unchecked Sendable {
    private let lock = NSLock()
    let wuspControlPayloads: AsyncStream<Data>
    private let continuation: AsyncStream<Data>.Continuation
    private let handler: @Sendable (Data) throws -> Data?
    private var sentCount = 0

    var numberOfSentPayloads: Int {
        lock.lock()
        defer { lock.unlock() }
        return sentCount
    }

    init(handler: @escaping @Sendable (Data) throws -> Data?) {
        let stream = AsyncStream<Data>.makeStream()
        wuspControlPayloads = stream.stream
        continuation = stream.continuation
        self.handler = handler
    }

    func sendWUSPControlPayload(_ payload: Data) async throws {
        recordSend()
        if let response = try handler(payload) { continuation.yield(response) }
    }

    private func recordSend() {
        lock.lock()
        sentCount += 1
        lock.unlock()
    }
}

private actor MockWUSPTransferStreamChannel: WUSPTransferStreamChannel {
    let wuspTransferStreamPayloads: AsyncStream<Data>
    private let continuation: AsyncStream<Data>.Continuation
    private(set) var sentFrames: [WUSPTransferStreamFrame] = []

    init() {
        let stream = AsyncStream<Data>.makeStream()
        wuspTransferStreamPayloads = stream.stream
        continuation = stream.continuation
    }

    func sendWUSPTransferStreamFrame(_ frame: WUSPTransferStreamFrame) async throws {
        sentFrames.append(frame)
        continuation.yield(try WUSPTransferStreamCodec.encode(frame))
    }
}

private func waitForUDPListener(_ listener: NWListener, queue: DispatchQueue) async throws -> UInt16 {
    try await withCheckedThrowingContinuation { continuation in
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let port = listener.port?.rawValue else {
                    continuation.resume(throwing: WireGuardUDPError.invalidEndpoint)
                    return
                }
                continuation.resume(returning: port)
            case let .failed(error): continuation.resume(throwing: error)
            default: break
            }
        }
        listener.start(queue: queue)
    }
}

private func startWireGuardResponder(_ connection: NWConnection, queue: DispatchQueue,
                                     peerPrivateKey: Data, peerPublicKey: Data,
                                     clientPublicKey: Data) {
    connection.start(queue: queue)
    @Sendable func receiveNext() {
        connection.receiveMessage { datagram, _, _, error in
            guard error == nil, let datagram else { return }
            guard let response = try? makeWireGuardResponderResponse(
                datagram, peerPrivateKey: peerPrivateKey, peerPublicKey: peerPublicKey,
                clientPublicKey: clientPublicKey
            ) else {
                receiveNext()
                return
            }
            connection.send(content: response, completion: .contentProcessed { error in
                if error == nil { receiveNext() }
            })
        }
    }
    receiveNext()
}

private final class WireGuardWUSPResponder: @unchecked Sendable {
    private let lock = NSLock()
    private let peerPrivateKey: Data
    private let peerPublicKey: Data
    private let clientPublicKey: Data
    private var receiver: WireGuardTransportCipher?
    private var sender: WireGuardTransportCipher?
    private var outboundCounter: UInt64 = 0
    private var assembler = WUSPControlFragmentAssembler()
    private var waiter: CheckedContinuation<Data, Error>?
    private var completedPayload: Data?
    private var connection: NWConnection?

    init(peerPrivateKey: Data, peerPublicKey: Data, clientPublicKey: Data) {
        self.peerPrivateKey = peerPrivateKey
        self.peerPublicKey = peerPublicKey
        self.clientPublicKey = clientPublicKey
    }

    func accept(_ connection: NWConnection, queue: DispatchQueue) {
        lock.lock()
        self.connection = connection
        lock.unlock()
        connection.start(queue: queue)
        receiveNext(on: connection)
    }

    func sendWUSP(_ payload: Data) async throws {
        let (connection, datagrams) = try makeWUSPDatagrams(payload)
        for datagram in datagrams {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(content: datagram, completion: .contentProcessed { error in
                    if let error { continuation.resume(throwing: error) }
                    else { continuation.resume() }
                })
            }
        }
    }

    func sendRawWUSP(_ payload: Data) async throws {
        let (connection, datagram) = try makeRawWUSPDatagram(payload)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: datagram, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            })
        }
    }

    private func makeWUSPDatagrams(_ payload: Data) throws -> (NWConnection, [Data]) {
        try lock.withLock {
            guard let connection, var sender else {
                throw WireGuardPeerSessionError.invalidState
            }
            let fragments = try WUSPControlFragmentCodec.fragment(payload, messageID: 1)
            let datagrams = try fragments.map { fragment -> Data in
                let padded = try WireGuardPacketPadding.pad(fragment, mtu: 1420)
                let datagram = try sender.seal(plaintext: padded, counter: outboundCounter,
                                               messageType: .wuspControl)
                outboundCounter += 1
                return datagram
            }
            self.sender = sender
            return (connection, datagrams)
        }
    }

    private func makeRawWUSPDatagram(_ payload: Data) throws -> (NWConnection, Data) {
        try lock.withLock {
            guard let connection, var sender else {
                throw WireGuardPeerSessionError.invalidState
            }
            let padded = try WireGuardPacketPadding.pad(payload, mtu: 1420)
            let datagram = try sender.seal(plaintext: padded, counter: outboundCounter,
                                           messageType: .wuspControl)
            outboundCounter += 1
            self.sender = sender
            return (connection, datagram)
        }
    }

    func waitForWUSP(timeout: Duration) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if let completedPayload {
                lock.unlock()
                continuation.resume(returning: completedPayload)
                return
            }
            waiter = continuation
            lock.unlock()
            Task {
                try? await Task.sleep(for: timeout)
                resolve(.failure(URLError(.timedOut)))
            }
        }
    }

    private func receiveNext(on connection: NWConnection) {
        connection.receiveMessage { [self] datagram, _, _, error in
            guard error == nil, let datagram else { return }
            if let response = try? makeResponseAndInstallReceiver(for: datagram) {
                connection.send(content: response, completion: .contentProcessed { [self] _ in
                    receiveNext(on: connection)
                })
                return
            }
            do {
                if let completed = try openWUSP(datagram) {
                    resolve(.success(completed))
                    if let reply = try? makeWUSPReply(Data("response!".utf8), messageID: 1) {
                        connection.send(content: reply, completion: .contentProcessed { _ in })
                    }
                }
            } catch {
                resolve(.failure(error))
            }
            receiveNext(on: connection)
        }
    }

    private func makeResponseAndInstallReceiver(for initiation: Data) throws -> Data {
        let authenticator = try WireGuardMessageAuthenticator(receiverStaticPublicKey: peerPublicKey)
        guard authenticator.verifiesMAC1(in: initiation) else {
            throw WireGuardInitiatorError.unauthenticatedPacket
        }
        let parsed = try WireGuardHandshakePacketCodec.decodeInitiation(initiation)
        var noise = try WireGuardNoiseHandshake(role: .responder,
                                                localPrivateKey: peerPrivateKey,
                                                remoteStaticPublicKey: clientPublicKey)
        try noise.consumeInitiation(parsed.payload)
        let payload = try noise.createResponse()
        let senderIndex = UInt32.random(in: 1...UInt32.max)
        let prefix = try WireGuardHandshakePacketCodec.encodeResponsePrefix(
            senderIndex: senderIndex, receiverIndex: parsed.senderIndex, payload: payload
        )
        let response = try WireGuardMessageAuthenticator(receiverStaticPublicKey: clientPublicKey)
            .addMACs(to: prefix)
        let keys = try noise.responderSessionKeys()
        let cipher = try WireGuardTransportCipher(key: keys.receive, receiverIndex: senderIndex)
        let sender = try WireGuardTransportCipher(key: keys.send, receiverIndex: parsed.senderIndex)
        lock.lock()
        receiver = cipher
        self.sender = sender
        lock.unlock()
        return response
    }

    private func makeWUSPReply(_ payload: Data, messageID: UInt64) throws -> Data {
        guard let frame = try WUSPControlFragmentCodec.fragment(payload, messageID: messageID).first else {
            throw WUSPControlFragmentError.malformed
        }
        let padded = try WireGuardPacketPadding.pad(frame, mtu: 1420)
        lock.lock()
        defer { lock.unlock() }
        guard var sender else { throw WireGuardPeerSessionError.invalidState }
        let datagram = try sender.seal(plaintext: padded, counter: outboundCounter,
                                       messageType: .wuspControl)
        outboundCounter += 1
        self.sender = sender
        return datagram
    }

    private func openWUSP(_ datagram: Data) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard var receiver else { throw WireGuardPeerSessionError.invalidState }
        let message = try receiver.open(datagram)
        self.receiver = receiver
        guard message.messageType == .wuspControl else { return nil }
        if message.plaintext.count >= 2,
           message.plaintext[message.plaintext.startIndex] == 0x53,
           message.plaintext[message.plaintext.index(after: message.plaintext.startIndex)] == 1,
           let frame = try? WUSPTransferStreamCodec.decode(message.plaintext) {
            return try WUSPTransferStreamCodec.encode(frame)
        }
        // Go pads the final WUSP datagram to a 16-byte block. This fixture is
        // aligned so exact reassembly does not assume an ambiguous tail length.
        return try assembler.consume(message.plaintext)
    }

    private func resolve(_ result: Result<Data, Error>) {
        lock.lock()
        let continuation = waiter
        waiter = nil
        if case let .success(payload) = result, continuation == nil {
            completedPayload = payload
        }
        lock.unlock()
        continuation?.resume(with: result)
    }
}

@Test func networkSettingsBuilderInstallsSplitRoutesAndEndpointExclusion() throws {
    let config = """
    [Interface]
    PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Address = 10.255.255.35/32
    DNS = 10.255.255.33, 1.1.1.1, 10.255.255.33
    [Peer]
    PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Endpoint = 127.0.0.1:51820
    AllowedIPs = 10.255.255.32/27, 192.168.1.8/32
    PersistentKeepalive = 25
    """
    let settings = try TunnelNetworkSettingsBuilder.build(WireGuardConfiguration.parse(config))
    let resolverFixtureURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("../../testdata/protocol/macos_split_dns.txt")
    let resolverLines = try String(contentsOf: resolverFixtureURL, encoding: .utf8)
        .split(whereSeparator: \.isNewline)
    var resolverDomain: String?
    var resolverServers: [String] = []
    for line in resolverLines {
        let fields = line.split(whereSeparator: \.isWhitespace)
        guard fields.count == 2 else { continue }
        if fields[0] == "domain" { resolverDomain = String(fields[1]) }
        if fields[0] == "nameserver" { resolverServers.append(String(fields[1])) }
    }
    let sharedResolverDomain = try #require(resolverDomain)
    #expect(!resolverServers.isEmpty)

    #expect(settings.tunnelRemoteAddress == "127.0.0.1")
    #expect(settings.mtu == 1420)
    #expect(settings.ipv4Settings?.addresses == ["10.255.255.35"])
    #expect(settings.ipv4Settings?.subnetMasks == ["255.255.255.255"])
    #expect(settings.ipv4Settings?.includedRoutes?.map(\.destinationAddress) == ["10.255.255.32", "192.168.1.8"])
    #expect(settings.ipv4Settings?.includedRoutes?.map(\.destinationSubnetMask) == ["255.255.255.224", "255.255.255.255"])
    #expect(settings.ipv4Settings?.excludedRoutes?.map(\.destinationAddress) == ["127.0.0.1"])
    #expect(settings.dnsSettings?.servers == resolverServers)
    #expect(settings.dnsSettings?.matchDomains == [sharedResolverDomain])
    #expect(settings.dnsSettings?.searchDomains == [sharedResolverDomain])
    #expect(settings.dnsSettings?.matchDomainsNoSearch == true)

    let remoteSubnet = try TunnelIPv4Prefix("172.19.4.9/32")
    let updated = try TunnelNetworkSettingsBuilder.build(WireGuardConfiguration.parse(config),
                                                         localAccessRoutes: [remoteSubnet])
    #expect(updated.ipv4Settings?.includedRoutes?.map(\.destinationAddress).contains("172.19.4.9") == true)
    #expect(updated.ipv4Settings?.includedRoutes?.map(\.destinationSubnetMask).contains("255.255.255.255") == true)
    #expect(throws: TunnelNetworkSettingsError.localRouteOverlapsTunnel) {
        try TunnelNetworkSettingsBuilder.build(WireGuardConfiguration.parse(config),
                                               localAccessRoutes: [try TunnelIPv4Prefix("10.255.255.36/32")])
    }

    let withExitRoute = try TunnelNetworkSettingsBuilder.build(
        WireGuardConfiguration.parse(config), exitNodeRoutes: ["0.0.0.0/0"])
    #expect(withExitRoute.ipv4Settings?.includedRoutes?.map(\.destinationAddress) ==
            ["10.255.255.32", "192.168.1.8", "0.0.0.0"])

    let dualStack = config.replacingOccurrences(
        of: "Address = 10.255.255.35/32",
        with: "Address = 10.255.255.35/32, fd00::35/128")
    let dualStackExit = try TunnelNetworkSettingsBuilder.build(
        WireGuardConfiguration.parse(dualStack), exitNodeRoutes: ["0.0.0.0/0", "::/0"])
    #expect(dualStackExit.ipv6Settings?.includedRoutes?.map(\.destinationAddress) == ["::"])
    #expect(dualStackExit.ipv6Settings?.includedRoutes?.map(\.destinationNetworkPrefixLength) == [0])
}

@Test func exitNodeRoutesMatchGoAddressFamilyPolicy() throws {
    #expect(try TunnelExitRoutePolicy.routeTargets(for: ["10.255.255.35/32"]) == ["0.0.0.0/0"])
    #expect(try TunnelExitRoutePolicy.routeTargets(for: ["fd00::35/128"]) == ["::/0"])
    #expect(try TunnelExitRoutePolicy.routeTargets(for: ["10.255.255.35/32", "fd00::35/128"]) ==
            ["0.0.0.0/0", "::/0"])
    #expect(try TunnelExitRoutePolicy.routeTargets(for: []) == ["0.0.0.0/0", "::/0"])
    #expect(throws: TunnelExitRoutePolicyError.invalidAddress) {
        try TunnelExitRoutePolicy.routeTargets(for: ["not-an-address/32"])
    }
}

@Test func networkSettingsBuilderRejectsHostnameDNSAndRouteWithoutInterfaceFamily() throws {
    let base = """
    [Interface]
    PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Address = 10.0.0.2/32
    [Peer]
    PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Endpoint = 127.0.0.1:51820
    AllowedIPs = 2001:db8::/32
    """
    #expect(throws: TunnelNetworkSettingsError.routeFamilyMissingAddress) {
        try TunnelNetworkSettingsBuilder.build(WireGuardConfiguration.parse(base))
    }
    let withDNS = base.replacingOccurrences(of: "Address = 10.0.0.2/32",
                                            with: "Address = 10.0.0.2/32\nDNS = resolver.example.test")
        .replacingOccurrences(of: "AllowedIPs = 2001:db8::/32", with: "AllowedIPs = 10.0.0.0/8")
    #expect(throws: TunnelNetworkSettingsError.invalidDNSAddress) {
        try TunnelNetworkSettingsBuilder.build(WireGuardConfiguration.parse(withDNS))
    }
}

@Test func nativeWireGuardPeerTransportFailsClosedWhenHandshakeTimesOut() async throws {
    let clientPrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let peerPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    let listener = try NWListener(using: .udp, on: .any)
    let queue = DispatchQueue(label: "wantastic.tests.wireguard.silent-peer")
    listener.newConnectionHandler = { connection in
        connection.start(queue: queue)
        connection.receiveMessage { _, _, _, _ in }
    }
    let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let port = listener.port?.rawValue else {
                    continuation.resume(throwing: WireGuardUDPError.invalidEndpoint)
                    return
                }
                continuation.resume(returning: port)
            case let .failed(error): continuation.resume(throwing: error)
            default: break
            }
        }
        listener.start(queue: queue)
    }
    defer { listener.cancel() }

    let config = """
    [Interface]
    PrivateKey = \(clientPrivate.base64EncodedString())
    Address = 10.0.0.2/32
    [Peer]
    PublicKey = \(peerPublic.base64EncodedString())
    Endpoint = 127.0.0.1:\(port)
    AllowedIPs = 10.0.0.0/8
    """
    let peer = try WireGuardPeerTransport(configuration: WireGuardConfiguration.parse(config))
    try await peer.start()
    await #expect(throws: WireGuardPeerTransportError.handshakeTimedOut) {
        try await peer.waitUntilEstablished(timeout: .milliseconds(200))
    }
    await peer.stop()
}

private func makeWireGuardResponderResponse(_ initiation: Data, peerPrivateKey: Data,
                                            peerPublicKey: Data, clientPublicKey: Data) throws -> Data {
    let packetAuthenticator = try WireGuardMessageAuthenticator(receiverStaticPublicKey: peerPublicKey)
    guard packetAuthenticator.verifiesMAC1(in: initiation) else {
        throw WireGuardInitiatorError.unauthenticatedPacket
    }
    let parsed = try WireGuardHandshakePacketCodec.decodeInitiation(initiation)
    var noise = try WireGuardNoiseHandshake(role: .responder, localPrivateKey: peerPrivateKey,
                                            remoteStaticPublicKey: clientPublicKey)
    try noise.consumeInitiation(parsed.payload)
    let payload = try noise.createResponse()
    let prefix = try WireGuardHandshakePacketCodec.encodeResponsePrefix(
        senderIndex: UInt32.random(in: 1...UInt32.max), receiverIndex: parsed.senderIndex, payload: payload
    )
    return try WireGuardMessageAuthenticator(receiverStaticPublicKey: clientPublicKey).addMACs(to: prefix)
}

@Test func consoleLoginRejectsInsecureURL() throws {
    let url = try #require(URL(string: "http://example.test"))
    #expect(throws: (any Error).self) { try ConsoleLogin(baseURL: url) }
}

@Test func deviceAuthorizationRequiresHTTPSAndClientID() throws {
    let insecureURL = try #require(URL(string: "http://console.wantastic.app"))
    #expect(throws: DeviceAuthorizationError.self) {
        try DeviceAuthorizationClient(baseURL: insecureURL, clientID: "wantastic_desktop")
    }
    let secureURL = try #require(URL(string: "https://console.wantastic.app"))
    #expect(throws: DeviceAuthorizationError.self) {
        try DeviceAuthorizationClient(baseURL: secureURL, clientID: "  ")
    }
    _ = try DeviceAuthorizationClient(baseURL: secureURL, clientID: "wantastic_desktop")
}

@Test func deviceAuthorizationResponseDecodesWireNames() throws {
    let payload = Data("""
    {"device_code":"secret-device-code","user_code":"ABCD-EFGH",
     "verification_uri":"https://console.wantastic.app/device",
     "verification_uri_complete":"https://console.wantastic.app/device?user_code=ABCD-EFGH",
     "expires_in":300,"interval":5}
    """.utf8)
    let value = try JSONDecoder().decode(DeviceAuthorization.self, from: payload)
    #expect(value.deviceCode == "secret-device-code")
    #expect(value.userCode == "ABCD-EFGH")
    #expect(value.expiresIn == 300)
    #expect(value.interval == 5)
}

@Test func deviceAuthorizationAppliesProtocolDefaults() throws {
    let payload = Data("""
    {"device_code":"d","user_code":"u","verification_uri":"https://console.wantastic.app/device","expires_in":0,"interval":0}
    """.utf8)
    let value = try JSONDecoder().decode(DeviceAuthorization.self, from: payload)
    #expect(value.expiresIn == 300)
    #expect(value.interval == 5)
}

@Test func wireGuardParserAcceptsHostRoutesAndRejectsInvalidPrefixes() throws {
    let config = """
    [Interface]
    PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Address = 10.255.255.35/32
    DNS = 10.255.255.33, 1.1.1.1

    [Peer]
    PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Endpoint = wg.wantastic.app:51820
    AllowedIPs = 10.255.255.32/27
    PersistentKeepalive = 25
    """
    let parsed = try WireGuardConfiguration.parse(config)
    #expect(parsed.addresses == ["10.255.255.35/32"])
    #expect(parsed.allowedIPs == ["10.255.255.32/27"])
    #expect(parsed.endpointHost == "wg.wantastic.app")
    #expect(parsed.endpointPort == 51820)
    #expect(parsed.persistentKeepalive == 25)

    let directKey = Data(repeating: 0x33, count: 32)
    let direct = try parsed.directPeer(
        publicKey: directKey,
        endpoint: P2PEndpoint(address: Data([203, 0, 113, 9]), port: 49_001),
        assignedIPv4: "10.255.255.36")
    #expect(direct.privateKey == parsed.privateKey)
    #expect(direct.addresses == parsed.addresses)
    #expect(direct.dnsServers == parsed.dnsServers)
    #expect(direct.peerPublicKey == directKey.base64EncodedString())
    #expect(direct.endpointHost == "203.0.113.9")
    #expect(direct.endpointPort == 49_001)
    #expect(direct.allowedIPs == ["10.255.255.36/32"])
    #expect(direct.peerPresharedKey == nil)
    #expect(direct.persistentKeepalive == 25)
    #expect(throws: WireGuardConfigError.invalidAddress) {
        try parsed.directPeer(publicKey: directKey,
                             endpoint: P2PEndpoint(address: Data([203, 0, 113, 9]), port: 49_001),
                             assignedIPv4: "not-an-ip")
    }

    let invalid = config.replacingOccurrences(of: "10.255.255.35/32", with: "10.255.255.35/33")
    #expect(throws: WireGuardConfigError.self) { try WireGuardConfiguration.parse(invalid) }
}

@Test func wireGuardX25519MatchesRFC7748KeyAgreementVector() throws {
    let alicePrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let bobPrivate = try #require(Data(hexEncoded: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    let expectedAlicePublic = try #require(Data(hexEncoded: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let expectedBobPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    let expectedSecret = try #require(Data(hexEncoded: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
    let alice = try WireGuardKeyAgreement(privateKey: alicePrivate)
    let bob = try WireGuardKeyAgreement(privateKey: bobPrivate)

    #expect(alice.publicKey == expectedAlicePublic)
    #expect(bob.publicKey == expectedBobPublic)
    #expect(try alice.sharedSecret(with: expectedBobPublic) == expectedSecret)
    #expect(try bob.sharedSecret(with: expectedAlicePublic) == expectedSecret)
    #expect(try WireGuardKeyAgreement(base64PrivateKey: alicePrivate.base64EncodedString()).publicKey == expectedAlicePublic)
}

@Test func wireGuardX25519RejectsInvalidAndLowOrderKeys() throws {
    #expect(throws: WireGuardKeyError.invalidPrivateKey) {
        try WireGuardKeyAgreement(privateKey: Data(repeating: 1, count: 31))
    }
    #expect(throws: WireGuardKeyError.invalidPrivateKey) {
        try WireGuardKeyAgreement(base64PrivateKey: "not-a-key")
    }
    let key = WireGuardKeyAgreement.generate()
    #expect(key.publicKey.count == 32)
    #expect(key.base64PrivateKey.count == 44)
    #expect(throws: WireGuardKeyError.invalidPublicKey) {
        try key.sharedSecret(with: Data(repeating: 0, count: 32))
    }
    #expect(throws: WireGuardKeyError.invalidPublicKey) {
        try key.sharedSecret(with: Data(repeating: 0, count: 31))
    }
}

@Test func wireGuardBlake2sAndKDFMatchGoFixtures() throws {
    let emptyDigest = try #require(Data(hexEncoded: "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"))
    let abcDigest = try #require(Data(hexEncoded: "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"))
    #expect(WireGuardKDF.blake2s(Data()) == emptyDigest)
    #expect(WireGuardKDF.blake2s(Data("abc".utf8)) == abcDigest)

    let key = Data("test-key".utf8)
    let input = Data("test-input".utf8)
    let expected = [
        try #require(Data(hexEncoded: "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633")),
        try #require(Data(hexEncoded: "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a")),
        try #require(Data(hexEncoded: "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24")),
    ]
    #expect(WireGuardKDF.derive1(chainingKey: key, input: input) == [expected[0]])
    #expect(WireGuardKDF.derive2(chainingKey: key, input: input) == Array(expected.prefix(2)))
    #expect(WireGuardKDF.derive3(chainingKey: key, input: input) == expected)

    let macKey = Data(0..<32)
    #expect(WireGuardKDF.blake2s128(key: macKey, message: Data()) ==
             (try #require(Data(hexEncoded: "9536f9b267655743dee97b8a670f9f53"))))
    #expect(WireGuardKDF.blake2s128(key: macKey, message: Data([0])) ==
             (try #require(Data(hexEncoded: "13bacfb85b48a1223c595f8c1e7e82cb"))))
}

@Test func wireGuardNoiseIKHandshakeDerivesMatchingDirectionalKeys() throws {
    let alicePrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let bobPrivate = try #require(Data(hexEncoded: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    let alicePublic = try #require(Data(hexEncoded: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let bobPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    let psk = Data(repeating: 0x5c, count: 32)
    let timestamp = Data([0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 1])
    var initiator = try WireGuardNoiseHandshake(role: .initiator, localPrivateKey: alicePrivate,
                                                 remoteStaticPublicKey: bobPublic, presharedKey: psk)
    var responder = try WireGuardNoiseHandshake(role: .responder, localPrivateKey: bobPrivate,
                                                 remoteStaticPublicKey: alicePublic, presharedKey: psk)

    let initiation = try initiator.createInitiation(timestamp: timestamp)
    #expect(initiation.ephemeralPublicKey.count == 32)
    #expect(initiation.encryptedStaticKey.count == 48)
    #expect(initiation.encryptedTimestamp.count == 28)
    try responder.consumeInitiation(initiation)
    let response = try responder.createResponse()
    #expect(response.ephemeralPublicKey.count == 32)
    #expect(response.encryptedEmpty.count == 16)

    let initiatorKeys = try initiator.consumeResponse(response)
    let responderKeys = try responder.responderSessionKeys()
    #expect(initiatorKeys.send == responderKeys.receive)
    #expect(initiatorKeys.receive == responderKeys.send)
    #expect(initiatorKeys.send.count == 32)
    #expect(initiatorKeys.receive.count == 32)
}

@Test func wireGuardNoiseIKRejectsTamperingAndInvalidTransitions() throws {
    let alicePrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let bobPrivate = try #require(Data(hexEncoded: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    let alicePublic = try #require(Data(hexEncoded: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let bobPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    var initiator = try WireGuardNoiseHandshake(role: .initiator, localPrivateKey: alicePrivate,
                                                 remoteStaticPublicKey: bobPublic)
    var responder = try WireGuardNoiseHandshake(role: .responder, localPrivateKey: bobPrivate,
                                                 remoteStaticPublicKey: alicePublic)
    let initiation = try initiator.createInitiation(timestamp: Data(repeating: 1, count: 12))
    var tamperedInitiation = initiation
    var encryptedStatic = Array(tamperedInitiation.encryptedStaticKey)
    encryptedStatic[0] ^= 1
    tamperedInitiation = WireGuardInitiationPayload(ephemeralPublicKey: initiation.ephemeralPublicKey,
                                                    encryptedStaticKey: Data(encryptedStatic),
                                                    encryptedTimestamp: initiation.encryptedTimestamp)
    #expect(throws: WireGuardHandshakeError.authenticationFailed) {
        try responder.consumeInitiation(tamperedInitiation)
    }
    try responder.consumeInitiation(initiation)
    let response = try responder.createResponse()
    var tamperedResponseBytes = Array(response.encryptedEmpty)
    tamperedResponseBytes[0] ^= 1
    let tamperedResponse = WireGuardResponsePayload(ephemeralPublicKey: response.ephemeralPublicKey,
                                                    encryptedEmpty: Data(tamperedResponseBytes))
    #expect(throws: WireGuardHandshakeError.authenticationFailed) {
        _ = try initiator.consumeResponse(tamperedResponse)
    }
    _ = try initiator.consumeResponse(response)
    #expect(throws: WireGuardHandshakeError.invalidState) {
        _ = try initiator.consumeResponse(response)
    }
    #expect(throws: WireGuardHandshakeError.invalidState) {
        try responder.consumeInitiation(initiation)
    }
}

@Test func wireGuardHandshakePacketsMatchFixedGoLayoutsAndMACs() throws {
    let payload = WireGuardInitiationPayload(ephemeralPublicKey: Data(repeating: 0x11, count: 32),
                                             encryptedStaticKey: Data(repeating: 0x22, count: 48),
                                             encryptedTimestamp: Data(repeating: 0x33, count: 28))
    let unsigned = try WireGuardHandshakePacketCodec.encodeInitiationPrefix(senderIndex: 0x11223344,
                                                                            payload: payload)
    #expect(unsigned.count == 116)
    #expect(Array(unsigned.prefix(8)) == [1, 0, 0, 0, 0x44, 0x33, 0x22, 0x11])

    let receiverPublicKey = Data(repeating: 0x44, count: 32)
    let cookie = Data(repeating: 0x55, count: 16)
    let authenticator = try WireGuardMessageAuthenticator(receiverStaticPublicKey: receiverPublicKey)
    let packetWithoutCookie = try authenticator.addMACs(to: unsigned)
    #expect(packetWithoutCookie.count == WireGuardHandshakePacketCodec.initiationLength)
    #expect(authenticator.verifiesMAC1(in: packetWithoutCookie))
    #expect(!authenticator.verifiesMAC2(in: packetWithoutCookie, cookie: cookie))
    let decoded = try WireGuardHandshakePacketCodec.decodeInitiation(packetWithoutCookie)
    #expect(decoded.senderIndex == 0x11223344)
    #expect(decoded.payload == payload)
    #expect(decoded.mac1.count == 16)
    #expect(decoded.mac2 == Data(repeating: 0, count: 16))

    let packetWithCookie = try authenticator.addMACs(to: unsigned, cookie: cookie)
    #expect(authenticator.verifiesMAC1(in: packetWithCookie))
    #expect(authenticator.verifiesMAC2(in: packetWithCookie, cookie: cookie))
    #expect(!authenticator.verifiesMAC2(in: packetWithCookie, cookie: Data(repeating: 0, count: 16)))
    var changed = Array(packetWithCookie)
    changed[12] ^= 1
    #expect(!authenticator.verifiesMAC1(in: Data(changed)))
    #expect(!authenticator.verifiesMAC2(in: Data(changed), cookie: cookie))
    let wrongReceiver = try WireGuardMessageAuthenticator(receiverStaticPublicKey: Data(repeating: 0x66, count: 32))
    #expect(!wrongReceiver.verifiesMAC1(in: packetWithCookie))
}

@Test func wireGuardInitiatorComposesAuthenticatedHandshakePackets() throws {
    let alicePrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let bobPrivate = try #require(Data(hexEncoded: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    let alicePublic = try #require(Data(hexEncoded: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let bobPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    let psk = Data(repeating: 0x5c, count: 32)
    let initiatorIndex: UInt32 = 0x10203040
    let responderIndex: UInt32 = 0x50607080
    var initiator = try WireGuardInitiator(localPrivateKey: alicePrivate,
                                            remoteStaticPublicKey: bobPublic,
                                            presharedKey: psk, senderIndex: initiatorIndex)
    let initialPacket = try initiator.begin(timestamp: Data(repeating: 1, count: 12))
    let responderInbound = try WireGuardMessageAuthenticator(receiverStaticPublicKey: bobPublic)
    #expect(responderInbound.verifiesMAC1(in: initialPacket))
    var cookieKeyInput = Data("cookie--".utf8)
    cookieKeyInput.append(alicePublic)
    let cookieKey = WireGuardKDF.blake2s(cookieKeyInput)
    let cookieNonce = Data(repeating: 0xa5, count: 24)
    let cookie = Data(repeating: 0x39, count: 16)
    let previousMAC1 = Data(initialPacket[116..<132])
    let encryptedCookie = try WireGuardMessageAuthenticator.xchacha20Poly1305Seal(
        key: cookieKey, nonce: cookieNonce, plaintext: cookie, aad: previousMAC1
    )
    let cookieReply = try WireGuardHandshakePacketCodec.encodeCookieReply(
        WireGuardCookieReply(receiverIndex: initiatorIndex, nonce: cookieNonce, encryptedCookie: encryptedCookie)
    )
    let initiation = try initiator.retry(afterCookieReply: cookieReply)
    #expect(Data(initiation.prefix(116)) == Data(initialPacket.prefix(116)))
    #expect(responderInbound.verifiesMAC1(in: initiation))
    #expect(responderInbound.verifiesMAC2(in: initiation, cookie: cookie))
    let parsedInitiation = try WireGuardHandshakePacketCodec.decodeInitiation(initiation)
    var responderNoise = try WireGuardNoiseHandshake(role: .responder, localPrivateKey: bobPrivate,
                                                      remoteStaticPublicKey: alicePublic, presharedKey: psk)
    try responderNoise.consumeInitiation(parsedInitiation.payload)
    let responsePayload = try responderNoise.createResponse()
    let responsePrefix = try WireGuardHandshakePacketCodec.encodeResponsePrefix(
        senderIndex: responderIndex, receiverIndex: initiatorIndex, payload: responsePayload
    )
    let responderOutbound = try WireGuardMessageAuthenticator(receiverStaticPublicKey: alicePublic)
    let response = try responderOutbound.addMACs(to: responsePrefix)
    let initiatorKeys = try initiator.receiveResponse(response)
    let responderKeys = try responderNoise.responderSessionKeys()
    #expect(initiatorKeys.send == responderKeys.receive)
    #expect(initiatorKeys.receive == responderKeys.send)
    #expect(throws: WireGuardInitiatorError.invalidState) {
        _ = try initiator.receiveResponse(response)
    }
}

@Test func wireGuardPeerSessionTransitionsHandshakeAndExchangesEncryptedPackets() throws {
    let clientPrivate = try #require(Data(hexEncoded: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let peerPrivate = try #require(Data(hexEncoded: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    let clientPublic = try #require(Data(hexEncoded: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let peerPublic = try #require(Data(hexEncoded: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    let clientIndex: UInt32 = 1234
    let peerIndex: UInt32 = 5678
    var client = try WireGuardPeerSession(localPrivateKey: clientPrivate,
                                           peerStaticPublicKey: peerPublic,
                                           localSenderIndex: clientIndex)
    #expect(throws: WireGuardPeerSessionError.invalidState) { _ = try client.encrypt(Data([1])) }
    let initiation = try client.begin(timestamp: Data(repeating: 2, count: 12))
    let parsed = try WireGuardHandshakePacketCodec.decodeInitiation(initiation)
    var peer = try WireGuardNoiseHandshake(role: .responder, localPrivateKey: peerPrivate,
                                           remoteStaticPublicKey: clientPublic)
    try peer.consumeInitiation(parsed.payload)
    let responsePayload = try peer.createResponse()
    let responsePrefix = try WireGuardHandshakePacketCodec.encodeResponsePrefix(
        senderIndex: peerIndex, receiverIndex: clientIndex, payload: responsePayload
    )
    let responseAuthenticator = try WireGuardMessageAuthenticator(receiverStaticPublicKey: clientPublic)
    let response = try responseAuthenticator.addMACs(to: responsePrefix)
    #expect(try client.receive(response) == .established(peerSenderIndex: peerIndex))

    let peerKeys = try peer.responderSessionKeys()
    let outboundPayload = Data([0x45, 0, 0, 20] + Array(repeating: 0xaa, count: 16))
    #expect(try WireGuardPacketPadding.trimIPPacket(outboundPayload) == outboundPayload)
    #expect(try WireGuardPacketPadding.pad(outboundPayload, mtu: 1420).count == 32)
    let outbound = try client.encrypt(outboundPayload)
    var peerReceiver = try WireGuardTransportCipher(key: peerKeys.receive, receiverIndex: peerIndex)
    let receivedAtPeer = try peerReceiver.open(outbound)
    #expect(try WireGuardPacketPadding.trimIPPacket(receivedAtPeer.plaintext) == outboundPayload)
    #expect(receivedAtPeer.counter == 0)

    let wuspPayload = Data([0x54, 1, 0, 0, 0x11, 0x22])
    let wuspDatagram = try client.encrypt(wuspPayload, messageType: .wuspControl)
    #expect(Array(wuspDatagram.prefix(4)) == [8, 0, 0, 0])
    let wuspMessage = try peerReceiver.open(wuspDatagram)
    #expect(wuspMessage.messageType == .wuspControl)
    #expect(wuspMessage.plaintext.prefix(wuspPayload.count) == wuspPayload)
    #expect(wuspMessage.plaintext.count == 16)

    let controlPayload = TunnelControlCodec.encodeExitNodeOffer(enabled: true)
    let controlDatagram = try client.encrypt(controlPayload, messageType: .tunnelControl)
    #expect(Array(controlDatagram.prefix(4)) == [7, 0, 0, 0])
    let controlMessage = try peerReceiver.open(controlDatagram)
    #expect(controlMessage.messageType == .tunnelControl)
    #expect(controlMessage.plaintext.prefix(controlPayload.count) == controlPayload)
    #expect(controlMessage.plaintext.count == 16)

    let inboundPayload = Data([0x60, 0, 0, 0, 0, 34] + Array(repeating: 0xcc, count: 68))
    #expect(try WireGuardPacketPadding.trimIPPacket(inboundPayload) == inboundPayload)
    #expect(try WireGuardPacketPadding.pad(inboundPayload, mtu: 1420).count == 80)
    var peerSender = try WireGuardTransportCipher(key: peerKeys.send, receiverIndex: clientIndex)
    let inbound = try peerSender.seal(plaintext: WireGuardPacketPadding.pad(inboundPayload, mtu: 1420), counter: 0)
    #expect(try client.receive(inbound) == .received(messageType: .transport, counter: 0,
                                                     plaintext: inboundPayload))
    let keepalive = try peerSender.seal(plaintext: Data(), counter: 1)
    #expect(try client.receive(keepalive) == .received(messageType: .transport, counter: 1,
                                                       plaintext: Data()))
    let routePayload = try TunnelControlCodec.encodeLocalAccessAdvertisement(["192.168.60.11/32"])
    let routeDatagram = try peerSender.seal(
        plaintext: WireGuardPacketPadding.pad(routePayload, mtu: 1420), counter: 2,
        messageType: .tunnelControl)
    #expect(try client.receive(routeDatagram) == .received(
        messageType: .tunnelControl, counter: 2,
        plaintext: WireGuardPacketPadding.pad(routePayload, mtu: 1420)))
    #expect(throws: WireGuardPeerSessionError.invalidState) { _ = try client.begin(timestamp: Data(repeating: 0, count: 12)) }
}

@Test func wuspControlFragmentsMatchGoWireHeaderAndBoundReassembly() throws {
    let fixture = WUSPControlFragment(messageID: 42, index: 0, count: 1, rawSize: 0,
                                      compressed: false, data: Data("abc".utf8))
    let encoded = try WUSPControlFragmentCodec.encode(fixture)
    #expect(encoded == Data([0x54, 1, 0, 42, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 97, 98, 99]))
    #expect(try WUSPControlFragmentCodec.decode(encoded) == .fragment(fixture))
    #expect(try WUSPControlFragmentCodec.decode(Data([1, 2])) == .raw(Data([1, 2])))

    let payload = Data((0..<2500).map { UInt8($0 & 0xff) })
    let frames = try WUSPControlFragmentCodec.fragment(payload, messageID: 0x0102030405060708)
    #expect(frames.count == 3)
    #expect(frames.allSatisfy { $0.count <= WUSPControlFragmentCodec.maximumDatagramPayload })
    let fragments = try frames.reversed().map { frame -> WUSPControlFragment in
        guard case let .fragment(fragment) = try WUSPControlFragmentCodec.decode(frame) else {
            throw WUSPControlFragmentError.malformed
        }
        return fragment
    }
    #expect(try WUSPControlFragmentCodec.reassemble(fragments) == payload)
    #expect(throws: WUSPControlFragmentError.malformed) {
        try WUSPControlFragmentCodec.reassemble([fragments[0], fragments[0], fragments[2]])
    }
    #expect(throws: WUSPControlFragmentError.tooLarge) {
        try WUSPControlFragmentCodec.fragment(Data(repeating: 0, count: 4 * 1024 * 1024 + 1), messageID: 1)
    }

    var assembler = WUSPControlFragmentAssembler()
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    #expect(try assembler.consume(frames[0], now: now) == nil)
    #expect(try assembler.consume(frames[0], now: now.addingTimeInterval(1)) == nil)
    #expect(try assembler.consume(frames[2], now: now.addingTimeInterval(2)) == nil)
    #expect(try assembler.consume(frames[1], now: now.addingTimeInterval(3)) == payload)
    #expect(assembler.pendingMessageCount == 0)

    #expect(try assembler.consume(frames[0], now: now) == nil)
    #expect(try assembler.consume(Data([1, 2, 3]), now: now.addingTimeInterval(31)) == Data([1, 2, 3]))
    #expect(assembler.pendingMessageCount == 0)
}

@Test func wireGuardResponseAndCookiePacketsRejectMalformedLengths() throws {
    let responsePayload = WireGuardResponsePayload(ephemeralPublicKey: Data(repeating: 0x77, count: 32),
                                                   encryptedEmpty: Data(repeating: 0x88, count: 16))
    let responsePrefix = try WireGuardHandshakePacketCodec.encodeResponsePrefix(
        senderIndex: 3, receiverIndex: 9, payload: responsePayload
    )
    let auth = try WireGuardMessageAuthenticator(receiverStaticPublicKey: Data(repeating: 0x44, count: 32))
    let response = try auth.addMACs(to: responsePrefix)
    let decodedResponse = try WireGuardHandshakePacketCodec.decodeResponse(response)
    #expect(decodedResponse.senderIndex == 3)
    #expect(decodedResponse.receiverIndex == 9)
    #expect(decodedResponse.payload == responsePayload)
    #expect(auth.verifiesMAC1(in: response))
    #expect(throws: WireGuardPacketError.malformed) {
        try WireGuardHandshakePacketCodec.decodeResponse(Data(repeating: 0, count: 91))
    }

    let cookieReply = WireGuardCookieReply(receiverIndex: 17, nonce: Data(repeating: 0xaa, count: 24),
                                          encryptedCookie: Data(repeating: 0xbb, count: 32))
    let cookiePacket = try WireGuardHandshakePacketCodec.encodeCookieReply(cookieReply)
    #expect(cookiePacket.count == WireGuardHandshakePacketCodec.cookieReplyLength)
    #expect(try WireGuardHandshakePacketCodec.decodeCookieReply(cookiePacket) == cookieReply)
    #expect(throws: WireGuardPacketError.malformed) {
        try WireGuardHandshakePacketCodec.decodeCookieReply(Data(repeating: 0, count: 63))
    }
}

@Test func xchacha20Poly1305OpensPublishedWireFormatVectorAndRejectsTampering() throws {
    let key = try #require(Data(hexEncoded: String(repeating: "00", count: 32)))
    let nonce = try #require(Data(hexEncoded: String(repeating: "00", count: 24)))
    let sealed = try #require(Data(hexEncoded: "789e9689e5208d7fd9e1f3c5b5341fb2f7033812ac9ebd3745e2c99c7bbfeb"))
    let plaintext = try WireGuardMessageAuthenticator.xchacha20Poly1305Open(
        key: key, nonce: nonce, ciphertext: sealed, aad: Data()
    )
    #expect(plaintext == Data(repeating: 0, count: 15))
    var tampered = Array(sealed)
    tampered[0] ^= 1
    #expect(throws: (any Error).self) {
        try WireGuardMessageAuthenticator.xchacha20Poly1305Open(
            key: key, nonce: nonce, ciphertext: Data(tampered), aad: Data()
        )
    }
}

@Test func wireGuardTransportEncryptsFramesAuthenticatesAndRejectsReplay() throws {
    let key = Data(repeating: 0x5a, count: 32)
    var receiver = try WireGuardTransportCipher(key: key, receiverIndex: 0x11223344)
    var sender = try WireGuardTransportCipher(key: key, receiverIndex: 0x11223344)
    let plaintext = Data([0x45, 0, 0, 20, 1, 2, 3, 4])
    let packet = try sender.seal(plaintext: plaintext, counter: 7)
    #expect(packet.count == WireGuardTransportCipher.headerLength + plaintext.count + 16)
    #expect(Array(packet.prefix(16)) == [4, 0, 0, 0, 0x44, 0x33, 0x22, 0x11,
                                         7, 0, 0, 0, 0, 0, 0, 0])
    let opened = try receiver.open(packet)
    #expect(opened.counter == 7)
    #expect(opened.plaintext == plaintext)
    #expect(throws: WireGuardTransportError.replayedOrOutOfWindow) { _ = try receiver.open(packet) }
    #expect(throws: WireGuardTransportError.replayedOrOutOfWindow) {
        _ = try sender.seal(plaintext: plaintext, counter: 7)
    }

    var tampered = Array(try sender.seal(plaintext: plaintext, counter: 8))
    tampered[tampered.count - 1] ^= 1
    #expect(throws: WireGuardTransportError.authenticationFailed) {
        _ = try receiver.open(Data(tampered))
    }
    var wrongReceiver = try WireGuardTransportCipher(key: key, receiverIndex: 1)
    #expect(throws: WireGuardTransportError.wrongReceiver) { _ = try wrongReceiver.open(packet) }
    _ = try receiver.open(try sender.seal(plaintext: plaintext, counter: 9000))
    let wuspPlaintext = Data([0x54, 1, 0, 0, 0x11, 0x22])
    let wuspPacket = try sender.seal(plaintext: wuspPlaintext, counter: 9001, messageType: .wuspControl)
    #expect(Array(wuspPacket.prefix(4)) == [8, 0, 0, 0])
    let openedWUSP = try receiver.open(wuspPacket)
    #expect(openedWUSP.messageType == .wuspControl)
    #expect(openedWUSP.plaintext == wuspPlaintext)
    let controlPacket = try sender.seal(plaintext: Data([6, 0]), counter: 9002, messageType: .tunnelControl)
    #expect(try receiver.open(controlPacket).messageType == .tunnelControl)
    #expect(throws: WireGuardTransportError.replayedOrOutOfWindow) { _ = try receiver.open(packet) }
    #expect(throws: WireGuardTransportError.counterExhausted) {
        _ = try sender.seal(plaintext: plaintext, counter: WireGuardTransportCipher.rejectAfterMessages)
    }
    #expect(throws: WireGuardTransportError.malformedPacket) {
        _ = try sender.seal(
            plaintext: Data(repeating: 0, count: WireGuardTransportCipher.maximumPacketLength), counter: 10
        )
    }
}

@Test func wireGuardReplayFilterMatchesGoRFC6479Fixtures() {
    var filter = WireGuardReplayFilter()
    let limit = WireGuardTransportCipher.rejectAfterMessages
    let accepted: [(UInt64, Bool)] = [
        (0, true), (1, true), (1, false), (9, true), (8, true), (7, true), (7, false),
        (8129, true), (8128, true), (8128, false), (8127, true), (2, true), (2, false),
        (8145, true), (3, false), (8145, false), (32516, true), (24388, true),
        (10, false), (24387, false), (24386, false), (24389, true), (24388, false),
        (0, false), (limit, false), (limit - 1, true), (limit, false),
        (limit - 1, false), (limit - 2, true), (limit + 1, false), (limit + 2, false),
        (limit - 2, false), (limit - 3, true), (0, false),
    ]
    for (counter, expected) in accepted {
        #expect(filter.validate(counter: counter, limit: limit) == expected)
    }
}

@Test func p2pCandidatePayloadMatchesGoWireFormatAndDeduplicates() {
    let ipv4 = P2PEndpoint(address: Data([192, 0, 2, 1]), port: 51820)
    let ipv6 = P2PEndpoint(address: Data([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]), port: 42000)
    let encoded = P2PProtocolCodec.encodeCandidates([ipv4, ipv4, ipv6,
        P2PEndpoint(address: Data([1, 2, 3]), port: 9999),
        P2PEndpoint(address: Data([203, 0, 113, 5]), port: 0)])

    let expected = Data([
        0x57, 0x50, 0x43, 0x31, 0x02,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1, 0xca, 0x6c,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xa4, 0x10,
    ])
    #expect(encoded == expected)
    #expect(P2PProtocolCodec.decodeCandidates(Data([0xaa, 0xbb]) + encoded, offset: 2) == [ipv4, ipv6])
}

@Test func p2pCandidateDecoderRejectsBadOffsetsAndTruncatedEntries() {
    let valid = P2PProtocolCodec.encodeCandidates([
        P2PEndpoint(address: Data([198, 51, 100, 9]), port: 51820),
    ])
    #expect(P2PProtocolCodec.decodeCandidates(valid, offset: -1).isEmpty)
    #expect(P2PProtocolCodec.decodeCandidates(valid, offset: valid.count).isEmpty)
    #expect(P2PProtocolCodec.decodeCandidates(valid.dropLast()).isEmpty)
    #expect(P2PProtocolCodec.decodeCandidates(Data([1, 2, 3, 4, 1])).isEmpty)
}

@Test func p2pMessageMatchesGoFixedHeaderAndRoundTrips() throws {
    #expect(P2PProtocolCodec.wireGuardMessageType == 6)
    #expect(P2PMessageSubtype.register == 1)
    #expect(P2PMessageSubtype.registerAck == 2)
    #expect(P2PMessageSubtype.peerList == 3)
    #expect(P2PMessageSubtype.punchRequest == 4)
    #expect(P2PMessageSubtype.punchRelay == 5)
    #expect(P2PMessageSubtype.punchPacket == 6)
    #expect(P2PMessageSubtype.heartbeat == 7)
    let message = try P2PMessage(
        subtype: 5,
        publicKey: Data(repeating: 0x11, count: 32),
        localAddress: Data(repeating: 0x22, count: 16), localPort: 51820,
        observedAddress: Data(repeating: 0x33, count: 16), observedPort: 42000,
        targetID: 0x01020304, nonce: Data([1, 2, 3, 4, 5, 6, 7, 8]),
        payload: Data([0xaa, 0xbb]))
    let encoded = try P2PProtocolCodec.encode(message)
    #expect(encoded.count == 86)
    #expect(Array(encoded.prefix(4)) == [5, 0, 0, 0])
    #expect(Array(encoded[52..<54]) == [0xca, 0x6c])
    #expect(Array(encoded[70..<76]) == [0xa4, 0x10, 1, 2, 3, 4])
    #expect(Array(encoded.suffix(2)) == [0xaa, 0xbb])
    #expect(try P2PProtocolCodec.decodeMessage(encoded) == message)
    let datagram = try P2PProtocolCodec.encodeDatagram(payload: encoded)
    #expect(Array(datagram.prefix(4)) == [6, 0, 0, 0])
    #expect(try P2PProtocolCodec.decodeDatagram(datagram) == encoded)
    #expect(throws: P2PProtocolError.malformedDatagram) {
        try P2PProtocolCodec.decodeDatagram(Data([6, 0, 0, 0]))
    }
    #expect(throws: P2PProtocolError.malformedDatagram) {
        try P2PProtocolCodec.decodeDatagram(Data([6, 1, 0, 0, 1]))
    }
    #expect(throws: WUSPTransportError.self) {
        try P2PProtocolCodec.decodeMessage(Data(repeating: 0, count: 83))
    }
}

@Test func p2pCoordinatorRegistersAndRequestsPeerListThroughTypeSixChannel() async throws {
    let channel = MockP2PCoordinatorChannel()
    let local = P2PEndpoint(address: Data([192, 168, 1, 20]), port: 51_820)
    let localPrivateKey = Data(repeating: 0x11, count: 32)
    let localPublicKey = try WireGuardKeyAgreement(privateKey: localPrivateKey).publicKey
    let coordinator = try P2PCoordinator(channel: channel,
                                         privateKey: localPrivateKey,
                                         publicKey: localPublicKey,
                                         serverPublicKey: Data(repeating: 0x22, count: 32),
                                         localEndpoint: local, candidates: [local])
    try await coordinator.start()
    for _ in 0..<50 {
        if await coordinator.snapshot.assignedID == 91 { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    let snapshot = await coordinator.snapshot
    #expect(snapshot.assignedID == 91)
    #expect(snapshot.observedEndpoint == P2PEndpoint(
        address: Data([8, 8, 4, 4]), port: 51_821))
    let sent = channel.sentMessages()
    #expect(sent.count >= 2)
    let registration = try P2PProtocolCodec.decodeMessage(sent[0])
    #expect(registration.subtype == P2PMessageSubtype.register)
    #expect(registration.publicKey == localPublicKey)
    #expect(registration.localPort == 51_820)
    #expect(P2PProtocolCodec.decodeCandidates(registration.payload).count == 1)
    #expect(try P2PProtocolCodec.decodeMessage(sent[1]).subtype == P2PMessageSubtype.peerList)
    await #expect(throws: P2PCoordinatorError.peerUnavailable) {
        try await coordinator.requestDirectConnection(to: 999)
    }
    await coordinator.close()
    await #expect(throws: P2PCoordinatorError.notRunning) {
        try await coordinator.requestDirectConnection(to: 999)
    }
}

@Test func p2pPunchMatchesWireLayoutAndAuthenticatesNonceAndSharedSecret() throws {
    let nonce = Data(hexEncoded: "0102030405060708")!
    let secret = Data(repeating: 0x5a, count: 32)
    let packet = try P2PPunchCodec.encode(nonce: nonce, sharedSecret: secret)
    #expect(packet.count == 41)
    #expect(packet[0] == P2PMessageSubtype.punchPacket)
    #expect(packet.subdata(in: 1..<9) == nonce)
    #expect(P2PPunchCodec.verify(packet, nonce: nonce, sharedSecret: secret))
    #expect(try P2PPunchCodec.encodeOuter(packet) == Data([6, 0, 0, 0]) + packet)
    let slicedPayload = try P2PProtocolCodec.encodeDatagram(payload: packet)
    let decodedSlice = try P2PProtocolCodec.decodeDatagram(slicedPayload)
    #expect(P2PPunchCodec.verify(decodedSlice, nonce: nonce, sharedSecret: secret))

    var changedTag = packet
    changedTag[40] ^= 0x80
    #expect(!P2PPunchCodec.verify(changedTag, nonce: nonce, sharedSecret: secret))
    #expect(!P2PPunchCodec.verify(packet, nonce: Data(repeating: 0, count: 8), sharedSecret: secret))
    #expect(!P2PPunchCodec.verify(packet, nonce: nonce, sharedSecret: Data(repeating: 0x33, count: 32)))
    #expect(throws: P2PPunchError.invalidNonce) {
        try P2PPunchCodec.encode(nonce: Data([1]), sharedSecret: secret)
    }
}

@Test func p2pPunchTargetsMatchGoOrderingAndBoundPortPrediction() {
    let privateLAN = P2PEndpoint(address: Data([192, 168, 1, 20]), port: 51820)
    let publicObserved = P2PEndpoint(address: Data([203, 0, 113, 8]), port: 50_000)
    let localLAN = P2PEndpoint(address: Data([10, 0, 0, 5]), port: 51820)
    let assignedOverlay = Data([100, 64, 0, 9])
    let targets = P2PPunchCodec.buildTargets(
        candidates: [privateLAN, privateLAN,
                     P2PEndpoint(address: assignedOverlay, port: 51820),
                     P2PEndpoint(address: Data([0, 0, 0, 0]), port: 51820)],
        observed: publicObserved, local: localLAN,
        assignedOverlayAddress: assignedOverlay
    )
    #expect(targets.count == 15)
    #expect(targets.count <= P2PPunchCodec.maximumPredictedTargets)
    #expect(Array(targets.prefix(3)) == [privateLAN, publicObserved, localLAN])
    #expect(targets[3] == P2PEndpoint(address: publicObserved.address, port: 50_001))
    #expect(targets[4] == P2PEndpoint(address: publicObserved.address, port: 49_999))
    #expect(!targets.contains(where: { $0.address == assignedOverlay }))
    #expect(Set(targets).count == targets.count)
}

@Test func tcpServiceScannerRejectsUnboundedOrNonLiteralTargets() async {
    await #expect(throws: TCPServiceScannerError.invalidAddress) {
        try await TCPServiceScanner.scan(address: "console.example.test")
    }
    await #expect(throws: TCPServiceScannerError.invalidPorts) {
        try await TCPServiceScanner.scan(address: "127.0.0.1", ports: [0])
    }
    await #expect(throws: TCPServiceScannerError.invalidPorts) {
        try await TCPServiceScanner.scan(address: "127.0.0.1", ports: [22, 22])
    }
    await #expect(throws: TCPServiceScannerError.tooManyPorts) {
        try await TCPServiceScanner.scan(address: "127.0.0.1", ports: Array(1...129).map(UInt16.init))
    }
    await #expect(throws: TCPServiceScannerError.invalidTimeout) {
        try await TCPServiceScanner.scan(address: "127.0.0.1", ports: [443], timeout: .infinity)
    }
}

@Test func tcpServiceScannerFindsAnOpenLoopbackPort() async throws {
    let (descriptor, port) = try makeLoopbackListener()
    defer { Darwin.close(descriptor) }
    let services = try await TCPServiceScanner.scan(address: "127.0.0.1", ports: [port], timeout: 1)
    #expect(services == [NetworkService(port: Int(port), kind: .other, isOpen: true)])
}

@Test func nativeICMPPingRepliesOnLoopbackAndBuildsPacketLossChartData() async throws {
    do {
        let latency = try await ICMPProbe.ping(address: "127.0.0.1", timeout: 1)
        #expect(latency > 0)
        let ipv6Latency = try await ICMPProbe.ping(address: "::1", timeout: 1)
        #expect(ipv6Latency > 0)
        let result = try await NativePingService.ping(target: "This Mac", address: "127.0.0.1",
                                                      sampleCount: 3, timeout: 1, interval: .zero)
        #expect(result.target == "This Mac")
        #expect(result.address == "127.0.0.1")
        #expect(result.reachable)
        #expect(result.packetLoss == 0)
        #expect(result.averageMS > 0)
        #expect(result.samples.count == 3)
        #expect(result.samples.allSatisfy { $0.reachable })
    } catch ICMPProbeError.timedOut {
        // Sandboxed test runners can suppress ICMP replies even for loopback.
        let result = try await NativePingService.ping(target: "This Mac", address: "127.0.0.1",
                                                      sampleCount: 1, timeout: 0.1, interval: .zero)
        #expect(!result.reachable)
        #expect(result.packetLoss == 100)
        #expect(result.samples == [PingSample(reachable: false)])
    }
}

@Test func nativeICMPPingValidatesAddressTimeoutAndSampleCount() async {
    await #expect(throws: ICMPProbeError.invalidAddress) {
        try await ICMPProbe.ping(address: "localhost")
    }
    await #expect(throws: ICMPProbeError.invalidTimeout) {
        try await ICMPProbe.ping(address: "127.0.0.1", timeout: .infinity)
    }
    await #expect(throws: NativePingError.invalidSampleCount) {
        try await NativePingService.ping(target: "", address: "127.0.0.1", sampleCount: 0)
    }
}

@Test func deviceIdentityIsStableAndPrivacyPreserving() {
    let first = DeviceIdentity.hashedIdentifier("  ABCD-1234  ")
    let second = DeviceIdentity.hashedIdentifier("abcd-1234")
    #expect(first == second)
    #expect(first.count == 64)
    #expect(first.allSatisfy { $0.isHexDigit })
}

@Test func portalTransportBoundsResponsesAndRequiresSameOriginTLS() async throws {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [StubURLProtocol.self]
    let origin = try #require(URL(string: "https://console.wantastic.app"))
    let transport = PortalHTTPTransport(origin: origin, configuration: configuration)
    let url = try #require(URL(string: "https://console.wantastic.app/oauth/device/code"))
    var request = URLRequest(url: url)
    request.httpMethod = "POST"

    StubURLProtocol.configure(status: 200, body: Data("ok".utf8), host: "console.wantastic.app", path: "/oauth/device/code")
    let response = try await transport.execute(request, maxBytes: 16)
    #expect(response.data == Data("ok".utf8))
    #expect(response.response.statusCode == 200)

    StubURLProtocol.configure(status: 200, body: Data(repeating: 0x41, count: 32), host: "console.wantastic.app", path: "/oauth/device/code")
    await #expect(throws: (any Error).self) {
        try await transport.execute(request, maxBytes: 8)
    }
}

@Test func consoleOriginValidationIncludesSchemeHostAndPort() throws {
    let origin = try #require(URL(string: "https://console.wantastic.app"))
    #expect(PortalHTTPTransport.matchesOrigin(URL(string: "https://console.wantastic.app/path"), origin: origin))
    #expect(PortalHTTPTransport.matchesOrigin(URL(string: "https://console.wantastic.app:443/path"), origin: origin))
    #expect(!PortalHTTPTransport.matchesOrigin(URL(string: "http://console.wantastic.app/path"), origin: origin))
    #expect(!PortalHTTPTransport.matchesOrigin(URL(string: "https://console.wantastic.app:8443/path"), origin: origin))
    #expect(!PortalHTTPTransport.matchesOrigin(URL(string: "https://other.wantastic.app/path"), origin: origin))
}

@Test func deviceAuthorizationRunsRFC8628RequestAndPollingFlow() async throws {
    let host = "auth-flow.wantastic.test"
    let baseURL = try #require(URL(string: "https://\(host)"))
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [StubURLProtocol.self]
    let transport = PortalHTTPTransport(origin: baseURL, configuration: configuration)
    let client = try DeviceAuthorizationClient(baseURL: baseURL, clientID: "wantastic-desktop-test", transport: transport)
    let response = Data("""
    {"device_code":"device-secret","user_code":"ABCD-EFGH",
     "verification_uri":"https://auth-flow.wantastic.test/device",
     "verification_uri_complete":"https://auth-flow.wantastic.test/device?user_code=ABCD-EFGH",
     "expires_in":300,"interval":5}
    """.utf8)
    StubURLProtocol.configure(status: 200, body: response, host: host, path: "/oauth/device/code")

    let authorization = try await client.begin(deviceID: "machine-fingerprint")

    #expect(authorization.userCode == "ABCD-EFGH")
    let startRequest = try #require(StubURLProtocol.lastRequest(host: host, path: "/oauth/device/code"))
    let startBody = try #require(StubURLProtocol.lastBody(host: host, path: "/oauth/device/code"))
    let startForm = try #require(URLComponents(string: "?\(String(decoding: startBody, as: UTF8.self))")?.queryItems)
    #expect(startRequest.httpMethod == "POST")
    #expect(startForm.first(where: { $0.name == "client_id" })?.value == "wantastic-desktop-test")
    #expect(startForm.first(where: { $0.name == "scope" })?.value == "openid profile email")
    #expect(startForm.first(where: { $0.name == "device_id" })?.value == "machine-fingerprint")

    StubURLProtocol.configure(status: 200, body: Data("{\"access_token\":\"access-secret\"}".utf8), host: host, path: "/oauth/token")
    let accessToken = try await client.poll(deviceCode: authorization.deviceCode)
    #expect(accessToken == "access-secret")
    let pollRequest = try #require(StubURLProtocol.lastRequest(host: host, path: "/oauth/token"))
    let pollBody = try #require(StubURLProtocol.lastBody(host: host, path: "/oauth/token"))
    let pollForm = try #require(URLComponents(string: "?\(String(decoding: pollBody, as: UTF8.self))")?.queryItems)
    #expect(pollRequest.httpMethod == "POST")
    #expect(pollForm.first(where: { $0.name == "device_code" })?.value == "device-secret")
    #expect(pollForm.first(where: { $0.name == "grant_type" })?.value == "urn:ietf:params:oauth:grant-type:device_code")
}

@Test func deviceRegistrationSendsSignedRequestAndDecryptsConfig() async throws {
    let host = "console.wantastic.app"
    let baseURL = try #require(URL(string: "https://\(host)"))
    let token = "test-access-token"
    let deviceID = String(repeating: "a", count: 64)
    let nonceValue: UInt64 = 0x0102030405060708
    let configText = """
    [Interface]
    PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Address = 10.0.0.2/32
    DNS = 10.0.0.1
    [Peer]
    PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Endpoint = wg.wantastic.app:51820
    AllowedIPs = 10.0.0.0/24
    PersistentKeepalive = 25
    """
    var littleEndianNonce = nonceValue.littleEndian
    var nonceBytes = Data(repeating: 0, count: 12)
    withUnsafeBytes(of: &littleEndianNonce) { nonceBytes.replaceSubrange(0..<8, with: $0) }
    let key = SymmetricKey(data: Data(SHA256.hash(data: Data(token.utf8))))
    let sealed = try ChaChaPoly.seal(Data(configText.utf8), using: key, nonce: ChaChaPoly.Nonce(data: nonceBytes))
    let responseBody = try JSONSerialization.data(withJSONObject: [
        "encrypted_config": (sealed.ciphertext + sealed.tag).base64EncodedString(),
        "token": "session-token",
        "server_url": "wss://hub.wantastic.app/wusp",
        "handoff_url": "https://\(host)/devices/claim",
    ])
    StubURLProtocol.configure(status: 201, body: responseBody, host: host, path: "/api/agent/credentials")
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [StubURLProtocol.self]
    let transport = PortalHTTPTransport(origin: baseURL, configuration: configuration)
    let client = try DeviceRegistrationClient(baseURL: baseURL, transport: transport, nonceGenerator: { nonceValue })

    let registered = try await client.register(accessToken: token, deviceID: deviceID)

    #expect(registered.configuration.addresses == ["10.0.0.2/32"])
    #expect(registered.configuration.allowedIPs == ["10.0.0.0/24"])
    #expect(registered.sessionToken == "session-token")
    #expect(registered.serverURL == "wss://hub.wantastic.app/wusp")
    #expect(registered.handoffURL?.absoluteString == "https://\(host)/devices/claim")
    let request = try #require(StubURLProtocol.lastRequest(host: host, path: "/api/agent/credentials"))
    #expect(request.httpMethod == "POST")
    #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer \(token)")
    #expect(request.value(forHTTPHeaderField: "x-wantastic-device") == deviceID)
    let timestamp = try #require(request.value(forHTTPHeaderField: "x-wantastic-ts"))
    #expect(request.value(forHTTPHeaderField: "x-wantastic-sig") == DeviceRegistrationClient.signature(timestamp: timestamp, deviceID: deviceID))
    let body = try #require(StubURLProtocol.lastBody(host: host, path: "/api/agent/credentials"))
    let payload = try #require((try? JSONSerialization.jsonObject(with: body)) as? [String: Any])
    #expect((payload["nonce"] as? NSNumber)?.uint64Value == nonceValue)
    #expect(payload["os"] as? String == "darwin")
}

@Test func registrationCipherMatchesPortalNonceAndKeyDerivation() throws {
    let token = "unit-test-access-token"
    let nonceValue: UInt64 = 0x0102030405060708
    var littleEndianNonce = nonceValue.littleEndian
    var nonceBytes = Data(repeating: 0, count: 12)
    withUnsafeBytes(of: &littleEndianNonce) { nonceBytes.replaceSubrange(0..<8, with: $0) }
    let nonce = try ChaChaPoly.Nonce(data: nonceBytes)
    let key = SymmetricKey(data: Data(SHA256.hash(data: Data(token.utf8))))
    let plaintext = Data("[Interface]\nAddress = 10.0.0.2/32\n".utf8)
    let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)
    let opened = try DeviceRegistrationClient.decrypt(sealed.ciphertext + sealed.tag, token: token, nonce: nonceValue)
    #expect(opened == plaintext)
}

@Test func registeredDeviceStoreScopesEncodesAndRemovesCredentials() throws {
    let credentials = MemoryCredentialPersistence()
    let store = RegisteredDeviceStore(credentials: credentials)
    let configuration = try WireGuardConfiguration.parse("""
    [Interface]
    PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Address = 10.0.0.2/32
    [Peer]
    PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Endpoint = wg.wantastic.app:51820
    AllowedIPs = 10.0.0.0/24
    """)
    let device = RegisteredDevice(configuration: configuration, sessionToken: "session-secret", serverURL: nil, handoffURL: nil)

    #expect(try store.load(consoleHost: "console.wantastic.app") == nil)
    try store.save(device, consoleHost: "Console.Wantastic.App")
    #expect(try store.load(consoleHost: "console.wantastic.app") == device)
    #expect(try store.load(consoleHost: "other.wantastic.app") == nil)
    try store.remove(consoleHost: "console.wantastic.app")
    #expect(try store.load(consoleHost: "console.wantastic.app") == nil)
}

@Test func registeredDeviceStoreRejectsCorruptDataAndInvalidHost() throws {
    let credentials = MemoryCredentialPersistence()
    let store = RegisteredDeviceStore(credentials: credentials)
    credentials.put(Data("not-json".utf8), account: "registered-device:console.wantastic.app")
    #expect(throws: RegisteredDeviceStoreError.invalidStoredData) {
        try store.load(consoleHost: "console.wantastic.app")
    }
    #expect(throws: RegisteredDeviceStoreError.invalidConsoleHost) {
        try store.load(consoleHost: "https://console.wantastic.app/path")
    }
}

@Test func manualWireGuardConfigurationStoreIsScopedAndSeparateFromLoginCredentials() throws {
    let credentials = MemoryCredentialPersistence()
    let registeredStore = RegisteredDeviceStore(credentials: credentials)
    let manualStore = ManualWireGuardConfigurationStore(credentials: credentials)
    let configuration = try WireGuardConfiguration.parse("""
    [Interface]
    PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Address = 10.0.0.2/32
    [Peer]
    PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Endpoint = wg.wantastic.app:51820
    AllowedIPs = 10.0.0.0/24
    """)
    let registered = RegisteredDevice(configuration: configuration, sessionToken: "session-secret",
                                      serverURL: nil, handoffURL: nil)

    try registeredStore.save(registered, consoleHost: "console.wantastic.app")
    try manualStore.save(configuration, consoleHost: "Console.Wantastic.App")
    #expect(try registeredStore.load(consoleHost: "console.wantastic.app") == registered)
    #expect(try manualStore.load(consoleHost: "console.wantastic.app") == configuration)
    #expect(try manualStore.load(consoleHost: "other.wantastic.app") == nil)
    #expect(throws: RegisteredDeviceStoreError.invalidConsoleHost) {
        try manualStore.save(configuration, consoleHost: "console.wantastic.app:443")
    }
    try manualStore.remove(consoleHost: "console.wantastic.app")
    #expect(try manualStore.load(consoleHost: "console.wantastic.app") == nil)
    #expect(try registeredStore.load(consoleHost: "console.wantastic.app") == registered)
}

@Test func serviceClassifierRecognizesRequestedServiceTypes() {
    #expect(ServiceClassifier.kind(for: 443) == .web)
    #expect(ServiceClassifier.kind(for: 3389) == .remoteDesktop)
    #expect(ServiceClassifier.kind(for: 22) == .secureShell)
    #expect(ServiceClassifier.kind(for: 5353) == .other)
}

@Test func serviceActionURLsAreTypedAndRestrictedToDiscoveredLiteralEndpoints() {
    let web = NetworkService(port: 8443, kind: .web, isOpen: true)
    let rdp = NetworkService(port: 3389, kind: .remoteDesktop, isOpen: true)
    let ssh = NetworkService(port: 22, kind: .secureShell, isOpen: true)
    let other = NetworkService(port: 5353, kind: .other, isOpen: true)

    #expect(ServiceActionURL.make(address: "192.0.2.8", service: web)?.absoluteString == "https://192.0.2.8:8443/")
    #expect(ServiceActionURL.make(address: "2001:db8::8", service: web)?.absoluteString == "https://[2001:db8::8]:8443/")
    #expect(ServiceActionURL.make(address: "192.0.2.8", service: rdp)?.absoluteString == "rdp://full%20address=s%3A192.0.2.8%3A3389")
    #expect(ServiceActionURL.make(address: "192.0.2.8", service: ssh)?.absoluteString == "ssh://192.0.2.8:22")
    #expect(ServiceActionURL.make(address: "example.com", service: web) == nil)
    #expect(ServiceActionURL.make(address: "192.0.2.8", service: other) == nil)
    #expect(ServiceActionURL.make(address: "192.0.2.8", service: NetworkService(port: 3389, kind: .web, isOpen: true)) == nil)
    #expect(ServiceActionURL.make(address: "192.0.2.8", service: NetworkService(port: 65_536, kind: .web, isOpen: true)) == nil)
    #expect(ServiceActionURL.make(address: "192.0.2.8", service: NetworkService(port: 443, kind: .web, isOpen: false)) == nil)
}

@Test func wuspRequestRoundTrips() throws {
    let request = WUSPRequest(id: 42, method: .set, paths: ["Device.Test.Value"], values: ["Device.Test.Value": "ready"])
    let data = try JSONEncoder().encode(request)
    #expect(try JSONDecoder().decode(WUSPRequest.self, from: data) == request)
}

@Test func offlineDeviceDefaultsRemainExplicit() {
    let device = DeviceRecord(id: "node-1", name: "Office", online: false)
    #expect(!device.online)
    #expect(device.address == nil)
    #expect(!device.direct)
}

@Test func p2pPeerDirectoryDecodesGoPeerListRecord() throws {
    var payload = Data([0, 0, 0, 1])
    payload.append(contentsOf: [0, 0, 0, 7]) // peer ID
    payload.append(contentsOf: Array(repeating: 0x11, count: 32)) // key
    payload.append(contentsOf: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 9]) // local IPv4-mapped
    payload.append(contentsOf: [0x1f, 0x90]) // local port 8080
    payload.append(contentsOf: Array(repeating: 0, count: 16)) // no observed endpoint
    payload.append(contentsOf: [0, 0])
    payload.append(0) // NAT type
    payload.append(3) // P2P-capable and exit-node capable
    payload.append(contentsOf: [10, 1, 2, 3]) // assigned IPv4

    let peers = try P2PPeerDirectoryCodec.decode(payload)
    #expect(peers.count == 1)
    #expect(peers[0].id == 7)
    #expect(peers[0].publicKey == Data(repeating: 0x11, count: 32))
    #expect(peers[0].localEndpoint == P2PEndpoint(address: Data([192, 168, 1, 9]), port: 8080))
    #expect(peers[0].observedEndpoint == nil)
    #expect(peers[0].p2pCapable)
    #expect(peers[0].offersExitNode)
    #expect(peers[0].assignedIPv4 == "10.1.2.3")
    #expect(peers[0].deviceRecord.address == "10.1.2.3")
}

@Test func p2pPeerDirectoryRejectsTruncatedAndOversizedLists() {
    #expect(throws: P2PPeerDirectoryError.malformed) {
        try P2PPeerDirectoryCodec.decode(Data([0, 0, 0]))
    }
    #expect(throws: P2PPeerDirectoryError.malformed) {
        try P2PPeerDirectoryCodec.decode(Data([0, 0, 0, 1]))
    }
    #expect(throws: P2PPeerDirectoryError.tooManyPeers) {
        try P2PPeerDirectoryCodec.decode(Data([0, 0, 0x10, 1]))
    }
    let record = makeP2PPeerListPayload(id: 7, publicKey: Data(repeating: 0x17, count: 32),
                                        assignedIPv4: [10, 0, 0, 7])
    var duplicateIDs = Data([0, 0, 0, 2])
    duplicateIDs.append(record.dropFirst(4))
    duplicateIDs.append(record.dropFirst(4))
    #expect(throws: P2PPeerDirectoryError.malformed) {
        try P2PPeerDirectoryCodec.decode(duplicateIDs)
    }
    var duplicateKeys = Data([0, 0, 0, 2])
    duplicateKeys.append(record.dropFirst(4))
    var secondRecord = Data(record.dropFirst(4))
    secondRecord[3] = 8 // distinct peer ID, duplicate WireGuard key
    duplicateKeys.append(secondRecord)
    #expect(throws: P2PPeerDirectoryError.malformed) {
        try P2PPeerDirectoryCodec.decode(duplicateKeys)
    }
}

@Test func tunnelControlExitNodePayloadsMatchGoLayout() throws {
    let key = String(repeating: "ab", count: 32)
    let selection = try TunnelControlCodec.encodeExitNodeSelection(publicKeyHex: key)
    #expect(selection.count == 33)
    #expect(selection[0] == 3)
    #expect(try TunnelControlCodec.decode(selection) == .requestExitNodeRouting(publicKey: Data(repeating: 0xab, count: 32)))
    #expect(try TunnelControlCodec.decode(TunnelControlCodec.encodeExitNodeSelection(publicKeyHex: nil)) == .requestExitNodeRouting(publicKey: nil))
    #expect(try TunnelControlCodec.decode(TunnelControlCodec.encodeExitNodeOffer(enabled: true)) == .setExitNodeOffer(enabled: true))
    let paddedOffer = try WireGuardPacketPadding.pad(TunnelControlCodec.encodeExitNodeOffer(enabled: true), mtu: 1420)
    #expect(try TunnelControlCodec.decodePaddedWireGuardPayload(paddedOffer) == .setExitNodeOffer(enabled: true))
    #expect(throws: TunnelControlError.malformed) {
        try TunnelControlCodec.decodePaddedWireGuardPayload(Data([4, 1, 0, 9]))
    }
    #expect(try TunnelControlCodec.decode(TunnelControlCodec.encodeExitNodeOffer(enabled: false)) == .setExitNodeOffer(enabled: false))
    #expect(throws: TunnelControlError.malformed) {
        try TunnelControlCodec.encodeExitNodeSelection(publicKeyHex: "abcd")
    }
    #expect(throws: TunnelControlError.malformed) {
        try TunnelControlCodec.decode(Data([4, 2]))
    }
}

@Test func tunnelControlServerRouteUpdatesPreserveOwnerAndRejectPublicRoutes() throws {
    let owner = Data(repeating: 0x33, count: 32)
    let applied = Data([7]) + owner + Data([1, 32, 172, 20, 4, 5])
    #expect(try TunnelControlCodec.decode(applied) == .applyLocalAccessRoutes(
        owner: owner, routes: [try TunnelIPv4Prefix("172.20.4.5/32")]
    ))
    #expect(try TunnelControlCodec.decode(Data([8]) + owner) == .removeLocalAccessRoutes(owner: owner))
    let publicRoute = Data([7]) + owner + Data([1, 24, 8, 8, 8, 0])
    #expect(throws: TunnelControlError.nonPrivateRoute) { try TunnelControlCodec.decode(publicRoute) }
    #expect(throws: TunnelControlError.malformed) { try TunnelControlCodec.decode(Data([8]) + owner + Data([0])) }
}

@Test func tunnelLocalAccessRouteTableAppliesUpdatesByOwnerAndWithdrawsCleanly() throws {
    let ownerA = Data(repeating: 0x31, count: 32)
    let ownerB = Data(repeating: 0x42, count: 32)
    let hostRoute = try TunnelIPv4Prefix("192.168.4.27/32")
    let siteRoute = try TunnelIPv4Prefix("10.24.0.0/16")
    var table = TunnelLocalAccessRouteTable()

    #expect(try table.apply(.applyLocalAccessRoutes(owner: ownerA, routes: [hostRoute])) == [hostRoute])
    #expect(try table.apply(.applyLocalAccessRoutes(owner: ownerA, routes: [hostRoute])) == nil)
    #expect(try table.apply(.applyLocalAccessRoutes(owner: ownerB, routes: [hostRoute, siteRoute])) == [siteRoute, hostRoute])
    #expect(try table.apply(.applyLocalAccessRoutes(owner: ownerA, routes: [])) == [siteRoute, hostRoute])
    #expect(try table.apply(.removeLocalAccessRoutes(owner: ownerB)) == [])
    #expect(try table.apply(.removeLocalAccessRoutes(owner: ownerB)) == nil)
    #expect(throws: TunnelControlError.malformed) {
        try table.apply(.applyLocalAccessRoutes(owner: Data([1]), routes: [hostRoute]))
    }
}

@Test func tunnelControlLocalRoutePayloadsMaskAndValidatePrivateIPv4() throws {
    let routes = try TunnelControlCodec.encodeLocalAccessAdvertisement(["192.168.10.17/24", "10.4.5.6/32", "192.168.10.0/24"])
    let fixtureURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("../../testdata/protocol/local_access_advertisement.hex")
    let fixtureHex = try String(contentsOf: fixtureURL, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let fixture = try #require(Data(hexEncoded: fixtureHex))
    #expect(routes == fixture)
    #expect(routes == Data([6, 2, 32, 10, 4, 5, 6, 24, 192, 168, 10, 0]))
    #expect(try TunnelControlCodec.decode(routes) == .setLocalAccessRoutes([
        try TunnelIPv4Prefix("10.4.5.6/32"), try TunnelIPv4Prefix("192.168.10.0/24")
    ]))
    let duplicateRoutes = Data([6, 2, 24, 10, 0, 0, 0, 24, 10, 0, 0, 0])
    #expect(try TunnelControlCodec.decode(duplicateRoutes) == .setLocalAccessRoutes([try TunnelIPv4Prefix("10.0.0.0/24")]))
    #expect(throws: TunnelControlError.nonPrivateRoute) {
        try TunnelControlCodec.encodeLocalAccessAdvertisement(["8.8.8.0/24"])
    }
    #expect(throws: TunnelControlError.malformed) {
        try TunnelControlCodec.decode(Data([7, 1, 2]))
    }
}

@Test func tunnelControlSnapshotRequiresBoundedCompletePrivateRoutes() throws {
    let owner = Data(repeating: 0x5a, count: 32)
    var snapshot = Data([9, 1])
    snapshot.append(owner)
    snapshot.append(contentsOf: [1, 24, 10, 20, 30, 0])
    #expect(try TunnelControlCodec.decode(snapshot) == .syncLocalAccessRoutes([
        (owner: owner, routes: [try TunnelIPv4Prefix("10.20.30.0/24")])
    ]))
    snapshot.append(0)
    #expect(throws: TunnelControlError.malformed) { try TunnelControlCodec.decode(snapshot) }
}

@Test func tunnelProviderRPCCodecBoundsAndVersionsAppExtensionMessages() throws {
    let request = TunnelProviderRPCRequest(
        request: WUSPRequest(id: 501, method: .get, paths: ["Device.DeviceInfo.HostName"])
    )
    let encodedRequest = try TunnelProviderRPCCodec.encode(request)
    #expect(try TunnelProviderRPCCodec.decodeRequest(encodedRequest) == request)

    let response = TunnelProviderRPCResponse(
        response: WUSPResponse(id: 501, values: ["Device.DeviceInfo.HostName": "studio"])
    )
    let encodedResponse = try TunnelProviderRPCCodec.encode(response)
    #expect(try TunnelProviderRPCCodec.decodeResponse(encodedResponse) == response)

    let snapshotRequest = TunnelProviderRPCRequest(operation: .p2pSnapshot)
    #expect(try TunnelProviderRPCCodec.decodeRequest(
        TunnelProviderRPCCodec.encode(snapshotRequest)) == snapshotRequest)
    let exitSelection = TunnelProviderRPCRequest(operation: .exitNodeSelection(peerID: 17))
    #expect(try TunnelProviderRPCCodec.decodeRequest(
        TunnelProviderRPCCodec.encode(exitSelection)) == exitSelection)
    let localAccess = TunnelProviderRPCRequest(operation: .localAccessEnable(
        routes: ["192.168.1.7/32", "10.20.30.0/24"]))
    #expect(try TunnelProviderRPCCodec.decodeRequest(
        TunnelProviderRPCCodec.encode(localAccess)) == localAccess)
    let peer = P2PPeerRecord(id: 17, publicKey: Data(repeating: 0x17, count: 32),
                             localEndpoint: P2PEndpoint(address: Data([192, 168, 1, 17]), port: 51820),
                             observedEndpoint: nil, natType: 2, p2pCapable: true,
                             offersExitNode: false, assignedIPv4: "10.255.255.17")
    let peerResponse = TunnelProviderRPCResponse(p2pPeers: [peer])
    #expect(try TunnelProviderRPCCodec.decodeResponse(
        TunnelProviderRPCCodec.encode(peerResponse)) == peerResponse)
    let acceptedResponse = TunnelProviderRPCResponse(accepted: true)
    #expect(try TunnelProviderRPCCodec.decodeResponse(
        TunnelProviderRPCCodec.encode(acceptedResponse)) == acceptedResponse)

    #expect(throws: TunnelProviderRPCError.unsupportedVersion) {
        try TunnelProviderRPCCodec.decodeRequest(try JSONEncoder().encode(
            TunnelProviderRPCRequest(request: WUSPRequest(id: 501, method: .get), version: 2)
        ))
    }
    #expect(throws: TunnelProviderRPCError.malformed) {
        try TunnelProviderRPCCodec.encode(TunnelProviderRPCRequest(
            request: WUSPRequest(id: 0, method: .get)
        ))
    }
    #expect(throws: TunnelProviderRPCError.malformed) {
        try TunnelProviderRPCCodec.encode(TunnelProviderRPCRequest(
            operation: .exitNodeSelection(peerID: 0)
        ))
    }
    #expect(throws: TunnelProviderRPCError.malformed) {
        try TunnelProviderRPCCodec.encode(TunnelProviderRPCRequest(
            operation: .localAccessEnable(routes: ["0.0.0.0/0"])
        ))
    }
    #expect(throws: TunnelProviderRPCError.tooLarge) {
        try TunnelProviderRPCCodec.decodeRequest(Data(repeating: 0x20,
                                                       count: TunnelProviderRPCCodec.maximumMessageBytes + 1))
    }
}

@Test func tunnelControllerPolicyRejectsOtherVPNProfiles() {
    #expect(TunnelProfilePolicy.isWantastic(providerBundleIdentifier: "app.wantastic.desktop.network-extension"))
    #expect(!TunnelProfilePolicy.isWantastic(providerBundleIdentifier: "com.example.other-vpn"))
    #expect(!TunnelProfilePolicy.isWantastic(providerBundleIdentifier: nil))
}

@Test func systemExtensionActivationMapsRestartRequirementExplicitly() {
    #expect(SystemExtensionActivationResult.from(requiresRestart: false) == .active)
    #expect(SystemExtensionActivationResult.from(requiresRestart: true) == .requiresRestart)
    #expect(TunnelControllerError.restartRequired.statusCopyKey == "restart_to_enable_extension")
}

@Test func menuBarConnectionStatusUsesLocalizedOnlineOfflineCopy() {
    #expect(ConnectionState.connected.trayStatusCopyKey == "online")
    #expect(ConnectionState.connecting.trayStatusCopyKey == "connecting")
    #expect(ConnectionState.disconnected.trayStatusCopyKey == "offline")
    #expect(ConnectionState.needsApproval.trayStatusCopyKey == "offline")
    #expect(ConnectionState.failed.trayStatusCopyKey == "offline")
}

@Test func mainConnectionStatusPreservesActionableExtensionApprovalState() {
    #expect(ConnectionState.mainStatusCopyKey(
        for: .needsApproval, profileReady: true,
        specificStatusCopyKey: "restart_to_enable_extension") == "restart_to_enable_extension")
    #expect(ConnectionState.mainStatusCopyKey(
        for: .needsApproval, profileReady: true,
        specificStatusCopyKey: nil) == "registered_offline")
    #expect(ConnectionState.mainStatusCopyKey(
        for: .disconnected, profileReady: false,
        specificStatusCopyKey: "restart_to_enable_extension") == "not_connected")
}

@Test func navigationCopyExistsForAllSupportedLanguages() {
    for language in AppLanguage.allCases {
        #expect(!AppCopy.text("devices", language: language).isEmpty)
        #expect(!AppCopy.text("settings", language: language).isEmpty)
    }
}

@Test func desktopInterfaceCopyExistsForAllSupportedLanguages() {
    let keys = AppCopy.allKeys
    for language in AppLanguage.allCases {
        for key in keys {
            #expect(AppCopy.hasTranslation(key, language: language), "Missing \(language.rawValue) translation for \(key)")
            #expect(AppCopy.text(key, language: language) != key)
        }
    }
}

@Test func wuspMethodIDsMatchWantasticWireContract() {
    #expect(WUSPMethod.allCases.map(\.wireID) == Array(UInt8(1)...UInt8(11)))
}

@Test func wuspOnBoardNotificationMatchesGoEventContract() throws {
    let serialNumber = String(repeating: "f", count: 64)
    let payload = try WUSPAgentEventCodec.encodeOnBoardRequest(
        id: 73, serialNumber: serialNumber, manufacturer: "Wantastic",
        productClass: "WantasticDesktopMac", softwareVersion: "Wantastic 1.0.0 (macOS 15.0.0)")
    let decoded = try WUSPTransportCodec.decodeRequest(payload)
    #expect(decoded.id == 73)
    #expect(decoded.method == .notify)
    #expect(decoded.objectCode == WUSPAgentEventCodec.deviceRootObjectCode)
    #expect(decoded.objectPath == nil)
    #expect(decoded.paths.isEmpty)
    #expect(decoded.metadata == [
        "event_type": "6",
        "manufacturer": "Wantastic",
        "product_class": "WantasticDesktopMac",
        "protocol_versions": "1.0.0",
        "serial_number": serialNumber,
        "software_version": "Wantastic 1.0.0 (macOS 15.0.0)",
    ])
    #expect(throws: WUSPTransportError.malformed) {
        try WUSPAgentEventCodec.encodeOnBoardRequest(
            id: 0, serialNumber: "serial", manufacturer: "Wantastic",
            productClass: "WantasticDesktopMac", softwareVersion: "1.0.0")
    }
    let goFixture = try #require(Data(hexEncoded:
        "0101072849000000000000000087be9ecd8eedcbafaa0100060a6576656e745f7479706501360c6d616e7566616374757265720957616e7461737469630d70726f647563745f636c6173731357616e7461737469634465736b746f704d61631170726f746f636f6c5f76657273696f6e7305312e302e300d73657269616c5f6e756d626572406666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666610736f6674776172655f76657273696f6e1e57616e74617374696320312e302e3020286d61634f532031352e302e3029"))
    #expect(payload == goFixture)
}

@Test func wuspValueChangeNotificationMatchesGoEventFixture() throws {
    let payload = try WUSPAgentEventCodec.encodeValueChange(
        id: 1, subscriptionID: "desktop-settings",
        parameterPath: "Device.DeviceInfo.FriendlyName", value: "Studio Mac")
    let goFixture = try #require(Data(hexEncoded:
        "0101073801000000000000000001e1a1cdcf97918bdd1f00a9cb88e1b0bea9fd0700030a6576656e745f7479706501320b706172616d5f76616c75650a53747564696f204d61630f737562736372697074696f6e5f6964106465736b746f702d73657474696e6773"))
    #expect(payload == goFixture)
}

@Test func macWUSPSupportsGoSubscriptionLifecycleAndValueChangeNotifications() throws {
    let credentials = MemoryCredentialPersistence()
    let events = MemoryWUSPEventRecorder()
    let agent = try MacWUSPAgentDispatcher(
        consoleHost: "console.example.test", credentials: credentials,
        eventSender: { events.append($0) },
        collector: {
            WUSPMessage(fields: [WUSPMessageField(
                path: "Device.DeviceInfo.HostName", value: .string("studio-mac"))])
        })

    let protocolResponse = try WUSPTransportCodec.decodeResponse(try #require(agent.handle(
        WUSPTransportCodec.encode(WUSPWireRequest(id: 90, method: .getSupportedProtocol)))))
    #expect(protocolResponse.protocolInfo?.methods.contains("Notify") == true)

    let goSubscribeFixture = try #require(Data(hexEncoded:
        "0101072807000000000000000087be9ecd8eedcbafaa0100040b777573705f616374696f6e097375627363726962650b777573705f7375625f6964106465736b746f702d73657474696e67730e777573705f7375625f7061746873124465766963652e446576696365496e666f2e0e777573705f7375625f74797065730132"))
    let subscribeResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(goSubscribeFixture)))
    #expect(subscribeResponse.error.isEmpty)
    #expect(subscribeResponse.metadata["wusp_sub_id"] == "desktop-settings")
    #expect(subscribeResponse.metadata["wusp_sub_status"] == "ok")

    let setFrame = try WUSPMessageCodec.encode(WUSPMessage(fields: [WUSPMessageField(
        path: "Device.DeviceInfo.FriendlyName", value: .string("Studio Mac"))]))
    let setResponse = try WUSPTransportCodec.decodeResponse(try #require(agent.handle(
        WUSPTransportCodec.encode(WUSPWireRequest(id: 92, method: .set, messageFrame: setFrame)))))
    #expect(setResponse.error.isEmpty)
    let eventPayload = try #require(events.payloads.first)
    let event = try WUSPTransportCodec.decodeRequest(eventPayload)
    #expect(event.id == 1)
    #expect(event.method == .notify)
    #expect(event.objectPath == nil)
    #expect(event.objectCode == WUSPAgentEventCodec.deviceInfoObjectCode)
    #expect(event.paths.isEmpty)
    #expect(event.pathCodes == [2_286_188_729_812_078_817])
    #expect(event.metadata == [
        "event_type": "2",
        "param_value": "Studio Mac",
        "subscription_id": "desktop-settings",
    ])

    let unsubscribe = WUSPWireRequest(id: 93, method: .notify, objectPath: "Device.", metadata: [
        "wusp_action": "unsubscribe", "wusp_sub_id": "desktop-settings",
    ])
    let unsubscribeResponse = try WUSPTransportCodec.decodeResponse(try #require(agent.handle(
        WUSPTransportCodec.encode(unsubscribe))))
    #expect(unsubscribeResponse.error.isEmpty)
    #expect(unsubscribeResponse.metadata["wusp_sub_status"] == "ok")

    let oversizedFilters = WUSPWireRequest(id: 94, method: .notify, objectPath: "Device.", metadata: [
        "wusp_action": "subscribe",
        "wusp_sub_id": "oversized",
        "wusp_sub_paths": (0..<129).map { "Device.DeviceInfo.\($0)." }.joined(separator: ","),
    ])
    let rejectedSubscription = try WUSPTransportCodec.decodeResponse(try #require(agent.handle(
        WUSPTransportCodec.encode(oversizedFilters))))
    #expect(rejectedSubscription.metadata["wusp.result.code"] == "WUSP_INVALID_REQUEST")

    _ = agent.handle(try WUSPTransportCodec.encode(WUSPWireRequest(
        id: 95, method: .set, messageFrame: setFrame)))
    #expect(events.payloads.count == 2)
    let untaggedEvent = try WUSPTransportCodec.decodeRequest(events.payloads[1])
    #expect(untaggedEvent.metadata["subscription_id"] == nil)
}

@Test func macWUSPOperateDispatchesValidatedCommandAndOnlyAdvertisesWhenConfigured() throws {
    let calls = MemoryWUSPEventRecorder()
    let input = WUSPMessage(fields: [WUSPMessageField(
        path: "Device.WiFi.Radio.1.Scan.SSID", value: .string("WantasticGuest"))])
    let output = WUSPMessage(fields: [WUSPMessageField(
        path: "Device.WiFi.Radio.1.Scan.Result", value: .string("complete"))])
    let inputFrame = try WUSPMessageCodec.encode(input)
    let agent = try MacWUSPAgentDispatcher(
        consoleHost: "console.example.test",
        operationHandler: { commandPath, receivedInput, metadata in
            #expect(commandPath == "Device.WiFi.Radio.1.Scan()")
            #expect(receivedInput == input)
            #expect(metadata["request-origin"] == "unit-test")
            calls.append(Data([1]))
            return output
        },
        collector: { WUSPMessage(fields: []) })

    let protocolResponse = try WUSPTransportCodec.decodeResponse(try #require(agent.handle(
        WUSPTransportCodec.encode(WUSPWireRequest(id: 701, method: .getSupportedProtocol)))))
    #expect(protocolResponse.protocolInfo?.methods.contains("Operate") == true)

    let request = WUSPWireRequest(
        id: 702, method: .operate, objectPath: "Device.WiFi.Radio.1.",
        messageFrame: inputFrame, metadata: [
            "wusp.operation_command_path": "Device.WiFi.Radio.1.Scan()",
            "request-origin": "unit-test",
        ])
    let response = try WUSPTransportCodec.decodeResponse(try #require(agent.handle(
        WUSPTransportCodec.encode(request))))
    #expect(response.error.isEmpty)
    #expect(response.objectPath == request.objectPath)
    #expect(try WUSPMessageCodec.decode(try #require(response.messageFrame)) == output)
    #expect(calls.payloads.count == 1)

    let mismatched = WUSPWireRequest(
        id: 703, method: .operate, objectPath: "Device.WiFi.Radio.2.",
        metadata: ["wusp.operation_command_path": "Device.WiFi.Radio.1.Scan()"])
    let rejected = try WUSPTransportCodec.decodeResponse(try #require(agent.handle(
        WUSPTransportCodec.encode(mismatched))))
    #expect(rejected.metadata["wusp.result.code"] == "WUSP_INVALID_REQUEST")
    #expect(calls.payloads.count == 1)

    let readOnlyAgent = try MacWUSPAgentDispatcher(
        consoleHost: "console.example.test", collector: { WUSPMessage(fields: []) })
    let readOnlyProtocol = try WUSPTransportCodec.decodeResponse(try #require(readOnlyAgent.handle(
        WUSPTransportCodec.encode(WUSPWireRequest(id: 704, method: .getSupportedProtocol)))))
    #expect(readOnlyProtocol.protocolInfo?.methods.contains("Operate") == false)
}

@Test func macWUSPAgentServesGoSelectorGetsAndFriendlyNameSet() throws {
    let credentials = MemoryCredentialPersistence()
    let collected = WUSPMessage(fields: [
        WUSPMessageField(path: "Device.RootDataModelVersion", value: .string("2.20")),
        WUSPMessageField(path: "Device.DeviceInfo.Manufacturer", value: .string("Apple")),
        WUSPMessageField(path: "Device.DeviceInfo.ProductClass", value: .string("Mac")),
        WUSPMessageField(path: "Device.DeviceInfo.HostName", value: .string("studio-mac")),
        WUSPMessageField(path: "Device.DeviceInfo.UpTime", value: .unsigned(123)),
        WUSPMessageField(path: "Device.DeviceInfo.MemoryStatus.Total", value: .unsigned(32_000)),
        WUSPMessageField(path: "Device.DeviceInfo.MemoryStatus.Free", value: .unsigned(16_000)),
        WUSPMessageField(path: "Device.DeviceInfo.NetworkProperties.TCPImplementation",
                         value: .list([.string("CUBIC")])),
        WUSPMessageField(path: "Device.Time.CurrentLocalTime", value: .timeNanoseconds(1_700_000_000_000_000_000)),
        WUSPMessageField(path: "Device.Time.LocalTimeZone", value: .string("Africa/Casablanca")),
        WUSPMessageField(path: "Device.IP.IPv4Capable", value: .bool(true)),
        WUSPMessageField(path: "Device.IP.IPv4Enable", value: .bool(true)),
        WUSPMessageField(path: "Device.IP.IPv4Status", value: .string("Enabled")),
        WUSPMessageField(path: "Device.IP.IPv6Capable", value: .bool(true)),
        WUSPMessageField(path: "Device.IP.IPv6Enable", value: .bool(true)),
        WUSPMessageField(path: "Device.IP.IPv6Status", value: .string("Enabled")),
        WUSPMessageField(path: "Device.IP.InterfaceNumberOfEntries", value: .unsigned(1)),
        WUSPMessageField(path: "Device.IP.Interface.1.Name", value: .string("en0")),
    ])
    let agent = try MacWUSPAgentDispatcher(consoleHost: "console.example.test",
                                           credentials: credentials,
                                           collector: { collected })

    let get = WUSPWireRequest(
        id: 801, method: .get, metadata: ["wusp.request_sequence": "51"],
        pathCodes: [8_582_781_017_805_368_456], pathInstances: [[]])
    let getPayload = try WUSPTransportCodec.encode(get)
    let getResponsePayload = try #require(agent.handle(getPayload))
    let getResponse = try WUSPTransportCodec.decodeResponse(getResponsePayload)
    #expect(getResponse.id == get.id)
    #expect(getResponse.method == .get)
    #expect(getResponse.error.isEmpty)
    #expect(getResponse.metadata["wusp.result.state"] == "success")
    #expect(getResponse.metadata["wusp.result.code"] == "WUSP_OK")
    #expect(getResponse.metadata["wusp.response_sequence"] == "51")
    let getMessage = try WUSPMessageCodec.decode(try #require(getResponse.messageFrame))
    #expect(getMessage.fields == [
        WUSPMessageField(path: "Device.DeviceInfo.HostName", value: .string("studio-mac"))
    ])

    let selectorFixtures: [(UInt64, WUSPMessageField)] = [
        (5_326_957_525_806_991_164, collected.fields[0]),
        (6_912_254_594_259_689_904, collected.fields[2]),
        (17_617_958_749_237_003_661, collected.fields[4]),
        (5_441_735_910_175_514_088, collected.fields[5]),
        (13_753_903_917_177_893_348, collected.fields[6]),
        (16_573_842_583_776_841_923, collected.fields[7]),
        (7_470_374_252_734_745_033, collected.fields[8]),
        (18_096_091_504_730_752_484, collected.fields[9]),
        (13_545_392_493_760_057_785, collected.fields[10]),
        (16_312_803_732_236_064_188, collected.fields[11]),
        (13_501_531_255_845_275_141, collected.fields[12]),
        (12_197_594_044_343_824_307, collected.fields[13]),
        (11_270_614_977_237_238_594, collected.fields[14]),
        (14_870_596_540_097_983_643, collected.fields[15]),
    ]
    for (index, fixture) in selectorFixtures.enumerated() {
        let selectorRequest = WUSPWireRequest(
            id: UInt64(820 + index), method: .get, pathCodes: [fixture.0], pathInstances: [[]])
        let selectorResponse = try WUSPTransportCodec.decodeResponse(try #require(agent.handle(
            WUSPTransportCodec.encode(selectorRequest))))
        #expect(selectorResponse.error.isEmpty)
        let selectorMessage = try WUSPMessageCodec.decode(try #require(selectorResponse.messageFrame))
        #expect(selectorMessage.fields == [fixture.1])
    }

    let instancesRequest = WUSPWireRequest(
        id: 804, method: .getInstances,
        pathCodes: [12_120_280_007_176_993_584], pathInstances: [[]])
    let instancesResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(instancesRequest))))
    #expect(instancesResponse.error.isEmpty)
    #expect(instancesResponse.paths == ["Device.IP.Interface.1."])

    let protocolRequest = WUSPWireRequest(id: 805, method: .getSupportedProtocol)
    let protocolResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(protocolRequest))))
    #expect(protocolResponse.protocolInfo == WUSPProtocolInfo(
        name: "wantastic-wusp-over-wireguard", version: 1,
        methods: ["Get", "Set", "Delete", "GetInstances", "GetSupportedDM", "GetSupportedProtocol"],
        compression: ["nested-message-lz4"],
        controlTransport: "wireguard-noise-fragmented-datagram+request-replay-v1",
        transferTransport: "", maxControlPayload: 1_200,
        recommendedChunkSize: 1_120, tunnelOnly: true, reliableTransfer: false))

    let supportedDMRequest = WUSPWireRequest(
        id: 807, method: .getSupportedDM, paths: ["Device.DeviceInfo."])
    let supportedDMResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(supportedDMRequest))))
    #expect(supportedDMResponse.error.isEmpty)
    #expect(supportedDMResponse.supportedDataModel?.objects.map(\.path) == ["Device.DeviceInfo."])
    #expect(supportedDMResponse.supportedDataModel?.params.map(\.path) == [
        "Device.DeviceInfo.FriendlyName", "Device.DeviceInfo.ProvisioningCode",
        "Device.DeviceInfo.HostName",
        "Device.DeviceInfo.Manufacturer", "Device.DeviceInfo.ModelName",
        "Device.DeviceInfo.ProductClass", "Device.DeviceInfo.SoftwareVersion",
        "Device.DeviceInfo.UpTime", "Device.DeviceInfo.MemoryStatus.Total",
        "Device.DeviceInfo.MemoryStatus.Free",
        "Device.DeviceInfo.NetworkProperties.TCPImplementation",
    ])
    let leafDMRequest = WUSPWireRequest(
        id: 808, method: .getSupportedDM,
        paths: ["Device.DeviceInfo.Manufacturer"])
    let leafDMResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(leafDMRequest))))
    #expect(leafDMResponse.supportedDataModel?.objects.map(\.path) == ["Device.DeviceInfo."])
    #expect(leafDMResponse.supportedDataModel?.params.map(\.path) == [
        "Device.DeviceInfo.Manufacturer",
    ])

    let setFrame = try WUSPMessageCodec.encode(WUSPMessage(fields: [
        WUSPMessageField(path: "Device.DeviceInfo.FriendlyName", value: .string("Studio Mac"))
    ]))
    let set = WUSPWireRequest(id: 802, method: .set, messageFrame: setFrame)
    let setResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(set))))
    #expect(setResponse.id == set.id)
    #expect(setResponse.method == .set)
    #expect(setResponse.error.isEmpty)
    #expect(setResponse.metadata["wusp.result.code"] == "WUSP_OK")

    let friendlyNameGet = WUSPWireRequest(
        id: 803, method: .get, pathCodes: [2_286_188_729_812_078_817],
        pathInstances: [[]])
    let friendlyNameResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(friendlyNameGet))))
    let friendlyMessage = try WUSPMessageCodec.decode(
        try #require(friendlyNameResponse.messageFrame))
    #expect(friendlyMessage.fields == [
        WUSPMessageField(path: "Device.DeviceInfo.FriendlyName", value: .string("Studio Mac"))
    ])

    let readOnlyFrame = try WUSPMessageCodec.encode(WUSPMessage(fields: [
        WUSPMessageField(path: "Device.DeviceInfo.HostName", value: .string("changed-host"))
    ]))
    let readOnlySet = WUSPWireRequest(id: 804, method: .set, messageFrame: readOnlyFrame)
    let rejected = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(readOnlySet))))
    #expect(rejected.error.contains("unsupported"))
    #expect(rejected.metadata["wusp.result.code"] == "WUSP_UNSUPPORTED")

    // ProvisioningCode and FriendlyName match the Go host backend's persisted
    // DeviceInfo settings and are deliberately stored in the Keychain.
    let provisioningSetFrame = try WUSPMessageCodec.encode(WUSPMessage(fields: [
        WUSPMessageField(path: "Device.DeviceInfo.FriendlyName", value: .string("Studio Mac")),
        WUSPMessageField(path: "Device.DeviceInfo.ProvisioningCode", value: .string("setup-42"))
    ]))
    let provisioningSet = WUSPWireRequest(id: 809, method: .set, messageFrame: provisioningSetFrame)
    #expect(try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(provisioningSet)))).error.isEmpty)
    let provisioningGet = WUSPWireRequest(
        id: 810, method: .get, pathCodes: [8_620_908_333_006_359_769], pathInstances: [[]])
    let provisioningResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(provisioningGet))))
    let provisioningMessage = try WUSPMessageCodec.decode(try #require(provisioningResponse.messageFrame))
    #expect(provisioningMessage.fields == [WUSPMessageField(
        path: "Device.DeviceInfo.ProvisioningCode", value: .string("setup-42"))])

    let clearProvisioningFrame = try WUSPMessageCodec.encode(WUSPMessage(fields: [WUSPMessageField(
        path: "Device.DeviceInfo.ProvisioningCode", value: .string("")
    )]))
    let clearProvisioning = WUSPWireRequest(id: 813, method: .set,
                                            messageFrame: clearProvisioningFrame)
    #expect(try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(clearProvisioning)))).error.isEmpty)
    let clearedProvisioningResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(provisioningGet))))
    #expect(clearedProvisioningResponse.error == "path not found: Device.DeviceInfo.ProvisioningCode")

    let restoreProvisioningFrame = try WUSPMessageCodec.encode(WUSPMessage(fields: [WUSPMessageField(
        path: "Device.DeviceInfo.ProvisioningCode", value: .string("setup-42")
    )]))
    #expect(try WUSPTransportCodec.decodeResponse(try #require(agent.handle(
        WUSPTransportCodec.encode(WUSPWireRequest(id: 814, method: .set,
                                                   messageFrame: restoreProvisioningFrame))))).error.isEmpty)

    let deleteFriendlyName = WUSPWireRequest(id: 811, method: .delete,
                                              paths: ["Device.DeviceInfo.FriendlyName"])
    #expect(try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(deleteFriendlyName)))).error.isEmpty)
    let defaultNameResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(friendlyNameGet))))
    let defaultNameMessage = try WUSPMessageCodec.decode(try #require(defaultNameResponse.messageFrame))
    #expect(defaultNameMessage.fields == [WUSPMessageField(
        path: "Device.DeviceInfo.FriendlyName", value: .string("studio-mac"))])

    let clearFriendlyNameFrame = try WUSPMessageCodec.encode(WUSPMessage(fields: [WUSPMessageField(
        path: "Device.DeviceInfo.FriendlyName", value: .string("")
    )]))
    let clearFriendlyName = WUSPWireRequest(id: 815, method: .set,
                                            messageFrame: clearFriendlyNameFrame)
    #expect(try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(clearFriendlyName)))).error.isEmpty)
    let clearedNameResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(friendlyNameGet))))
    let clearedNameMessage = try WUSPMessageCodec.decode(try #require(clearedNameResponse.messageFrame))
    #expect(clearedNameMessage.fields == [WUSPMessageField(
        path: "Device.DeviceInfo.FriendlyName", value: .string("studio-mac"))])

    let deleteProvisioning = WUSPWireRequest(
        id: 812, method: .delete, pathCodes: [8_620_908_333_006_359_769], pathInstances: [[]])
    #expect(try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(deleteProvisioning)))).error.isEmpty)
    #expect(try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(provisioningGet)))).error ==
        "path not found: Device.DeviceInfo.ProvisioningCode")

    // The macOS model has no mutable TR-181 instances, default executable commands,
    // controller-managed subscriptions, or authorized file-transfer handlers.
    // Those methods stay absent from capabilities and fail closed.
    for method: WUSPMethod in [.add, .operate, .notify, .upload, .download] {
        let unsupportedMethod = WUSPWireRequest(
            id: 810 + UInt64(method.wireID), method: method,
            objectPath: method == .operate ? "Device." : nil)
        let response = try WUSPTransportCodec.decodeResponse(
            try #require(agent.handle(WUSPTransportCodec.encode(unsupportedMethod))))
        #expect(response.id == unsupportedMethod.id)
        #expect(response.method == method)
        #expect(response.metadata["wusp.result.code"] == "WUSP_UNSUPPORTED")
    }
    let unsupportedDelete = WUSPWireRequest(id: 819, method: .delete,
                                             paths: ["Device.DeviceInfo.HostName"])
    let unsupportedDeleteResponse = try WUSPTransportCodec.decodeResponse(
        try #require(agent.handle(WUSPTransportCodec.encode(unsupportedDelete))))
    #expect(unsupportedDeleteResponse.metadata["wusp.result.code"] == "WUSP_UNSUPPORTED")

    #expect(agent.handle(Data([0xff])) == nil)
}

@Test func tunnelProviderRPCDispatchReturnsWUSPResponseAndStableErrors() async throws {
    let request = WUSPRequest(id: 44, method: .get, paths: ["Device.DeviceInfo.HostName"])
    let encodedRequest = try TunnelProviderRPCCodec.encode(TunnelProviderRPCRequest(request: request))
    let success = TunnelProviderRPCDispatcher(
        transport: WUSPTransportStub(response: WUSPResponse(id: 44, values: ["name": "Studio"])),
        deviceID: "peer")
    let encodedResponse = try #require(await success.dispatch(encodedRequest))
    #expect(try TunnelProviderRPCCodec.decodeResponse(encodedResponse).response?.values == ["name": "Studio"])

    let unavailable = TunnelProviderRPCDispatcher(transport: WUSPTransportFailure(), deviceID: "peer")
    let failedResponse = try #require(await unavailable.dispatch(encodedRequest))
    #expect(try TunnelProviderRPCCodec.decodeResponse(failedResponse).errorCode == "request_failed")
    let malformedResponse = try #require(await success.dispatch(Data([0xff])))
    #expect(try TunnelProviderRPCCodec.decodeResponse(malformedResponse).errorCode == "invalid_request")
    let unsupported = try TunnelProviderRPCCodec.encode(
        TunnelProviderRPCRequest(operation: .p2pSnapshot))
    let unsupportedResponse = try #require(await success.dispatch(unsupported))
    #expect(try TunnelProviderRPCCodec.decodeResponse(unsupportedResponse).errorCode == "p2p_unavailable")

    let peerPrivateKey = Data(repeating: 0x33, count: 32)
    let fixtureKey = try WireGuardKeyAgreement(privateKey: peerPrivateKey).publicKey
    let localPrivateKey = Data(repeating: 0x11, count: 32)
    let localPublicKey = try WireGuardKeyAgreement(privateKey: localPrivateKey).publicKey
    let nonce = Data(hexEncoded: "0102030405060708")!
    let sharedSecret = try WireGuardKeyAgreement(privateKey: localPrivateKey)
        .sharedSecret(with: fixtureKey)
    let peerPunch = try P2PPunchCodec.encode(nonce: nonce, sharedSecret: sharedSecret)
    let peerPunchOuter = try P2PPunchCodec.encodeOuter(peerPunch)
    let peerCandidate = P2PEndpoint(address: Data([192, 168, 1, 44]), port: 51_820)
    var relayPayload = Data([10, 255, 255, 123])
    relayPayload.append(P2PProtocolCodec.encodeCandidates([peerCandidate]))
    let coordinatorChannel = MockP2PCoordinatorChannel(
        peerListPayload: makeP2PPeerListPayload(id: 123, publicKey: fixtureKey,
                                                assignedIPv4: [10, 255, 255, 123], offersExitNode: true),
        punchResponse: peerPunchOuter)
    let coordinator = try P2PCoordinator(channel: coordinatorChannel,
                                         privateKey: localPrivateKey,
                                         publicKey: localPublicKey,
                                         localEndpoint: P2PEndpoint(address: Data([192, 168, 1, 20]), port: 51820))
    let pathCandidates = await coordinator.authenticatedPathCandidates
    try await coordinator.start()
    for _ in 0..<50 {
        if await coordinator.snapshot.peers.count == 1 { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    let tunnelControlSender = MockTunnelControlPayloadSender()
    let p2pDispatcher = TunnelProviderRPCDispatcher(transport: WUSPTransportStub(response: WUSPResponse(id: 1)),
                                                    deviceID: "peer", p2pCoordinator: coordinator,
                                                    tunnelControlSender: tunnelControlSender)
    let peersData = try #require(await p2pDispatcher.dispatch(unsupported))
    let peers = try #require(TunnelProviderRPCCodec.decodeResponse(peersData).p2pPeers)
    #expect(peers.count == 1)
    #expect(peers[0].publicKey == fixtureKey)
    #expect(peers[0].offersExitNode)
    #expect(peers[0].assignedIPv4 == "10.255.255.123")
    #expect(!peers[0].udpReachable)
    let punchRequest = try TunnelProviderRPCCodec.encode(
        TunnelProviderRPCRequest(operation: .p2pPunch(peerID: 123)))
    let punchData = try #require(await p2pDispatcher.dispatch(punchRequest))
    #expect(try TunnelProviderRPCCodec.decodeResponse(punchData).accepted == true)
    let selectExitNode = try TunnelProviderRPCCodec.encode(
        TunnelProviderRPCRequest(operation: .exitNodeSelection(peerID: 123)))
    let selectedResponse = try #require(await p2pDispatcher.dispatch(selectExitNode))
    #expect(try TunnelProviderRPCCodec.decodeResponse(selectedResponse).accepted == true)
    #expect(try TunnelControlCodec.decode(try #require(tunnelControlSender.sentPayloads.last)) ==
            .requestExitNodeRouting(publicKey: fixtureKey))
    let clearExitNode = try TunnelProviderRPCCodec.encode(
        TunnelProviderRPCRequest(operation: .exitNodeSelection(peerID: nil)))
    let clearedResponse = try #require(await p2pDispatcher.dispatch(clearExitNode))
    #expect(try TunnelProviderRPCCodec.decodeResponse(clearedResponse).accepted == true)
    #expect(try TunnelControlCodec.decode(try #require(tunnelControlSender.sentPayloads.last)) ==
            .requestExitNodeRouting(publicKey: nil))

    let nonOfferingCoordinator = try P2PCoordinator(
        channel: MockP2PCoordinatorChannel(peerListPayload: makeP2PPeerListPayload(
            id: 124, publicKey: fixtureKey, assignedIPv4: [10, 255, 255, 124])),
        privateKey: localPrivateKey, publicKey: localPublicKey,
        localEndpoint: P2PEndpoint(address: Data([192, 168, 1, 20]), port: 51820))
    try await nonOfferingCoordinator.start()
    for _ in 0..<50 {
        if await nonOfferingCoordinator.snapshot.peers.count == 1 { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    let guardedDispatcher = TunnelProviderRPCDispatcher(
        transport: WUSPTransportStub(response: WUSPResponse(id: 1)), deviceID: "peer",
        p2pCoordinator: nonOfferingCoordinator, tunnelControlSender: tunnelControlSender)
    let deniedResponse = try #require(await guardedDispatcher.dispatch(
        TunnelProviderRPCCodec.encode(TunnelProviderRPCRequest(operation: .exitNodeSelection(peerID: 124)))))
    #expect(try TunnelProviderRPCCodec.decodeResponse(deniedResponse).errorCode == "peer_not_exit_node")
    #expect(tunnelControlSender.sentPayloads.count == 2)
    await nonOfferingCoordinator.close()
    let relay = try P2PMessage(
        subtype: P2PMessageSubtype.punchRelay, publicKey: fixtureKey,
        localAddress: Data(repeating: 0, count: 10) + Data([0xff, 0xff, 192, 168, 1, 44]),
        localPort: 51_820,
        observedAddress: Data(repeating: 0, count: 10) + Data([0xff, 0xff, 8, 8, 4, 4]),
        observedPort: 51_821, targetID: 123, nonce: nonce, payload: relayPayload)
    coordinatorChannel.emit(try P2PProtocolCodec.encode(relay))
    for _ in 0..<100 {
        if await coordinator.snapshot.authenticatedReachablePeerIDs.contains(123) { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    let reachability = await coordinator.snapshot
    #expect(reachability.authenticatedReachablePeerIDs == [123])
    var pathIterator = pathCandidates.makeAsyncIterator()
    let pathCandidate = await pathIterator.next()
    #expect(pathCandidate?.peer.id == 123)
    let validTargets = P2PPunchCodec.buildTargets(
        candidates: [peerCandidate],
        observed: P2PEndpoint(address: Data([8, 8, 4, 4]), port: 51_821),
        local: P2PEndpoint(address: Data([192, 168, 1, 44]), port: 51_820),
        assignedOverlayAddress: Data([10, 255, 255, 123]))
    #expect(pathCandidate.map { validTargets.contains($0.endpoint) } == true)
    await pathCandidate?.channel.close()
    let updatedPeersData = try #require(await p2pDispatcher.dispatch(unsupported))
    let updatedPeers = try #require(TunnelProviderRPCCodec.decodeResponse(updatedPeersData).p2pPeers)
    #expect(updatedPeers[0].udpReachable)
    #expect(!updatedPeers[0].deviceRecord.direct)
    #expect(updatedPeers[0].deviceRecord.p2pReachable)
    await coordinator.close()
}

@Test func macWUSPControlRetriesReplayMutationResponseAndRejectIdentityReuse() async throws {
    let invocations = WUSPTestInvocationCounter()
    let agent = try MacWUSPAgentDispatcher(
        consoleHost: "console.example.test",
        credentials: MemoryCredentialPersistence(),
        operationHandler: { _, _, _ in
            invocations.increment()
            Thread.sleep(forTimeInterval: 0.05)
            return nil
        })

    let request = WUSPWireRequest(
        id: 9001, method: .operate, objectPath: "Device.DeviceInfo.",
        metadata: [
            "wusp.request_sequence": "41",
            "wusp.operation_command_path": "Device.DeviceInfo.Reboot()",
            "wusp.response_max_control_payload": "800",
        ])
    let firstPayload = try WUSPTransportCodec.encode(request)
    async let first = agent.handleAsync(firstPayload)
    async let duplicate = agent.handleAsync(firstPayload)
    let (firstResponse, duplicateResponse) = await (first, duplicate)
    #expect(firstResponse != nil)
    #expect(firstResponse == duplicateResponse)
    #expect(invocations.value == 1)

    // The response budget is transport policy, not action identity, and Go
    // deliberately excludes it from the replay fingerprint.
    var sameAction = request
    sameAction.metadata["wusp.response_max_control_payload"] = "1000"
    let replay = try #require(await agent.handleAsync(WUSPTransportCodec.encode(sameAction)))
    #expect(replay == firstResponse)
    #expect(invocations.value == 1)

    var changedAction = request
    changedAction.metadata["wusp.operation_command_path"] = "Device.DeviceInfo.FactoryReset()"
    let conflict = try WUSPTransportCodec.decodeResponse(try #require(
        await agent.handleAsync(WUSPTransportCodec.encode(changedAction))))
    #expect(conflict.metadata["wusp.result.code"] == "WUSP_AGENT_ERROR")
    #expect(conflict.error.contains("reused with different action data"))
    #expect(invocations.value == 1)

    var nextSequence = request
    nextSequence.metadata["wusp.request_sequence"] = "42"
    _ = try #require(await agent.handleAsync(WUSPTransportCodec.encode(nextSequence)))
    #expect(invocations.value == 2)
}

@Test func macWUSPAsyncOperationHandlerSupportsOnlyInstalledNativeCommands() async throws {
    let invoked = WUSPTestInvocationCounter()
    let agent = try MacWUSPAgentDispatcher(
        consoleHost: "console.example.test",
        credentials: MemoryCredentialPersistence(),
        asyncOperationHandler: { commandPath, _, _ in
            guard commandPath == "Device.Reboot()" else {
                throw MacWUSPOperationError.unsupported
            }
            invoked.increment()
            return nil
        })
    let request = WUSPWireRequest(
        id: 9002, method: .operate, objectPath: "Device.",
        metadata: ["wusp.operation_command_path": "Device.Reboot()"])
    let response = try WUSPTransportCodec.decodeResponse(try #require(
        await agent.handleAsync(WUSPTransportCodec.encode(request))))
    #expect(response.error.isEmpty)
    #expect(invoked.value == 1)

    let unsupported = WUSPWireRequest(
        id: 9003, method: .operate, objectPath: "Device.",
        metadata: ["wusp.operation_command_path": "Device.FactoryReset()"])
    let rejected = try WUSPTransportCodec.decodeResponse(try #require(
        await agent.handleAsync(WUSPTransportCodec.encode(unsupported))))
    #expect(rejected.metadata["wusp.result.code"] == "WUSP_UNSUPPORTED")
    #expect(invoked.value == 1)

    let protocolRequest = WUSPWireRequest(id: 9004, method: .getSupportedProtocol)
    let protocolResponse = try WUSPTransportCodec.decodeResponse(try #require(
        await agent.handleAsync(WUSPTransportCodec.encode(protocolRequest))))
    #expect(protocolResponse.protocolInfo?.methods.contains("Operate") == true)
}

@Test func macWUSPFactoryResetClearsOnlyCurrentTenantCredentials() async throws {
    let credentials = MemoryCredentialPersistence()
    let ownedAccounts = [
        "registered-device:console.example.test",
        "manual-wireguard:console.example.test",
        "wusp-settings:console.example.test:friendly-name",
        "wusp-settings:console.example.test:provisioning-code",
    ]
    for account in ownedAccounts {
        try credentials.write(Data("secret".utf8), account: account)
    }
    try credentials.write(Data("other tenant".utf8),
                          account: "registered-device:other.example.test")

    let agent = try MacWUSPAgentDispatcher(
        consoleHost: "console.example.test", credentials: credentials,
        asyncOperationHandler: { commandPath, _, _ in
            guard commandPath == "Device.FactoryReset()" else {
                throw MacWUSPOperationError.unsupported
            }
            return nil
        })
    let request = WUSPWireRequest(
        id: 9005, method: .operate, objectPath: "Device.",
        metadata: ["wusp.operation_command_path": "Device.FactoryReset()"])
    let response = try WUSPTransportCodec.decodeResponse(try #require(
        await agent.handleAsync(WUSPTransportCodec.encode(request))))
    #expect(response.error.isEmpty)
    for account in ownedAccounts {
        #expect(try credentials.read(account: account) == nil)
    }
    #expect(try credentials.read(account: "registered-device:other.example.test") ==
            Data("other tenant".utf8))
}

private actor MockProviderLocalAccessManager: TunnelProviderLocalAccessManaging {
    private(set) var selectedRoutes: [String] = []
    private(set) var enabled = false

    func enable(routes: [String]) async throws {
        selectedRoutes = routes
        enabled = true
    }

    func disable() async throws { enabled = false }
    func isEnabled() async -> Bool { enabled }
}

@Test func tunnelProviderRPCControlsOptInLocalAccessRoutes() async throws {
    let manager = MockProviderLocalAccessManager()
    let dispatcher = TunnelProviderRPCDispatcher(
        transport: WUSPTransportStub(response: WUSPResponse(id: 1)),
        deviceID: "peer", localAccessManager: manager)
    let enable = try TunnelProviderRPCCodec.encode(TunnelProviderRPCRequest(
        operation: .localAccessEnable(routes: ["192.168.1.7/32"])))
    let enabledData = try #require(await dispatcher.dispatch(enable))
    #expect(try TunnelProviderRPCCodec.decodeResponse(enabledData).accepted == true)
    #expect(await manager.selectedRoutes == ["192.168.1.7/32"])

    let status = try TunnelProviderRPCCodec.encode(TunnelProviderRPCRequest(
        operation: .localAccessStatus))
    let statusData = try #require(await dispatcher.dispatch(status))
    #expect(try TunnelProviderRPCCodec.decodeResponse(statusData).accepted == true)

    let disable = try TunnelProviderRPCCodec.encode(TunnelProviderRPCRequest(
        operation: .localAccessDisable))
    let disabledData = try #require(await dispatcher.dispatch(disable))
    #expect(try TunnelProviderRPCCodec.decodeResponse(disabledData).accepted == true)
    #expect(await manager.isEnabled() == false)
}

@Test func packetFlowDirectRouteFailureFallsBackToHubRelay() async throws {
    let recorder = PacketFlowRouteRecorder()
    let packet = Data([0x45, 0, 0, 20])
    try await PacketFlowRouteSender.send(
        packet,
        directly: { _ in
            await recorder.directAttempted()
            throw URLError(.cannotConnectToHost)
        },
        relay: { relayPacket in
            #expect(relayPacket == packet)
            await recorder.relayAttempted()
        },
        onDirectFailure: { await recorder.directDemoted() })
    let counts = await recorder.counts()
    #expect(counts.direct == 1)
    #expect(counts.demoted == 1)
    #expect(counts.relay == 1)
}

@Test func directPeerPacketPolicyEnforcesIPv4AllowedSource() {
    var packet = Data(repeating: 0, count: 20)
    packet[0] = 0x45
    packet[2] = 0
    packet[3] = 20
    packet.replaceSubrange(12..<16, with: [10, 255, 255, 36])

    #expect(TunnelPeerPacketPolicy.acceptsIPv4(packet, sourceAddress: "10.255.255.36"))
    #expect(!TunnelPeerPacketPolicy.acceptsIPv4(packet, sourceAddress: "10.255.255.37"))
    #expect(!TunnelPeerPacketPolicy.acceptsIPv4(packet, sourceAddress: "not-an-ip"))
    #expect(!TunnelPeerPacketPolicy.acceptsIPv4(Data(packet.prefix(19)), sourceAddress: "10.255.255.36"))

    var invalidHeaderLength = packet
    invalidHeaderLength[0] = 0x44
    #expect(!TunnelPeerPacketPolicy.acceptsIPv4(invalidHeaderLength, sourceAddress: "10.255.255.36"))

    var invalidTotalLength = packet
    invalidTotalLength[3] = 19
    #expect(!TunnelPeerPacketPolicy.acceptsIPv4(invalidTotalLength, sourceAddress: "10.255.255.36"))

    var oversizedTotalLength = packet
    oversizedTotalLength[2] = 0
    oversizedTotalLength[3] = 21
    #expect(!TunnelPeerPacketPolicy.acceptsIPv4(oversizedTotalLength, sourceAddress: "10.255.255.36"))

    var ipv6 = Data(repeating: 0, count: 40)
    ipv6[0] = 0x60
    #expect(!TunnelPeerPacketPolicy.acceptsIPv4(ipv6, sourceAddress: "10.255.255.36"))
}

@Test func packetFlowRelayFailureStillPropagates() async {
    await #expect(throws: URLError.self) {
        try await PacketFlowRouteSender.send(
            Data([0x45, 0, 0, 20]), directly: nil,
            relay: { _ in throw URLError(.notConnectedToInternet) },
            onDirectFailure: {})
    }
}

@Test func wuspTransportRequestMatchesGoEnvelopeAndRoundTrips() throws {
    let request = WUSPWireRequest(id: 42, method: .get, paths: ["Device.DeviceInfo.SerialNumber"])
    let encoded = try WUSPTransportCodec.encode(request)
    #expect(Array(encoded.prefix(12)) == [1, 1, 1, 0, 42, 0, 0, 0, 0, 0, 0, 0])
    let decoded = try WUSPTransportCodec.decodeRequest(encoded)
    #expect(decoded == request)
}

@Test func wuspAllGoMethodRequestShapesRoundTripWithoutChangingWireFields() throws {
    // Mirrors the request coverage in internal/wusp/usp_transport_test.go.
    // Unsupported macOS operations still need a lossless Go-compatible codec.
    let message = try WUSPMessageCodec.encode(WUSPMessage(fields: [
        WUSPMessageField(path: "Device.WUSP.Request.1.Command", value: .string("Reboot"))
    ]))
    let requests: [(WUSPWireRequest, UInt8)] = [
        (WUSPWireRequest(id: 1, method: .get,
                         paths: ["Device.DeviceInfo.Manufacturer", "Device.WireGuard.Peer.{i}."]), 0),
        (WUSPWireRequest(id: 2, method: .set,
                         paths: ["Device.DeviceInfo.FriendlyName"], messageFrame: message), 1),
        (WUSPWireRequest(id: 3, method: .add,
                         objectPath: "Device.WireGuard.Peer.{i}.", messageFrame: message), 5),
        (WUSPWireRequest(id: 4, method: .delete,
                         paths: ["Device.DeviceInfo.FriendlyName", "Device.WireGuard.Peer.{i}."]), 0),
        (WUSPWireRequest(id: 5, method: .getInstances,
                         paths: ["Device.IP.Interface.{i}."]), 0),
        (WUSPWireRequest(id: 6, method: .operate,
                         objectPath: "Device.WUSP.Request.{i}.", messageFrame: message,
                         metadata: ["command_key": "operate-1"]), 13),
        (WUSPWireRequest(id: 7, method: .notify,
                         objectPath: "Device.WUSP.Subscription.{i}.", messageFrame: message,
                         metadata: ["subscription_id": "sub-1"]), 13),
        (WUSPWireRequest(id: 8, method: .getSupportedDM,
                         paths: ["Device.WireGuard."]), 0),
        (WUSPWireRequest(id: 9, method: .getSupportedProtocol), 0),
        (WUSPWireRequest(id: 10, method: .upload, transfer: WUSPTransferRequest(
            path: "Device.DeviceInfo.SerialNumber", uri: "https://controller.example.net/upload",
            filename: "device-export.bin", contentType: "application/octet-stream",
            payload: Data("hello upload".utf8),
            metadata: ["content-sha256": "deadbeef", "session": "upload-1"])), 2),
        (WUSPWireRequest(id: 11, method: .download, transfer: WUSPTransferRequest(
            path: "Device.DeviceInfo.SoftwareVersion", uri: "https://controller.example.net/download",
            filename: "firmware.bin", metadata: ["session": "download-1"])), 2),
    ]

    for (request, expectedFlags) in requests {
        let frame = try WUSPTransportCodec.encode(request)
        #expect(Array(frame.prefix(4)) == [1, 1, request.method.wireID, expectedFlags])
        #expect(try WUSPTransportCodec.decodeRequest(frame) == request)
    }
}

@Test func wuspOperateCommandMetadataMatchesSharedGoFixture() throws {
    let fixtureURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("../../testdata/protocol/wusp_operate_request.hex")
    let hex = try String(contentsOf: fixtureURL, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let fixture = try #require(Data(hexEncoded: hex))
    let message = try WUSPMessageCodec.encode(WUSPMessage(fields: [WUSPMessageField(
        path: "Device.WiFi.Radio.1.Scan.SSID", value: .string("WantasticGuest"))]))
    let request = WUSPWireRequest(
        id: 702, method: .operate, objectPath: "Device.WiFi.Radio.1.",
        messageFrame: message, metadata: [
            "wusp.operation_command_path": "Device.WiFi.Radio.1.Scan()",
            "request-origin": "unit-test",
        ])
    let encoded = try WUSPTransportCodec.encode(request)
    #expect(encoded == fixture)
    #expect(try WUSPTransportCodec.decodeRequest(fixture) == request)
}

@Test func wuspTransferOpenFrameMatchesGoGoldenBytes() throws {
    let fixtureDirectory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("../../testdata/protocol")
    func fixture(_ name: String) throws -> Data {
        let url = fixtureDirectory.appendingPathComponent(name)
        let hex = try String(contentsOf: url, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return try #require(Data(hexEncoded: hex))
    }

    let frame = WUSPTransferStreamFrame(
        sessionID: 7, requestID: 101, method: .upload, phase: .open)
    let openFixture = try fixture("wusp_transfer_open.hex")
    #expect(try WUSPTransferStreamCodec.encode(frame) == openFixture)
    #expect(try WUSPTransferStreamCodec.decode(openFixture) == frame)

    let chunk = WUSPTransferStreamFrame(
        sessionID: 7, requestID: 101, method: .upload, phase: .chunk,
        sequence: 1, totalSize: 3, data: Data([1, 2, 3]))
    let chunkFixture = try fixture("wusp_transfer_chunk.hex")
    #expect(try WUSPTransferStreamCodec.encode(chunk) == chunkFixture)
    #expect(try WUSPTransferStreamCodec.decode(chunkFixture) == chunk)

    let compressedPayload = Data(String(repeating: "WUSP-transfer-compressible-payload-", count: 160).utf8)
    let compressedChunk = WUSPTransferStreamFrame(
        sessionID: 7, requestID: 101, method: .upload, phase: .chunk,
        sequence: 2, offset: 3, totalSize: UInt64(compressedPayload.count),
        data: compressedPayload)
    let compressedFixture = try fixture("wusp_transfer_compressed_chunk.hex")
    #expect(compressedFixture[4] & (1 << 5) != 0)
    #expect(try WUSPTransferStreamCodec.encode(compressedChunk) == compressedFixture)
    #expect(try WUSPTransferStreamCodec.decode(compressedFixture) == compressedChunk)
}

@Test func wuspTransferStreamFramesRoundTripFieldsCompressionAndPadding() throws {
    let frames = [
        WUSPTransferStreamFrame(
            sessionID: 7, requestID: 101, method: .upload, phase: .open,
            path: "Device.DeviceInfo.VendorConfigFile.{i}.", filename: "backup.cfg",
            contentType: "application/octet-stream", metadata: ["sha256": "deadbeef"]),
        WUSPTransferStreamFrame(
            sessionID: 7, requestID: 101, method: .upload, phase: .chunk,
            sequence: 3, acknowledgementSequence: 2, offset: 2_048, totalSize: 8_192,
            data: Data(repeating: 0x57, count: 5_632), isFinal: true),
        WUSPTransferStreamFrame(
            sessionID: 9, requestID: 202, method: .download, phase: .acknowledgement,
            sequence: 4, acknowledgementSequence: 4),
        WUSPTransferStreamFrame(
            sessionID: 9, requestID: 202, method: .download, phase: .complete,
            metadata: ["status": "complete"], isFinal: true),
        WUSPTransferStreamFrame(
            sessionID: 9, requestID: 202, method: .upload, phase: .abort,
            metadata: ["reason": "cancelled"]),
    ]
    for frame in frames {
        let encoded = try WUSPTransferStreamCodec.encode(frame)
        if frame.phase == .chunk {
            #expect(encoded[4] & (1 << 5) != 0)
        }
        #expect(try WUSPTransferStreamCodec.decode(encoded) == frame)
        var padded = encoded
        padded.append(contentsOf: [0, 0, 0, 0])
        #expect(try WUSPTransferStreamCodec.decode(padded) == frame)
    }
}

@Test func wuspTransferStreamRejectsTruncatedHeadersAndInvalidChunks() throws {
    for length in 0..<45 {
        #expect(throws: WUSPTransportError.malformed) {
            try WUSPTransferStreamCodec.decode(Data(repeating: 0, count: length))
        }
    }
    #expect(throws: WUSPTransportError.malformed) {
        try WUSPTransferStreamCodec.encode(WUSPTransferStreamFrame(
            sessionID: 1, requestID: 1, method: .upload, phase: .chunk))
    }
    #expect(throws: WUSPTransportError.unsupported) {
        try WUSPTransferStreamCodec.encode(WUSPTransferStreamFrame(
            sessionID: 1, requestID: 1, method: .get, phase: .open))
    }
}

@Test func wuspTransferSessionManagerAtomicallyReceivesUploadInsidePrivateDirectory() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("wantastic-transfer-upload-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let channel = MockWUSPTransferStreamChannel()
    let manager = WUSPTransferSessionManager(channel: channel, directory: root)
    let request = WUSPWireRequest(id: 811, method: .upload, transfer: WUSPTransferRequest(
        path: "Device.DeviceInfo.Configuration", uri: "", filename: "backup.bin",
        contentType: "application/octet-stream", metadata: ["size": "5"]))
    let response = try await manager.begin(request)
    let transferResult = try #require(response.transfer)
    let encodedSessionID = try #require(transferResult.metadata["session_id"])
    let sessionID = try #require(UInt64(encodedSessionID))
    let destination = root.appendingPathComponent("backup.bin")
    #expect(!FileManager.default.fileExists(atPath: destination.path))

    await manager.receive(WUSPTransferStreamFrame(
        sessionID: sessionID, requestID: request.id, method: .upload,
        phase: .open, totalSize: 5))
    await manager.receive(WUSPTransferStreamFrame(
        sessionID: sessionID, requestID: request.id, method: .upload,
        phase: .chunk, sequence: 1, offset: 0, totalSize: 5,
        data: Data("hello".utf8), isFinal: true))
    #expect(!FileManager.default.fileExists(atPath: destination.path))
    await manager.receive(WUSPTransferStreamFrame(
        sessionID: sessionID, requestID: request.id, method: .upload,
        phase: .complete, acknowledgementSequence: 1, offset: 5, totalSize: 5,
        isFinal: true))

    #expect(try Data(contentsOf: destination) == Data("hello".utf8))
    let directoryMode = try FileManager.default.attributesOfItem(atPath: root.path)[.posixPermissions] as? Int
    let fileMode = try FileManager.default.attributesOfItem(atPath: destination.path)[.posixPermissions] as? Int
    #expect(directoryMode == 0o700)
    #expect(fileMode == 0o600)
    let frames = await channel.sentFrames
    #expect(frames.map(\.phase) == [.acknowledgement, .acknowledgement, .complete])
    #expect(frames[1].acknowledgementSequence == 1)
    #expect(frames[2].metadata["destination"] == destination.path)
}

@Test func macWUSPAgentAdvertisesAndStartsTransferOnlyWhenSessionManagerIsConfigured() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("wantastic-transfer-dispatch-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let channel = MockWUSPTransferStreamChannel()
    let manager = WUSPTransferSessionManager(channel: channel, directory: root)
    let agent = try MacWUSPAgentDispatcher(
        consoleHost: "console.example.test", credentials: MemoryCredentialPersistence(),
        transferManager: manager, collector: { WUSPMessage(fields: []) })
    let protocolRequest = try WUSPTransportCodec.encode(WUSPWireRequest(
        id: 815, method: .getSupportedProtocol))
    let protocolPayload = try #require(await agent.handleAsync(protocolRequest))
    let protocolResponse = try WUSPTransportCodec.decodeResponse(protocolPayload)
    #expect(protocolResponse.protocolInfo?.methods.contains("Upload") == true)
    #expect(protocolResponse.protocolInfo?.methods.contains("Download") == true)
    #expect(protocolResponse.protocolInfo?.transferTransport == "wireguard-noise-type-8-stream")
    #expect(protocolResponse.protocolInfo?.reliableTransfer == true)

    let uploadPayload = try WUSPTransportCodec.encode(WUSPWireRequest(
        id: 816, method: .upload, transfer: WUSPTransferRequest(
            path: "Device.Config", uri: "", filename: "node.cfg", metadata: ["size": "0"])))
    let uploadResponsePayload = try #require(await agent.handleAsync(uploadPayload))
    let uploadResponse = try WUSPTransportCodec.decodeResponse(uploadResponsePayload)
    #expect(uploadResponse.id == 816)
    #expect(uploadResponse.error.isEmpty)
    #expect(uploadResponse.transfer?.metadata["transport"] == "wg-stream")
    await manager.close()
}

@Test func wuspTransferSessionManagerRestrictsPathsAndRejectsExistingOrExternalSources() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("wantastic-transfer-policy-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let existing = root.appendingPathComponent("existing.bin")
    try Data([1]).write(to: existing)
    let externalLink = root.appendingPathComponent("external-link.bin")
    try FileManager.default.createSymbolicLink(
        at: externalLink, withDestinationURL: URL(fileURLWithPath: "/etc/hosts"))
    let channel = MockWUSPTransferStreamChannel()
    let manager = WUSPTransferSessionManager(channel: channel, directory: root)

    do {
        _ = try await manager.begin(WUSPWireRequest(id: 812, method: .upload,
            transfer: WUSPTransferRequest(path: "Device.File", uri: "", filename: "existing.bin")))
        Issue.record("existing destinations must not be overwritten")
    } catch WUSPTransferSessionError.destinationExists {
        // Expected: remote upload cannot overwrite an existing file.
    }

    do {
        _ = try await manager.begin(WUSPWireRequest(id: 813, method: .download,
            transfer: WUSPTransferRequest(path: "Device.File", uri: "", filename: "/etc/hosts")))
        Issue.record("download must not read outside the private transfer directory")
    } catch WUSPTransferSessionError.sourceUnavailable {
        // Expected: only staged regular files are downloadable.
    }

    do {
        _ = try await manager.begin(WUSPWireRequest(id: 821, method: .download,
            transfer: WUSPTransferRequest(path: "Device.File", uri: "",
                                         filename: externalLink.lastPathComponent)))
        Issue.record("symbolic links must not expose files outside the staging directory")
    } catch WUSPTransferSessionError.sourceUnavailable {
        // Expected: symlink targets are never accepted as transfer sources.
    }
}

@Test func wuspTransferSessionManagerStreamsDownloadWithChunkAcknowledgements() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("wantastic-transfer-download-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let payload = Data((0..<2_500).map { UInt8($0 & 0xff) })
    try payload.write(to: root.appendingPathComponent("source.bin"))
    let channel = MockWUSPTransferStreamChannel()
    let manager = WUSPTransferSessionManager(channel: channel, directory: root)
    let request = WUSPWireRequest(id: 814, method: .download,
        transfer: WUSPTransferRequest(path: "Device.File", uri: "", filename: "source.bin"))
    let response = try await manager.begin(request)
    let transferResult = try #require(response.transfer)
    let encodedSessionID = try #require(transferResult.metadata["session_id"])
    let sessionID = try #require(UInt64(encodedSessionID))
    await manager.receive(WUSPTransferStreamFrame(
        sessionID: sessionID, requestID: request.id, method: .download,
        phase: .acknowledgement, acknowledgementSequence: 1))

    func waitForFrameCount(_ count: Int) async throws -> [WUSPTransferStreamFrame] {
        for _ in 0..<200 {
            let frames = await channel.sentFrames
            if frames.count >= count { return frames }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw URLError(.timedOut)
    }

    var frames = try await waitForFrameCount(2)
    #expect(frames[0].phase == .open)
    #expect(frames[1].phase == .chunk)
    #expect(frames[1].sequence == 1)
    try await Task.sleep(for: .milliseconds(20))
    #expect(await channel.sentFrames.count == 2)
    await manager.receive(WUSPTransferStreamFrame(
        sessionID: sessionID, requestID: request.id, method: .download,
        phase: .acknowledgement, acknowledgementSequence: 999))
    try await Task.sleep(for: .milliseconds(20))
    #expect(await channel.sentFrames.count == 2)
    await manager.receive(WUSPTransferStreamFrame(
        sessionID: sessionID, requestID: request.id, method: .download,
        phase: .acknowledgement, acknowledgementSequence: 1))

    frames = try await waitForFrameCount(3)
    #expect(frames[2].sequence == 2)
    await manager.receive(WUSPTransferStreamFrame(
        sessionID: sessionID, requestID: request.id, method: .download,
        phase: .acknowledgement, acknowledgementSequence: 2))
    frames = try await waitForFrameCount(4)
    #expect(frames[3].sequence == 3)
    await manager.receive(WUSPTransferStreamFrame(
        sessionID: sessionID, requestID: request.id, method: .download,
        phase: .acknowledgement, acknowledgementSequence: 3))
    frames = try await waitForFrameCount(5)
    #expect(frames[4].phase == .complete)
    #expect(Data(frames.filter { $0.phase == .chunk }.flatMap(\.data)) == payload)
}

@Test func wuspTransferSessionManagerRetriesUnacknowledgedChunksThenAborts() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("wantastic-transfer-retry-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try Data("retry me".utf8).write(to: root.appendingPathComponent("retry.bin"))
    let channel = MockWUSPTransferStreamChannel()
    let manager = WUSPTransferSessionManager(channel: channel, directory: root,
                                              acknowledgementTimeout: .milliseconds(20),
                                              maximumRetries: 3)
    _ = try await manager.begin(WUSPWireRequest(id: 817, method: .download,
        transfer: WUSPTransferRequest(path: "Device.File", uri: "", filename: "retry.bin")))

    var frames: [WUSPTransferStreamFrame] = []
    for _ in 0..<200 {
        frames = await channel.sentFrames
        if frames.contains(where: { $0.phase == .abort }) { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    let retries = frames.filter { $0.phase == .chunk }
    #expect(retries.count == 3)
    #expect(retries.dropFirst().allSatisfy { $0 == retries.first })
    #expect(frames.last?.phase == .abort)
}

@Test func wuspTransferSessionManagerEnforcesAggregateStagingQuota() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("wantastic-transfer-quota-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let channel = MockWUSPTransferStreamChannel()
    let manager = WUSPTransferSessionManager(channel: channel, directory: root)
    let first = WUSPWireRequest(id: 818, method: .upload, transfer: WUSPTransferRequest(
        path: "Device.File", uri: "", filename: "first.bin",
        metadata: ["size": String(WUSPTransferSessionManager.maximumTransferBytes - 1)]))
    _ = try await manager.begin(first)
    let second = WUSPWireRequest(id: 819, method: .upload, transfer: WUSPTransferRequest(
        path: "Device.File", uri: "", filename: "second.bin", metadata: ["size": "2"]))
    do {
        _ = try await manager.begin(second)
        Issue.record("aggregate staging quota must reject overcommit")
    } catch WUSPTransferSessionError.transferTooLarge {
        // Expected: aggregate reservations cannot exceed the staging quota.
    }
    await manager.close()

    let afterCleanup = WUSPWireRequest(id: 820, method: .upload, transfer: WUSPTransferRequest(
        path: "Device.File", uri: "", filename: "after-cleanup.bin",
        metadata: ["size": String(WUSPTransferSessionManager.maximumTransferBytes)]))
    _ = try await manager.begin(afterCleanup)
    await manager.close()
}

@Test func wuspRequestTransportEncodesRequestsCorrelatesResponsesAndMapsValues() async throws {
    let channel = MockWUSPControlChannel { payload in
        let request = try WUSPTransportCodec.decodeRequest(payload)
        #expect(request.id == 91)
        #expect(request.method == .set)
        #expect(request.paths == ["Device.DeviceInfo.HostName"])
        let sentMessage = try #require(request.messageFrame)
        let decodedMessage = try WUSPMessageCodec.decode(sentMessage)
        #expect(decodedMessage.fields == [
            WUSPMessageField(path: "Device.DeviceInfo.HostName", value: .string("Studio Mac"))
        ])

        let responseMessage = WUSPMessage(fields: [
            WUSPMessageField(path: "Device.DeviceInfo.HostName", value: .string("Studio Mac")),
            WUSPMessageField(path: "Device.DeviceInfo.UpTime", value: .unsigned(42))
        ])
        let response = WUSPWireResponse(
            id: request.id, method: request.method,
            messageFrame: try WUSPMessageCodec.encode(responseMessage)
        )
        return try WUSPTransportCodec.encode(response)
    }
    let transport = WUSPRequestTransport(channel: channel, deviceID: "peer-1", timeout: .seconds(1))
    let response = try await transport.send(
        WUSPRequest(id: 91, method: .set, paths: ["Device.DeviceInfo.HostName"],
                    values: ["Device.DeviceInfo.HostName": "Studio Mac"]),
        to: "peer-1"
    )
    #expect(response.id == 91)
    #expect(response.values == ["Device.DeviceInfo.HostName": "Studio Mac",
                                "Device.DeviceInfo.UpTime": "42"])
    await transport.close()
}

@Test func wuspRequestTransportRejectsWrongDeviceAndTimesOutUnansweredRequest() async throws {
    let channel = MockWUSPControlChannel { _ in nil }
    let transport = WUSPRequestTransport(channel: channel, deviceID: "peer-1", timeout: .milliseconds(30))
    await #expect(throws: WUSPRequestTransportError.wrongDevice) {
        try await transport.send(WUSPRequest(id: 1, method: .get), to: "peer-2")
    }
    await #expect(throws: WUSPRequestTransportError.timedOut) {
        try await transport.send(WUSPRequest(id: 2, method: .get), to: "peer-1")
    }
    await transport.close()
}

@Test func wuspRequestTransportRejectsResponseWithWrongMethod() async throws {
    let channel = MockWUSPControlChannel { _ in
        try WUSPTransportCodec.encode(WUSPWireResponse(id: 12, method: .delete))
    }
    let transport = WUSPRequestTransport(channel: channel, deviceID: "peer-1", timeout: .seconds(1))
    await #expect(throws: WUSPRequestTransportError.malformedResponse) {
        try await transport.send(WUSPRequest(id: 12, method: .get), to: "peer-1")
    }
    await transport.close()
}

@Test func wuspRequestTransportCloseFailsOutstandingRequests() async throws {
    let channel = MockWUSPControlChannel { _ in nil }
    let transport = WUSPRequestTransport(channel: channel, deviceID: "peer-1", timeout: .seconds(10))
    let requestTask = Task {
        try await transport.send(WUSPRequest(id: 13, method: .get), to: "peer-1")
    }
    for _ in 0..<100 {
        if channel.numberOfSentPayloads > 0 { break }
        try await Task.sleep(for: .milliseconds(1))
    }
    #expect(channel.numberOfSentPayloads == 1)
    await transport.close()
    await #expect(throws: WUSPRequestTransportError.channelClosed) {
        try await requestTask.value
    }
}

@Test func wuspTransportRejectsMalformedAndOversizedFrames() throws {
    #expect(throws: WUSPTransportError.self) { try WUSPTransportCodec.decodeRequest(Data([1, 1, 99])) }
    let request = WUSPWireRequest(id: 1, method: .get, paths: [String(repeating: "x", count: 1_100_000)])
    #expect(throws: WUSPTransportError.self) { try WUSPTransportCodec.encode(request) }
}

@Test func wuspMessageFrameMatchesInlinePathWireFormat() throws {
    let frame = try WUSPMessageCodec.encode(WUSPMessage(fields: [
        WUSPMessageField(path: "a", value: .string("x"))
    ]))
    #expect(Array(frame) == [0x57, 0x55, 1, 0x27, 0xdb, 0, 0, 0, 1, 0, 1, 0x61, 6, 1, 0x78])
    #expect(try WUSPMessageCodec.decode(frame) == WUSPMessage(fields: [
        WUSPMessageField(path: "a", value: .string("x"))
    ]))
}

@Test func wuspTypedValuesMatchSharedGoFixture() throws {
    let fixtureURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("../../testdata/protocol/wusp_typed_values.hex")
    let hex = try String(contentsOf: fixtureURL, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let fixture = try #require(Data(hexEncoded: hex))
    let ipv6Address = Data([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ])
    let message = WUSPMessage(
        deviceID: "fixture-device", timestampNanoseconds: 1_700_000_000_123_456_789,
        fields: [
            WUSPMessageField(path: "Device.Test.Null", value: .null),
            WUSPMessageField(path: "Device.Test.False", value: .bool(false)),
            WUSPMessageField(path: "Device.Test.True", value: .bool(true)),
            WUSPMessageField(path: "Device.Test.Unsigned", value: .unsigned(300)),
            WUSPMessageField(path: "Device.Test.Signed", value: .signed(-42)),
            WUSPMessageField(path: "Device.Test.Decimal", value: .decimal(12.5)),
            WUSPMessageField(path: "Device.Test.String", value: .string("hello")),
            WUSPMessageField(path: "Device.Test.Bytes", value: .bytes(Data([0, 255]))),
            WUSPMessageField(path: "Device.Test.Time", value: .timeNanoseconds(1_700_000_000_123_456_789)),
            WUSPMessageField(path: "Device.Test.IPv4", value: .ipv4(Data([192, 0, 2, 1]))),
            WUSPMessageField(path: "Device.Test.IPv6", value: .ipv6(ipv6Address)),
            WUSPMessageField(path: "Device.Test.IPv4Prefix",
                             value: .ipv4Prefix(Data([192, 0, 2, 0]), 24)),
            WUSPMessageField(path: "Device.Test.IPv6Prefix",
                             value: .ipv6Prefix(Data([
                                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             ]), 32)),
            WUSPMessageField(path: "Device.Test.MAC", value: .mac(Data([0, 17, 34, 51, 68, 85]))),
            WUSPMessageField(path: "Device.Test.List", value: .list([.string("nested"), .unsigned(7)])),
        ])
    #expect(try WUSPMessageCodec.encode(message) == fixture)
    #expect(try WUSPMessageCodec.decode(fixture) == message)
}

@Test func wuspMessageCodecRoundTripsTypedValuesAndLZ4() throws {
    let message = WUSPMessage(fields: [
        WUSPMessageField(path: "Device.Test.Bool", value: .bool(true)),
        WUSPMessageField(path: "Device.Test.Integer", value: .signed(-42)),
        WUSPMessageField(path: "Device.Test.Bytes", value: .bytes(Data([1, 2, 3]))),
        WUSPMessageField(path: "Device.Test.IPv4", value: .ipv4(Data([10, 0, 0, 1]))),
        WUSPMessageField(path: "Device.Test.List", value: .list([.string("one"), .unsigned(2)])),
    ])
    #expect(try WUSPMessageCodec.decode(WUSPMessageCodec.encode(message)) == message)
    let repeated = WUSPMessage(fields: (0..<30).map { index in
        WUSPMessageField(path: "Device.Test.Value.\(index)", value: .string(String(repeating: "x", count: 120)))
    })
    let compressed = try WUSPMessageCodec.encode(repeated, compress: true)
    #expect(compressed[5] & 1 == 1)
    #expect(try WUSPMessageCodec.decode(compressed) == repeated)
}

@Test func wuspCompactSelectorEnvelopesMatchGoFixtures() throws {
    let goRequest = Data([
        0x01, 0x01, 0x01, 0x10, 0x2a, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0xb8, 0xf2, 0xa0, 0xd5, 0x94, 0xae, 0x93, 0xa4, 0xc8, 0x01, 0,
    ])
    let request = try WUSPTransportCodec.decodeRequest(goRequest)
    #expect(request.id == 42)
    #expect(request.method == .get)
    #expect(request.pathCodes.count == 1)
    #expect(try WUSPTransportCodec.encode(request) == goRequest)

    let goResponse = Data([
        0x01, 0x02, 0x01, 0x90, 0x2a, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 3, 0x73, 0x65, 0x71, 1, 0x39,
        1, 0xb8, 0xf2, 0xa0, 0xd5, 0x94, 0xae, 0x93, 0xa4, 0xc8, 0x01, 0,
        0, 0,
    ])
    let response = try WUSPTransportCodec.decodeResponse(goResponse)
    #expect(response.id == 42)
    #expect(response.metadata == ["seq": "9"])
    #expect(response.pathCodes.count == 1)
    #expect(try WUSPTransportCodec.encode(response) == goResponse)

    let goProtocolResponse = try #require(Data(hexEncoded:
        "010209402503000000000000001d77616e7461737469632d777573702d6f7665722d776972656775617264010b0347657403536574034164640644656c6574650c476574496e7374616e636573074f706572617465064e6f746966790e476574537570706f72746564444d14476574537570706f7274656450726f746f636f6c0655706c6f616408446f776e6c6f616402126e65737465642d6d6573736167652d6c7a341073747265616d2d6368756e6b2d6c7a34237769726567756172642d6e6f6973652d667261676d656e7465642d646174616772616d1e7769726567756172642d6e6f6973652d73747265616d2d7061636b657473b009e0080101"))
    let protocolResponse = try WUSPTransportCodec.decodeResponse(goProtocolResponse)
    #expect(protocolResponse.protocolInfo == WUSPProtocolInfo(
        name: "wantastic-wusp-over-wireguard", version: 1,
        methods: ["Get", "Set", "Add", "Delete", "GetInstances", "Operate", "Notify",
                  "GetSupportedDM", "GetSupportedProtocol", "Upload", "Download"],
        compression: ["nested-message-lz4", "stream-chunk-lz4"],
        controlTransport: "wireguard-noise-fragmented-datagram",
        transferTransport: "wireguard-noise-stream-packets", maxControlPayload: 1_200,
        recommendedChunkSize: 1_120, tunnelOnly: true, reliableTransfer: true))
    #expect(try WUSPTransportCodec.encode(protocolResponse) == goProtocolResponse)

    let goSupportedDM = try #require(Data(hexEncoded:
        "0102082026030000000000000004322e323008066465766963651f54522d3138312044657669636520285553502046756c6c20496d706f72742906322e32302e3103322e3004322e32303942726f616462616e64466f72756d2f7573702d646174612d6d6f64656c732074722d3138312d322d32302d312d7573702d66756c6c2e786d6c5868747470733a2f2f6769746875622e636f6d2f42726f616462616e64466f72756d2f7573702d646174612d6d6f64656c732f626c6f622f6d61737465722f74722d3138312d322d32302d312d7573702d66756c6c2e786d6ceb06a337097769726567756172641054522d3138312057697265477561726406322e32302e3104322e323004322e32303742726f616462616e64466f72756d2f6465766963652d646174612d6d6f64656c2074722d3138312d322d7769726567756172642e786d6c5868747470733a2f2f6769746875622e636f6d2f42726f616462616e64466f72756d2f7573702d646174612d6d6f64656c732f626c6f622f6d61737465722f74722d3138312d322d32302d312d7573702d66756c6c2e786d6c051e04777573700e57616e746173746963205755535005312e302e3003312e3003312e301d57616e7461737469632057555350206f766572205769726547756172642768747470733a2f2f6769746875622e636f6d2f77616e7461737469632f77616e74617374696364051717777573702d63656c6c756c61722d74656c656d657472792157616e74617374696320575553502043656c6c756c61722054656c656d6574727905312e302e3003312e3003312e301d57616e7461737469632057555350206f766572205769726547756172642768747470733a2f2f6769746875622e636f6d2f77616e7461737469632f77616e74617374696364043115777573702d63656c6c756c61722d636f6e74726f6c1f57616e74617374696320575553502043656c6c756c617220436f6e74726f6c05312e302e3003312e3003312e301d57616e7461737469632057555350206f766572205769726547756172642768747470733a2f2f6769746875622e636f6d2f77616e7461737469632f77616e74617374696364021109777573702d676e73731357616e746173746963205755535020474e535305312e302e3003312e3003312e301d57616e7461737469632057555350206f766572205769726547756172642768747470733a2f2f6769746875622e636f6d2f77616e7461737469632f77616e74617374696364021713777573702d6d6573682d74656c656d657472791d57616e7461737469632057555350204d6573682054656c656d6574727905312e302e3003312e3003312e301d57616e7461737469632057555350206f766572205769726547756172642768747470733a2f2f6769746875622e636f6d2f77616e7461737469632f77616e746173746963640d9e0116777573702d6e6574776f726b2d74656c656d657472792057616e7461737469632057555350204e6574776f726b2054656c656d6574727905312e302e3003312e3003312e301d57616e7461737469632057555350206f766572205769726547756172642768747470733a2f2f6769746875622e636f6d2f77616e7461737469632f77616e74617374696364020d02074465766963652e0004322e3132124465766963652e446576696365496e666f2e0004322e3132021e4465766963652e446576696365496e666f2e4d616e75666163747572657206737472696e6708726561644f6e6c7904322e3132214465766963652e446576696365496e666f2e4d616e7566616374757265724f554906737472696e6708726561644f6e6c7904322e3132"))
    let supportedDMResponse = try WUSPTransportCodec.decodeResponse(goSupportedDM)
    let supportedDM = try #require(supportedDMResponse.supportedDataModel)
    #expect(supportedDM.rootDataModelVersion == "2.20")
    #expect(supportedDM.models.count == 8)
    #expect(supportedDM.objects.map(\.path) == ["Device.", "Device.DeviceInfo."])
    #expect(supportedDM.params.map(\.path) == [
        "Device.DeviceInfo.Manufacturer", "Device.DeviceInfo.ManufacturerOUI",
    ])
    #expect(try WUSPTransportCodec.encode(supportedDMResponse) == goSupportedDM)
}

@Test func wuspLZ4DecodesWantasticGoFixture() throws {
    // Captured from EncodeMessageLZ4 in wantasticd for 30 inline string fields.
    let hex = "57550127db010000d7100000ff091e00134465766963652e546573742e56616c75652e3006780100651f008f00001f318f007b1f328f007b1f338f007b1f348f007b1f358f007b1f368f007b1f378f007b1f388f007b1f398f00681e1496051f319705691f149000001f3120017c1f3290007c1f3390007c1f3490007c1f3590007c1f3690007c1f3790007c1f3890007c1f3990007b1f32a0057c1f32a0057c1f32a0057c1f32a0057c1f32a0057c1f32a0057c1f32a0057c1f32a0057c1f32a0057c1f32a0056800"
    let bytes = stride(from: 0, to: hex.count, by: 2).compactMap { index -> UInt8? in
        let start = hex.index(hex.startIndex, offsetBy: index)
        let end = hex.index(start, offsetBy: 2)
        return UInt8(hex[start..<end], radix: 16)
    }
    let message = try WUSPMessageCodec.decode(Data(bytes))
    #expect(message.fields.count == 30)
    #expect(message.fields[29].value == .string(String(repeating: "x", count: 120)))
}

@Test func macCollectorBuildsReadOnlyTypedSystemSnapshot() throws {
    let interface = MacInterfaceSnapshot(name: "en0", isUp: true, addresses: [
        MacIPAddressSnapshot(address: Data([192, 168, 1, 20]), subnetMask: Data([255, 255, 255, 0]), family: AF_INET),
        MacIPAddressSnapshot(address: Data(repeating: 0, count: 16), subnetMask: nil, family: AF_INET6),
    ], hardwareAddress: Data([0, 1, 2, 3, 4, 5]))
    let message = MacDeviceCollector.message(
        hostname: "office-mac", model: "Mac15,7", softwareVersion: "macOS 15.0",
        interfaces: [interface], timestamp: Date(timeIntervalSince1970: 1.25),
        systemUptimeSeconds: 99, totalMemoryKilobytes: 16_384,
        freeMemoryKilobytes: 4_096, localTimeZone: "Africa/Casablanca"
    )
    #expect(message.deviceID == nil)
    #expect(message.timestampNanoseconds == 1_250_000_000)
    #expect(message.fields.contains(WUSPMessageField(path: "Device.RootDataModelVersion", value: .string("2.20"))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.DeviceInfo.Manufacturer", value: .string("Apple"))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.DeviceInfo.ProductClass", value: .string("Mac"))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.DeviceInfo.UpTime", value: .unsigned(99))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.DeviceInfo.MemoryStatus.Total", value: .unsigned(16_384))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.DeviceInfo.MemoryStatus.Free", value: .unsigned(4_096))))
    #expect(message.fields.contains(
        WUSPMessageField(path: "Device.DeviceInfo.NetworkProperties.TCPImplementation",
                         value: .list([.string("CUBIC")]))))
    #expect(message.fields.contains(WUSPMessageField(
        path: "Device.Time.CurrentLocalTime", value: .timeNanoseconds(1_250_000_000))))
    #expect(message.fields.contains(WUSPMessageField(
        path: "Device.Time.LocalTimeZone", value: .string("Africa/Casablanca"))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.IP.IPv4Capable", value: .bool(true))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.IP.IPv6Enable", value: .bool(true))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.IP.Interface.1.Enable", value: .bool(true))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.IP.InterfaceNumberOfEntries", value: .unsigned(1))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.Ethernet.Interface.1.MACAddress", value: .mac(Data([0, 1, 2, 3, 4, 5])))))
    #expect(message.fields.contains(WUSPMessageField(path: "Device.IP.Interface.1.IPv4Address.1.IPAddress", value: .ipv4(Data([192, 168, 1, 20])))))
}

@Test func macCollectorReadsNativeHostData() throws {
    let message = try MacDeviceCollector.collect()
    let localRoutes = try MacDeviceCollector.privateLANRoutes()
    #expect(localRoutes.count <= TunnelControlCodec.maxRoutesPerOwner)
    #expect(localRoutes == Array(Set(localRoutes)).sorted())
    for route in localRoutes { _ = try TunnelIPv4Prefix(route) }
    #expect(message.fields.contains(WUSPMessageField(path: "Device.DeviceInfo.Manufacturer", value: .string("Apple"))))
    #expect(message.fields.contains { field in
        guard field.path == "Device.DeviceInfo.ModelName", case .string(let value) = field.value else { return false }
        return !value.isEmpty
    })
    #expect(message.fields.contains { field in
        guard field.path == "Device.DeviceInfo.HostName", case .string(let value) = field.value else { return false }
        return !value.isEmpty
    })
    #expect(message.fields.contains { field in
        guard field.path == "Device.DeviceInfo.UpTime", case .unsigned(let value) = field.value else { return false }
        return value > 0
    })
    #expect(message.fields.contains { field in
        guard field.path == "Device.DeviceInfo.MemoryStatus.Total", case .unsigned(let value) = field.value else { return false }
        return value > 0
    })
    #expect(message.fields.contains { $0.path == "Device.Time.CurrentLocalTime" })
    #expect(message.fields.contains { field in
        guard field.path == "Device.DeviceInfo.SoftwareVersion", case .string(let value) = field.value else { return false }
        return value == MacDeviceCollector.productVersion(ProcessInfo.processInfo.operatingSystemVersion)
    })
}

@Test func macOSProductVersionMatchesSystemProductVersionShape() {
    #expect(MacDeviceCollector.productVersion(
        OperatingSystemVersion(majorVersion: 15, minorVersion: 0, patchVersion: 0)) == "15.0")
    #expect(MacDeviceCollector.productVersion(
        OperatingSystemVersion(majorVersion: 15, minorVersion: 2, patchVersion: 1)) == "15.2.1")
}

@Test func macCollectorDoesNotAdvertiseLoopbackOrVirtualInterfaces() {
    let physical = MacInterfaceSnapshot(name: "en0", isUp: true, addresses: [], hardwareAddress: Data([0, 1, 2, 3, 4, 5]))
    let loopback = MacInterfaceSnapshot(name: "lo0", isUp: true, addresses: [], isLoopback: true, hardwareAddress: Data([0, 0, 0, 0, 0, 0]))
    let virtual = MacInterfaceSnapshot(name: "utun4", isUp: true, addresses: [])
    let message = MacDeviceCollector.message(hostname: "mac", model: "Mac", softwareVersion: "macOS", interfaces: [physical, loopback, virtual])
    #expect(message.fields.contains(WUSPMessageField(path: "Device.IP.InterfaceNumberOfEntries", value: .unsigned(1))))
    #expect(!message.fields.contains { $0.path.contains("utun4") || $0.path.contains("lo0") })
}

@Test func p2pCandidateCollectionExcludesVirtualLoopbackAndLinkLocalAddresses() {
    let mac = Data([0, 1, 2, 3, 4, 5])
    let interfaces = [
        MacInterfaceSnapshot(name: "en0", isUp: true, addresses: [
            MacIPAddressSnapshot(address: Data([192, 168, 1, 20]), subnetMask: nil, family: AF_INET),
            MacIPAddressSnapshot(address: Data([169, 254, 1, 2]), subnetMask: nil, family: AF_INET),
            MacIPAddressSnapshot(address: Data([0x20, 1] + Array(repeating: 0, count: 13) + [1]), subnetMask: nil, family: AF_INET6),
            MacIPAddressSnapshot(address: Data([0xfe, 0x80] + Array(repeating: 0, count: 14)), subnetMask: nil, family: AF_INET6),
        ], hardwareAddress: mac),
        MacInterfaceSnapshot(name: "lo0", isUp: true, addresses: [
            MacIPAddressSnapshot(address: Data([127, 0, 0, 1]), subnetMask: nil, family: AF_INET),
        ], isLoopback: true, hardwareAddress: mac),
        MacInterfaceSnapshot(name: "utun4", isUp: true, addresses: [
            MacIPAddressSnapshot(address: Data([10, 0, 0, 2]), subnetMask: nil, family: AF_INET),
        ]),
    ]
    let candidates = MacDeviceCollector.p2pCandidates(from: interfaces, udpPort: 51_820)
    #expect(candidates.count == 2)
    #expect(candidates.contains(P2PEndpoint(address: Data([192, 168, 1, 20]), port: 51_820)))
    #expect(candidates.contains(P2PEndpoint(
        address: Data([0x20, 1] + Array(repeating: 0, count: 13) + [1]), port: 51_820)))
}

@Test func macCollectorDiscoversOnlyBoundedPrivateLANRoutes() throws {
    let mac = Data([0, 1, 2, 3, 4, 5])
    let interfaces = [
        MacInterfaceSnapshot(name: "en0", isUp: true, addresses: [
            MacIPAddressSnapshot(address: Data([192, 168, 1, 27]),
                                 subnetMask: Data([255, 255, 255, 0]), family: AF_INET),
            MacIPAddressSnapshot(address: Data([10, 0, 0, 1]),
                                 subnetMask: Data([255, 255, 255, 255]), family: AF_INET),
            MacIPAddressSnapshot(address: Data([10, 0, 0, 1]),
                                 subnetMask: Data([255, 0, 255, 0]), family: AF_INET),
            MacIPAddressSnapshot(address: Data([169, 254, 1, 2]),
                                 subnetMask: Data([255, 255, 0, 0]), family: AF_INET),
            MacIPAddressSnapshot(address: Data([203, 0, 113, 8]),
                                 subnetMask: Data([255, 255, 255, 0]), family: AF_INET),
        ], hardwareAddress: mac),
        MacInterfaceSnapshot(name: "lo0", isUp: true, addresses: [
            MacIPAddressSnapshot(address: Data([10, 2, 0, 1]),
                                 subnetMask: Data([255, 255, 0, 0]), family: AF_INET),
        ], isLoopback: true, hardwareAddress: mac),
        MacInterfaceSnapshot(name: "utun4", isUp: true, addresses: [
            MacIPAddressSnapshot(address: Data([10, 3, 0, 1]),
                                 subnetMask: Data([255, 255, 0, 0]), family: AF_INET),
        ], hardwareAddress: mac),
        MacInterfaceSnapshot(name: "ppp0", isUp: true, addresses: [
            MacIPAddressSnapshot(address: Data([10, 4, 0, 1]),
                                 subnetMask: Data([255, 255, 0, 0]), family: AF_INET),
        ], isPointToPoint: true, hardwareAddress: mac),
        MacInterfaceSnapshot(name: "en1", isUp: false, addresses: [
            MacIPAddressSnapshot(address: Data([10, 5, 0, 1]),
                                 subnetMask: Data([255, 255, 0, 0]), family: AF_INET),
        ], hardwareAddress: mac),
        MacInterfaceSnapshot(name: "en2", isUp: true, addresses: [
            MacIPAddressSnapshot(address: Data([10, 6, 0, 1]),
                                 subnetMask: Data([255, 255, 0, 0]), family: AF_INET),
        ]),
    ]

    let routes = try MacDeviceCollector.privateLANRoutes(from: interfaces, tunnelInterfaceName: "en3")
    #expect(routes == [
        "10.0.0.1/32", "192.168.1.0/24",
    ])
    let routeCandidates = try MacDeviceCollector.privateLANRouteCandidates(
        from: interfaces, tunnelInterfaceName: "en3")
    #expect(routeCandidates.map { $0.prefix.description } == routes)
    #expect(routeCandidates.allSatisfy { $0.interfaceName == "en0" })
    let firewallPlan = try MacLocalAccessFirewallPlan(tunnelInterfaceName: "utun7",
                                                      routes: routeCandidates,
                                                      overlaySources: ["10.255.255.32/27"])
    #expect(firewallPlan.rules.contains("nat on en0 inet from 10.255.255.32/27 to 192.168.1.0/24"))
    #expect(try TunnelControlCodec.encodeLocalAccessAdvertisement(routes) == Data([
        6, 2, 32, 10, 0, 0, 1, 24, 192, 168, 1, 0,
    ]))
}

@Test func macCollectorResolvesAssignedOverlayAddressToAnActiveTunnelInterface() {
    let overlayAddress = Data([10, 255, 255, 35])
    let onEthernet = MacInterfaceSnapshot(
        name: "en0", isUp: true,
        addresses: [MacIPAddressSnapshot(address: overlayAddress, subnetMask: nil, family: AF_INET)])
    let onTunnel = MacInterfaceSnapshot(
        name: "utun12", isUp: true,
        addresses: [MacIPAddressSnapshot(address: overlayAddress, subnetMask: nil, family: AF_INET)])
    let downTunnel = MacInterfaceSnapshot(
        name: "utun13", isUp: false,
        addresses: [MacIPAddressSnapshot(address: overlayAddress, subnetMask: nil, family: AF_INET)])

    #expect(MacDeviceCollector.interfaceName(owningIPv4Address: "10.255.255.35",
                                             from: [onEthernet, downTunnel, onTunnel]) == "utun12")
    #expect(MacDeviceCollector.interfaceName(owningIPv4Address: "10.255.255.35",
                                             from: [downTunnel]) == nil)
    #expect(MacDeviceCollector.interfaceName(owningIPv4Address: "not-an-ip",
                                             from: [onTunnel]) == nil)
}

@Test func macCollectorRejectsAmbiguousLocalRouteEgress() {
    let mac = Data([0, 1, 2, 3, 4, 5])
    let address = MacIPAddressSnapshot(address: Data([192, 168, 60, 5]),
                                       subnetMask: Data([255, 255, 255, 0]), family: AF_INET)
    let interfaces = [
        MacInterfaceSnapshot(name: "en0", isUp: true, addresses: [address], hardwareAddress: mac),
        MacInterfaceSnapshot(name: "en1", isUp: true, addresses: [address], hardwareAddress: mac),
    ]
    #expect(throws: MacCollectorError.ambiguousLocalRoute) {
        try MacDeviceCollector.privateLANRouteCandidates(from: interfaces)
    }
}

@Test func macCollectorRejectsUnboundedPrivateLANRouteDiscovery() throws {
    let mac = Data([0, 1, 2, 3, 4, 5])
    let addresses = (0..<17).map { index in
        MacIPAddressSnapshot(address: Data([10, UInt8(index), 0, 1]),
                             subnetMask: Data([255, 255, 255, 0]), family: AF_INET)
    }
    let interface = MacInterfaceSnapshot(name: "en0", isUp: true,
                                         addresses: addresses, hardwareAddress: mac)
    #expect(throws: TunnelControlError.tooManyRoutes) {
        try MacDeviceCollector.privateLANRoutes(from: [interface])
    }
}

@Test func macLocalAccessFirewallPlanMatchesDarwinGoRuleLayoutIncludingHostRoutes() throws {
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [
            MacLocalAccessRoute(prefix: "192.168.60.17/32", interfaceName: "en0"),
            MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0"),
        ],
        overlaySources: ["10.255.255.35/32", "10.255.255.32/27"])

    #expect(MacLocalAccessFirewallPlan.pfAnchor == "com.apple/wantastic")
    #expect(plan.routes.map(\.prefix.description) == ["192.168.60.0/24", "192.168.60.17/32"])
    #expect(plan.overlaySources.map(\.description) == ["10.255.255.32/27", "10.255.255.35/32"])
    #expect(plan.rules == """
    nat on en0 inet from 10.255.255.32/27 to 192.168.60.0/24 -> (en0)
    pass in quick on utun7 inet from 10.255.255.32/27 to 192.168.60.0/24 keep state
    nat on en0 inet from 10.255.255.35/32 to 192.168.60.0/24 -> (en0)
    pass in quick on utun7 inet from 10.255.255.35/32 to 192.168.60.0/24 keep state
    nat on en0 inet from 10.255.255.32/27 to 192.168.60.17/32 -> (en0)
    pass in quick on utun7 inet from 10.255.255.32/27 to 192.168.60.17/32 keep state
    nat on en0 inet from 10.255.255.35/32 to 192.168.60.17/32 -> (en0)
    pass in quick on utun7 inet from 10.255.255.35/32 to 192.168.60.17/32 keep state
    """ + "\n")
}

@Test func macLocalAccessFirewallHelperRequestRoundTripsOnlyValidatedPlanInputs() throws {
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.17/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.35/32"])
    let encoded = try JSONEncoder().encode(MacLocalAccessFirewallPlanRequest(plan: plan))
    let json = String(decoding: encoded, as: UTF8.self)
    #expect(json.contains("192.168.60.0\\/24"))
    #expect(!json.contains("rules"))
    let request = try JSONDecoder().decode(MacLocalAccessFirewallPlanRequest.self, from: encoded)
    #expect(try request.validatedPlan() == plan)

    let unsafeRequest = MacLocalAccessFirewallPlanRequest(
        tunnelInterfaceName: "utun7",
        routes: [.init(prefix: "8.8.8.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])
    #expect(throws: TunnelControlError.nonPrivateRoute) {
        try unsafeRequest.validatedPlan()
    }
}

@Test func macLocalAccessFirewallPlanRejectsUnsafeOrAmbiguousRules() throws {
    let hostRoute = try MacLocalAccessRoute(prefix: "10.255.255.35/32", interfaceName: "en0")
    #expect(throws: MacLocalAccessFirewallError.overlappingOverlayRoute) {
        try MacLocalAccessFirewallPlan(tunnelInterfaceName: "utun7", routes: [hostRoute],
                                       overlaySources: ["10.255.255.32/27"])
    }
    #expect(throws: MacLocalAccessFirewallError.conflictingEgressInterfaces) {
        try MacLocalAccessFirewallPlan(tunnelInterfaceName: "utun7", routes: [
            MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0"),
            MacLocalAccessRoute(prefix: "192.168.60.2/24", interfaceName: "en1"),
        ], overlaySources: ["10.255.255.32/27"])
    }
    #expect(throws: MacLocalAccessFirewallError.invalidInterface) {
        try MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0;pfctl")
    }
}

@Test func privilegedFirewallOperationsRejectInvalidPlansBeforeInvokingPF() throws {
    let runner = RecordingPFCommandRunner()
    let operations = MacLocalAccessPrivilegedOperations(commandRunner: runner,
                                                        stateStore: InMemoryLocalAccessStateStore())
    #expect(throws: MacLocalAccessPrivilegedOperationError.invalidPlan) {
        try operations.applyFirewallPlan(Data(#"{"tunnelInterfaceName":"utun7","routes":[],"overlaySources":["10.255.255.32/27"]}"#.utf8))
    }
    #expect(runner.invocations.isEmpty)

    let injection = Data(#"{"tunnelInterfaceName":"utun7","routes":[{"prefix":"192.168.60.0/24","interfaceName":"en0;touch /tmp/pwned"}],"overlaySources":["10.255.255.32/27"]}"#.utf8)
    #expect(throws: MacLocalAccessPrivilegedOperationError.invalidPlan) {
        try operations.applyFirewallPlan(injection)
    }
    #expect(runner.invocations.isEmpty)
}

@Test func privilegedHelperSchedulesNativeSystemRebootAfterResponseWindow() {
    let rebootRequestor = RecordingSystemRebootRequestor()
    let operations = MacLocalAccessPrivilegedOperations(
        commandRunner: RecordingPFCommandRunner(),
        rebootRequestor: rebootRequestor,
        stateStore: InMemoryLocalAccessStateStore())
    operations.scheduleSystemReboot()
    #expect(rebootRequestor.delays == [2])
}

@Test func privilegedFirewallOperationsUseFixedPFAnchorAndValidateTokens() throws {
    let runner = RecordingPFCommandRunner(responses: ["Token : 12345\n", ""])
    let stateStore = InMemoryLocalAccessStateStore()
    let operations = MacLocalAccessPrivilegedOperations(commandRunner: runner, stateStore: stateStore)
    let token = try operations.enablePacketFilter()
    #expect(token == "12345")
    try operations.releasePacketFilterToken(token)
    #expect(runner.invocations.map(\.arguments) == [["-E"], ["-X", "12345"]])
    #expect(try stateStore.load().packetFilterToken == nil)
    #expect(throws: MacLocalAccessPrivilegedOperationError.invalidToken) {
        try operations.releasePacketFilterToken("54321")
    }
    #expect(runner.invocations.count == 2)

    #expect(throws: MacLocalAccessPrivilegedOperationError.invalidToken) {
        try operations.releasePacketFilterToken("12345;echo unsafe")
    }
    #expect(runner.invocations.count == 2)
}

@Test func privilegedFirewallOperationsRebuildsPFRulesFromValidatedPlan() throws {
    let runner = RecordingPFCommandRunner()
    let stateStore = InMemoryLocalAccessStateStore()
    let operations = MacLocalAccessPrivilegedOperations(commandRunner: runner, stateStore: stateStore)
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])
    let request = try JSONEncoder().encode(MacLocalAccessFirewallPlanRequest(plan: plan))
    try operations.applyFirewallPlan(request)
    #expect(runner.invocations.count == 1)
    #expect(runner.invocations[0].arguments == ["-a", MacLocalAccessFirewallPlan.pfAnchor, "-f", "-"])
    #expect(runner.invocations[0].input == plan.rules)
    #expect(try stateStore.load().anchorCleanupRequired)
}

@Test func privilegedHelperPersistsForwardingBeforeMutationAndRecoversOwnedValue() throws {
    let forwarding = MockIPv4ForwardingAccess(enabled: false)
    let stateStore = InMemoryLocalAccessStateStore()
    let operations = MacLocalAccessPrivilegedOperations(
        commandRunner: RecordingPFCommandRunner(), forwarding: forwarding, stateStore: stateStore)

    try operations.setIPv4Forwarding(true)
    #expect(forwarding.isEnabledValue)
    #expect(try stateStore.load() == MacLocalAccessHelperRecoveryState(
        originalIPv4Forwarding: false, forwardingValueBeforeMutation: false,
        helperSetIPv4Forwarding: true))

    try operations.recoverOwnedState()
    #expect(!forwarding.isEnabledValue)
    #expect(try stateStore.load().isEmpty)
}

@Test func privilegedHelperRecoveryOnlyRestoresForwardingWhenItsValueIsStillOwned() throws {
    let forwarding = MockIPv4ForwardingAccess(enabled: false)
    let stateStore = InMemoryLocalAccessStateStore()
    let operations = MacLocalAccessPrivilegedOperations(
        commandRunner: RecordingPFCommandRunner(), forwarding: forwarding, stateStore: stateStore)
    try operations.setIPv4Forwarding(true)
    forwarding.setExternally(enabled: false)

    try operations.recoverOwnedState()
    #expect(!forwarding.isEnabledValue)
    #expect(try stateStore.load().isEmpty)
}

@Test func privilegedHelperRecoveryHandlesInterruptionBeforeForwardingWrite() throws {
    let forwarding = MockIPv4ForwardingAccess(enabled: false)
    let stateStore = InMemoryLocalAccessStateStore()
    let operations = MacLocalAccessPrivilegedOperations(
        commandRunner: RecordingPFCommandRunner(), forwarding: forwarding, stateStore: stateStore)
    forwarding.failNextSet()

    #expect(throws: MockForwardingAccessError.writeFailed) {
        try operations.setIPv4Forwarding(true)
    }
    #expect(try !stateStore.load().isEmpty)
    try operations.recoverOwnedState()
    #expect(!forwarding.isEnabledValue)
    #expect(try stateStore.load().isEmpty)
}

@Test func privilegedHelperRetainsRecoveryRecordWhenForwardingStateCannotBeRead() throws {
    let forwarding = MockIPv4ForwardingAccess(enabled: true)
    let stateStore = InMemoryLocalAccessStateStore(state: MacLocalAccessHelperRecoveryState(
        originalIPv4Forwarding: false, forwardingValueBeforeMutation: false,
        helperSetIPv4Forwarding: true))
    let operations = MacLocalAccessPrivilegedOperations(
        commandRunner: RecordingPFCommandRunner(), forwarding: forwarding, stateStore: stateStore)
    forwarding.failNextRead()

    #expect(throws: MockForwardingAccessError.readFailed) {
        try operations.recoverOwnedState()
    }
    #expect(try !stateStore.load().isEmpty)
}

@Test func privilegedHelperStartupRecoveryFlushesOnlyWantasticAnchorAndOwnedPFToken() throws {
    let runner = RecordingPFCommandRunner(responses: ["", ""])
    let forwarding = MockIPv4ForwardingAccess(enabled: true)
    let stateStore = InMemoryLocalAccessStateStore(state: MacLocalAccessHelperRecoveryState(
        anchorCleanupRequired: true, packetFilterToken: "9876",
        originalIPv4Forwarding: false, forwardingValueBeforeMutation: false,
        helperSetIPv4Forwarding: true))
    let operations = MacLocalAccessPrivilegedOperations(
        commandRunner: runner, forwarding: forwarding, stateStore: stateStore)

    try operations.recoverOwnedState()
    #expect(runner.invocations.map(\.arguments) == [
        ["-a", MacLocalAccessFirewallPlan.pfAnchor, "-F", "all"], ["-X", "9876"],
    ])
    #expect(!forwarding.isEnabledValue)
    #expect(try stateStore.load().isEmpty)
}

@Test func privilegedHelperRecoveryStateRejectsForgedTokensAndPartialForwardingOwnership() {
    #expect(throws: MacLocalAccessHelperStateStoreError.invalidState) {
        try MacLocalAccessHelperRecoveryState(packetFilterToken: "123;pfctl -d").validated()
    }
    #expect(throws: MacLocalAccessHelperStateStoreError.invalidState) {
        try MacLocalAccessHelperRecoveryState(originalIPv4Forwarding: false).validated()
    }
}

@Test func macLocalAccessFirewallControllerActivatesAndRestoresOnlyStateItOwns() async throws {
    let system = MockMacLocalAccessFirewallSystem()
    let controller = MacLocalAccessFirewallController(system: system)
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])

    try await controller.activate(plan)
    #expect(system.events == ["readForwarding", "readPF", "enablePF", "load", "forwardingOn"])
    #expect(system.currentRules == plan.rules)
    #expect(system.isPFEnabled)
    #expect(system.isForwardingEnabled)

    try await controller.deactivate()
    #expect(system.events.suffix(1) == ["restoreOwnedState"])
    #expect(system.currentRules.isEmpty)
    #expect(!system.isPFEnabled)
    #expect(!system.isForwardingEnabled)
}

@Test func macLocalAccessFirewallControllerPreservesPreexistingPFAndForwarding() async throws {
    let system = MockMacLocalAccessFirewallSystem(pfEnabled: true, forwardingEnabled: true)
    let controller = MacLocalAccessFirewallController(system: system)
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])

    try await controller.activate(plan)
    try await controller.deactivate()
    #expect(system.events == ["readForwarding", "readPF", "load", "restoreOwnedState"])
    #expect(system.isPFEnabled)
    #expect(system.isForwardingEnabled)
}

@Test func macLocalAccessFirewallControllerCleansPersistentOwnershipAfterControllerRestart() async throws {
    let system = MockMacLocalAccessFirewallSystem()
    let firstController = MacLocalAccessFirewallController(system: system)
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])
    try await firstController.activate(plan)

    let restartedController = MacLocalAccessFirewallController(system: system)
    try await restartedController.activate(plan)
    try await restartedController.deactivate()
    #expect(system.currentRules.isEmpty)
    #expect(!system.isPFEnabled)
    #expect(!system.isForwardingEnabled)
}

@Test func macLocalAccessFirewallControllerRollsBackBeforeFailedActivationReturns() async throws {
    let system = MockMacLocalAccessFirewallSystem()
    system.failNext("forwardingOn")
    let controller = MacLocalAccessFirewallController(system: system)
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])

    await #expect(throws: MacLocalAccessFirewallControllerError.self) {
        try await controller.activate(plan)
    }
    #expect(system.events.suffix(2) == ["forwardingOn", "restoreOwnedState"])
    #expect(system.currentRules.isEmpty)
    #expect(!system.isPFEnabled)
    #expect(!system.isForwardingEnabled)
}

@Test func macLocalAccessFirewallControllerRestoresPreviousRulesWhenUpdateFails() async throws {
    let system = MockMacLocalAccessFirewallSystem(pfEnabled: true, forwardingEnabled: true)
    let controller = MacLocalAccessFirewallController(system: system)
    let original = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])
    let replacement = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.61.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])
    try await controller.activate(original)
    system.failNext("load")

    await #expect(throws: MacLocalAccessFirewallControllerError.self) {
        try await controller.activate(replacement)
    }
    #expect(system.currentRules == original.rules)
    try await controller.deactivate()
}

@Test func macLocalAccessCoordinatorAdvertisesOnlyAfterFirewallActivationAndWithdrawsFirst() async throws {
    let system = MockMacLocalAccessFirewallSystem()
    let firewall = MacLocalAccessFirewallController(system: system)
    let sender = MockMacLocalAccessRouteSender(system: system)
    let coordinator = MacLocalAccessRouteCoordinator(firewall: firewall, sender: sender)
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])

    try await coordinator.activate(plan)
    #expect(system.events.suffix(3) == ["load", "forwardingOn", "advertise"])
    #expect(try TunnelControlCodec.decode(sender.payloads[0]) == .setLocalAccessRoutes([
        TunnelIPv4Prefix("192.168.60.0/24")
    ]))

    try await coordinator.deactivate()
    #expect(system.events.suffix(2) == ["withdraw", "restoreOwnedState"])
    #expect(system.currentRules.isEmpty)
}

@Test func macLocalAccessCoordinatorRollsBackWhenAdvertisementFails() async throws {
    let system = MockMacLocalAccessFirewallSystem()
    let firewall = MacLocalAccessFirewallController(system: system)
    let sender = MockMacLocalAccessRouteSender(system: system)
    sender.failNext()
    let coordinator = MacLocalAccessRouteCoordinator(firewall: firewall, sender: sender)
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])

    await #expect(throws: MacLocalAccessRouteCoordinatorError.self) {
        try await coordinator.activate(plan)
    }
    #expect(system.events.suffix(3) == ["advertise", "withdraw", "restoreOwnedState"])
    #expect(system.currentRules.isEmpty)
    #expect(!system.isForwardingEnabled)
}

@Test func macLocalAccessCoordinatorPreservesForwardingWhenAdvertisementAndWithdrawalFail() async throws {
    let system = MockMacLocalAccessFirewallSystem()
    let firewall = MacLocalAccessFirewallController(system: system)
    let sender = MockMacLocalAccessRouteSender(system: system)
    sender.failNext(count: 2)
    let coordinator = MacLocalAccessRouteCoordinator(firewall: firewall, sender: sender)
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])

    await #expect(throws: MacLocalAccessRouteCoordinatorError.self) {
        try await coordinator.activate(plan)
    }
    #expect(system.currentRules == plan.rules)
    #expect(system.isForwardingEnabled)
    #expect(system.events.suffix(3) == ["forwardingOn", "advertise", "withdraw"])

    try await coordinator.deactivate()
    #expect(system.currentRules.isEmpty)
    #expect(!system.isForwardingEnabled)
}

@Test func macLocalAccessCoordinatorKeepsForwardingUntilRouteWithdrawalSucceeds() async throws {
    let system = MockMacLocalAccessFirewallSystem()
    let firewall = MacLocalAccessFirewallController(system: system)
    let sender = MockMacLocalAccessRouteSender(system: system)
    let coordinator = MacLocalAccessRouteCoordinator(firewall: firewall, sender: sender)
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])
    try await coordinator.activate(plan)
    sender.failNext()

    await #expect(throws: MacLocalAccessRouteCoordinatorError.self) {
        try await coordinator.deactivate()
    }
    #expect(system.events.suffix(1) == ["withdraw"])
    #expect(system.currentRules == plan.rules)
    #expect(system.isForwardingEnabled)
}

@Test func macLocalAccessCoordinatorCanRetryFirewallCleanupAfterWithdrawal() async throws {
    let system = MockMacLocalAccessFirewallSystem()
    let firewall = MacLocalAccessFirewallController(system: system)
    let sender = MockMacLocalAccessRouteSender(system: system)
    let coordinator = MacLocalAccessRouteCoordinator(firewall: firewall, sender: sender)
    let plan = try MacLocalAccessFirewallPlan(
        tunnelInterfaceName: "utun7",
        routes: [MacLocalAccessRoute(prefix: "192.168.60.0/24", interfaceName: "en0")],
        overlaySources: ["10.255.255.32/27"])
    try await coordinator.activate(plan)
    system.failNext("restoreOwnedState")

    await #expect(throws: MacLocalAccessRouteCoordinatorError.self) {
        try await coordinator.deactivate()
    }
    #expect(system.isForwardingEnabled)
    try await coordinator.deactivate()
    #expect(!system.isForwardingEnabled)
    #expect(system.currentRules.isEmpty)
}

@Test func macLocalAccessProviderManagerEnablesOnlyDiscoveredHostRoutes() async throws {
    let configuration = try WireGuardConfiguration.parse("""
    [Interface]
    PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Address = 10.255.255.35/32
    [Peer]
    PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Endpoint = 127.0.0.1:51820
    AllowedIPs = 10.255.255.32/27
    PersistentKeepalive = 25
    """)
    let discovered = [try MacLocalAccessRoute(prefix: "192.168.1.7/32", interfaceName: "en0")]
    let system = MockMacLocalAccessFirewallSystem()
    let sender = MockMacLocalAccessRouteSender(system: system)
    let manager = MacLocalAccessProviderManager(
        configuration: configuration,
        sender: sender,
        firewall: MacLocalAccessFirewallController(system: system),
        routeDiscovery: { discovered },
        interfaceResolver: { _ in "utun9" })

    try await manager.enable(routes: ["192.168.1.7/32"])
    #expect(await manager.isEnabled())
    #expect(system.currentRules.contains("nat on en0 inet from 10.255.255.35/32 to 192.168.1.7/32"))
    #expect(try TunnelControlCodec.decode(try #require(sender.payloads.first)) ==
            .setLocalAccessRoutes([TunnelIPv4Prefix("192.168.1.7/32")]))

    await #expect(throws: MacLocalAccessProviderError.invalidRouteSelection) {
        try await manager.enable(routes: ["192.168.2.0/24"])
    }
    try await manager.disable()
    #expect(!(await manager.isEnabled()))
}

@Test func macLocalAccessProviderManagerFailsClosedWithoutTunnelInterface() async throws {
    let configuration = try WireGuardConfiguration.parse("""
    [Interface]
    PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Address = 10.255.255.35/32
    [Peer]
    PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Endpoint = 127.0.0.1:51820
    AllowedIPs = 10.255.255.32/27
    PersistentKeepalive = 25
    """)
    let system = MockMacLocalAccessFirewallSystem()
    let manager = MacLocalAccessProviderManager(
        configuration: configuration,
        sender: MockMacLocalAccessRouteSender(system: system),
        firewall: MacLocalAccessFirewallController(system: system),
        routeDiscovery: { [try MacLocalAccessRoute(prefix: "192.168.1.0/24", interfaceName: "en0")] },
        interfaceResolver: { _ in nil })

    await #expect(throws: MacLocalAccessProviderError.tunnelInterfaceNotFound) {
        try await manager.enable(routes: ["192.168.1.0/24"])
    }
    #expect(system.events.isEmpty)
}

private final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    private struct StubResponse {
        let status: Int
        let body: Data
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var responses: [String: StubResponse] = [:]
    nonisolated(unsafe) private static var requests: [String: URLRequest] = [:]
    nonisolated(unsafe) private static var requestBodies: [String: Data] = [:]

    static func configure(status: Int, body: Data, host: String, path: String) {
        lock.lock()
        let key = host + path
        responses[key] = StubResponse(status: status, body: body)
        requests[key] = nil
        requestBodies[key] = nil
        lock.unlock()
    }

    static func lastRequest(host: String, path: String) -> URLRequest? {
        lock.lock()
        defer { lock.unlock() }
        return requests[host + path]
    }

    static func lastBody(host: String, path: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return requestBodies[host + path]
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        let path = request.url?.path ?? "/"
        let key = (request.url?.host ?? "") + path
        let stub = Self.responses[key]
        Self.requests[key] = request
        if let body = request.httpBody ?? Self.readBody(request.httpBodyStream) {
            Self.requestBodies[key] = body
        }
        Self.lock.unlock()
        guard let url = request.url,
              let stub,
              let response = HTTPURLResponse(url: url, statusCode: stub.status, httpVersion: "HTTP/1.1", headerFields: nil) else {
            client?.urlProtocol(self, didFailWithError: WUSPTransportError.malformed)
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: stub.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func readBody(_ stream: InputStream?) -> Data? {
        guard let stream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count < 0 { return nil }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
            if data.count > 64 * 1024 { return nil }
        }
        return data
    }
}

private final class MemoryCredentialPersistence: CredentialPersistence, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]

    func read(account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return values[account]
    }

    func write(_ data: Data, account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values[account] = data
    }

    func delete(account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values.removeValue(forKey: account)
    }

    func put(_ data: Data, account: String) {
        lock.lock()
        defer { lock.unlock() }
        values[account] = data
    }
}

private final class WUSPTestInvocationCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    func increment() {
        lock.lock()
        count += 1
        lock.unlock()
    }
}

private final class MemoryWUSPEventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storedPayloads: [Data] = []

    var payloads: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return storedPayloads
    }

    func append(_ payload: Data) {
        lock.lock()
        defer { lock.unlock() }
        storedPayloads.append(payload)
    }
}

private func makeLoopbackUDPListener(echo: Bool) async throws -> (NWListener, UInt16) {
    let listener = try NWListener(using: .udp, on: .any)
    let queue = DispatchQueue(label: "wantastic.tests.udp.p2p.\(UUID().uuidString)")
    listener.newConnectionHandler = { connection in
        connection.start(queue: queue)
        guard echo else { return }
        connection.receiveMessage { datagram, _, _, error in
            guard error == nil, let datagram else { return }
            connection.send(content: datagram, completion: .contentProcessed { _ in })
        }
    }
    let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let port = listener.port?.rawValue else {
                    continuation.resume(throwing: WireGuardUDPError.invalidEndpoint)
                    return
                }
                continuation.resume(returning: port)
            case let .failed(error): continuation.resume(throwing: error)
            default: break
            }
        }
        listener.start(queue: queue)
    }
    return (listener, port)
}

private func makeLoopbackListener() throws -> (Int32, UInt16) {
    let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    guard descriptor >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = 0
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let bindResult = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bindResult == 0, Darwin.listen(descriptor, 1) == 0 else {
        let error = POSIXError(.init(rawValue: errno) ?? .EIO)
        Darwin.close(descriptor)
        throw error
    }
    var bound = sockaddr_in()
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let result = withUnsafeMutablePointer(to: &bound) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.getsockname(descriptor, $0, &length)
        }
    }
    guard result == 0 else {
        let error = POSIXError(.init(rawValue: errno) ?? .EIO)
        Darwin.close(descriptor)
        throw error
    }
    return (descriptor, UInt16(bigEndian: bound.sin_port))
}

private actor PacketFlowRouteRecorder {
    private var direct = 0
    private var demoted = 0
    private var relay = 0

    func directAttempted() { direct += 1 }
    func directDemoted() { demoted += 1 }
    func relayAttempted() { relay += 1 }
    func counts() -> (direct: Int, demoted: Int, relay: Int) { (direct, demoted, relay) }
}

private final class RecordingPFCommandRunner: PFCommandExecuting, @unchecked Sendable {
    struct Invocation: Equatable {
        let arguments: [String]
        let input: String?
    }

    private let lock = NSLock()
    private var storedInvocations: [Invocation] = []
    private var responses: [String]

    init(responses: [String] = []) { self.responses = responses }

    var invocations: [Invocation] { lock.withLock { storedInvocations } }

    func run(arguments: [String], input: String?) throws -> String {
        lock.withLock {
            storedInvocations.append(Invocation(arguments: arguments, input: input))
            return responses.isEmpty ? "" : responses.removeFirst()
        }
    }
}

private final class RecordingSystemRebootRequestor: SystemRebootRequesting, @unchecked Sendable {
    private let lock = NSLock()
    private var scheduledDelays: [TimeInterval] = []

    var delays: [TimeInterval] { lock.withLock { scheduledDelays } }

    func schedule(after delay: TimeInterval) {
        lock.withLock { scheduledDelays.append(delay) }
    }
}

private final class InMemoryLocalAccessStateStore: MacLocalAccessHelperStateStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var state: MacLocalAccessHelperRecoveryState

    init(state: MacLocalAccessHelperRecoveryState = MacLocalAccessHelperRecoveryState()) {
        self.state = state
    }

    func load() throws -> MacLocalAccessHelperRecoveryState {
        lock.withLock { state }
    }

    func save(_ state: MacLocalAccessHelperRecoveryState) throws {
        let validated = try state.validated()
        lock.withLock { self.state = validated }
    }

    func clear() throws {
        lock.withLock { state = MacLocalAccessHelperRecoveryState() }
    }
}

private final class MockIPv4ForwardingAccess: IPv4ForwardingAccess, @unchecked Sendable {
    private let lock = NSLock()
    private var enabled: Bool
    private var failNextWrite = false
    private var shouldFailNextRead = false

    init(enabled: Bool) { self.enabled = enabled }

    var isEnabledValue: Bool { lock.withLock { enabled } }

    func isEnabled() throws -> Bool {
        try lock.withLock {
            if shouldFailNextRead {
                shouldFailNextRead = false
                throw MockForwardingAccessError.readFailed
            }
            return enabled
        }
    }

    func setEnabled(_ enabled: Bool) throws {
        try lock.withLock {
            if failNextWrite {
                failNextWrite = false
                throw MockForwardingAccessError.writeFailed
            }
            self.enabled = enabled
        }
    }

    func failNextSet() { lock.withLock { failNextWrite = true } }
    func failNextRead() { lock.withLock { shouldFailNextRead = true } }

    func setExternally(enabled: Bool) {
        lock.withLock { self.enabled = enabled }
    }
}

private enum MockForwardingAccessError: Error, Equatable {
    case writeFailed
    case readFailed
}

private extension Data {
    init?(hexEncoded value: String) {
        guard value.count.isMultiple(of: 2) else { return nil }
        var output = Data()
        output.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
            output.append(byte)
            index = next
        }
        self = output
    }
}
