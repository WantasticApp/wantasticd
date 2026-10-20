import Foundation

public enum WireGuardInitiatorError: Error, Equatable {
    case invalidState
    case wrongReceiver
    case unauthenticatedPacket
    case missingCookieContext
}

public struct WireGuardNegotiatedSession: Equatable, Sendable {
    public let peerSenderIndex: UInt32
    public let keys: WireGuardSessionKeys
}

/// Stateful initiator-side composition of the Noise transcript, fixed packet
/// layouts, MAC1/MAC2, and cookie replies. UDP retransmission/timers and
/// responder timestamp-replay state remain responsibilities of the session.
public struct WireGuardInitiator: Sendable {
    private enum State: Equatable, Sendable { case ready, awaitingResponse, complete }

    private let senderIndex: UInt32
    private let outboundAuthenticator: WireGuardMessageAuthenticator
    private let inboundAuthenticator: WireGuardMessageAuthenticator
    private var noise: WireGuardNoiseHandshake
    private var state: State = .ready
    private var unsignedInitiation: Data?
    private var lastMAC1: Data?

    public init(localPrivateKey: Data, remoteStaticPublicKey: Data,
                presharedKey: Data = Data(repeating: 0, count: 32), senderIndex: UInt32) throws {
        let localKey = try WireGuardKeyAgreement(privateKey: localPrivateKey)
        self.senderIndex = senderIndex
        self.outboundAuthenticator = try WireGuardMessageAuthenticator(
            receiverStaticPublicKey: remoteStaticPublicKey
        )
        self.inboundAuthenticator = try WireGuardMessageAuthenticator(
            receiverStaticPublicKey: localKey.publicKey
        )
        self.noise = try WireGuardNoiseHandshake(role: .initiator, localPrivateKey: localPrivateKey,
                                                 remoteStaticPublicKey: remoteStaticPublicKey,
                                                 presharedKey: presharedKey)
    }

    public mutating func begin(timestamp: Data) throws -> Data {
        guard state == .ready else { throw WireGuardInitiatorError.invalidState }
        let payload = try noise.createInitiation(timestamp: timestamp)
        let prefix = try WireGuardHandshakePacketCodec.encodeInitiationPrefix(senderIndex: senderIndex,
                                                                              payload: payload)
        let packet = try outboundAuthenticator.addMACs(to: prefix)
        unsignedInitiation = prefix
        lastMAC1 = Data(packet[116..<132])
        state = .awaitingResponse
        return packet
    }

    /// Opens a cookie challenge for the most recently sent initiation and
    /// returns that same Noise message with a fresh MAC2 for retransmission.
    public mutating func retry(afterCookieReply packet: Data) throws -> Data {
        guard state == .awaitingResponse, let unsignedInitiation, let lastMAC1 else {
            throw WireGuardInitiatorError.missingCookieContext
        }
        let reply = try WireGuardHandshakePacketCodec.decodeCookieReply(packet)
        guard reply.receiverIndex == senderIndex else { throw WireGuardInitiatorError.wrongReceiver }
        let cookie: Data
        do {
            cookie = try inboundAuthenticator.openCookieReply(reply, authenticatingLastMAC1: lastMAC1)
        } catch {
            throw WireGuardInitiatorError.unauthenticatedPacket
        }
        let retry = try outboundAuthenticator.addMACs(to: unsignedInitiation, cookie: cookie)
        self.lastMAC1 = Data(retry[116..<132])
        return retry
    }

    public mutating func receiveResponse(_ packet: Data) throws -> WireGuardSessionKeys {
        try receiveResponseWithPeerIndex(packet).keys
    }

    public mutating func receiveResponseWithPeerIndex(_ packet: Data) throws -> WireGuardNegotiatedSession {
        guard state == .awaitingResponse else { throw WireGuardInitiatorError.invalidState }
        let response = try WireGuardHandshakePacketCodec.decodeResponse(packet)
        guard response.receiverIndex == senderIndex else { throw WireGuardInitiatorError.wrongReceiver }
        guard inboundAuthenticator.verifiesMAC1(in: packet) else {
            throw WireGuardInitiatorError.unauthenticatedPacket
        }
        let keys = try noise.consumeResponse(response.payload)
        state = .complete
        unsignedInitiation = nil
        lastMAC1 = nil
        return WireGuardNegotiatedSession(peerSenderIndex: response.senderIndex, keys: keys)
    }
}
