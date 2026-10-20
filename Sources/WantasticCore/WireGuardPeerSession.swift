import Foundation

public enum WireGuardPeerSessionError: Error, Equatable {
    case invalidState
    case malformedDatagram
    case unsupportedMessage
}

public enum WireGuardPeerSessionEvent: Equatable, Sendable {
    case retransmitHandshake(Data)
    case established(peerSenderIndex: UInt32)
    case received(messageType: WireGuardEncryptedMessageType, counter: UInt64, plaintext: Data)
    case wuspControlPayload(Data)
}

/// Serial, per-peer WireGuard initiator state. A caller must serialize access
/// to this value and drive retransmission/rekey/keepalive timers externally.
public struct WireGuardPeerSession: Sendable {
    private enum State: Equatable { case ready, handshaking, active }

    private let localSenderIndex: UInt32
    private let mtu: Int
    private var initiator: WireGuardInitiator
    private var state: State = .ready
    private var peerSenderIndex: UInt32?
    private var sendCipher: WireGuardTransportCipher?
    private var receiveCipher: WireGuardTransportCipher?
    private var sendCounter: UInt64 = 0

    public init(localPrivateKey: Data, peerStaticPublicKey: Data,
                presharedKey: Data = Data(repeating: 0, count: 32), localSenderIndex: UInt32,
                mtu: Int = 1420) throws {
        guard (576...9000).contains(mtu) else { throw WireGuardTransportError.invalidMTU }
        self.localSenderIndex = localSenderIndex
        self.mtu = mtu
        self.initiator = try WireGuardInitiator(localPrivateKey: localPrivateKey,
                                                remoteStaticPublicKey: peerStaticPublicKey,
                                                presharedKey: presharedKey,
                                                senderIndex: localSenderIndex)
    }

    public var isEstablished: Bool { state == .active }

    public mutating func begin(timestamp: Data) throws -> Data {
        guard state == .ready else { throw WireGuardPeerSessionError.invalidState }
        let packet = try initiator.begin(timestamp: timestamp)
        state = .handshaking
        return packet
    }

    public mutating func receive(_ datagram: Data) throws -> WireGuardPeerSessionEvent {
        guard let type = datagram.first else { throw WireGuardPeerSessionError.malformedDatagram }
        switch type {
        case 3:
            guard state == .handshaking else { throw WireGuardPeerSessionError.invalidState }
            return .retransmitHandshake(try initiator.retry(afterCookieReply: datagram))
        case 2:
            guard state == .handshaking else { throw WireGuardPeerSessionError.invalidState }
            let negotiated = try initiator.receiveResponseWithPeerIndex(datagram)
            let send = try WireGuardTransportCipher(key: negotiated.keys.send,
                                                    receiverIndex: negotiated.peerSenderIndex)
            let receive = try WireGuardTransportCipher(key: negotiated.keys.receive,
                                                       receiverIndex: localSenderIndex)
            peerSenderIndex = negotiated.peerSenderIndex
            sendCipher = send
            receiveCipher = receive
            state = .active
            return .established(peerSenderIndex: negotiated.peerSenderIndex)
        case 4, 7, 8:
            guard state == .active, var receiveCipher else { throw WireGuardPeerSessionError.invalidState }
            let opened = try receiveCipher.open(datagram)
            self.receiveCipher = receiveCipher
            let plaintext = opened.messageType == .transport && !opened.plaintext.isEmpty
                ? try WireGuardPacketPadding.trimIPPacket(opened.plaintext)
                : opened.plaintext
            return .received(messageType: opened.messageType, counter: opened.counter, plaintext: plaintext)
        default:
            throw WireGuardPeerSessionError.unsupportedMessage
        }
    }

    public mutating func encrypt(_ plaintext: Data,
                                 messageType: WireGuardEncryptedMessageType = .transport) throws -> Data {
        guard state == .active, var sendCipher else { throw WireGuardPeerSessionError.invalidState }
        guard sendCounter < WireGuardTransportCipher.rejectAfterMessages else {
            throw WireGuardTransportError.counterExhausted
        }
        let padded = try WireGuardPacketPadding.pad(plaintext, mtu: mtu)
        let datagram = try sendCipher.seal(plaintext: padded, counter: sendCounter,
                                           messageType: messageType)
        sendCounter += 1
        self.sendCipher = sendCipher
        return datagram
    }
}
