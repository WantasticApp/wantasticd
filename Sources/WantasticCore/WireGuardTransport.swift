import CryptoKit
import Foundation

public enum WireGuardTransportError: Error, Equatable {
    case invalidKey
    case malformedPacket
    case wrongReceiver
    case replayedOrOutOfWindow
    case authenticationFailed
    case counterExhausted
    case unsupportedMessageType
    case invalidMTU
}

/// Encrypted data message types supported by Wantastic's deployed Go peer.
public enum WireGuardEncryptedMessageType: UInt32, Equatable, Sendable {
    case transport = 4
    case tunnelControl = 7
    case wuspControl = 8
}

public enum WireGuardPacketPadding {
    /// Mirrors `device.calculatePaddingSize` in the bundled Go WireGuard peer.
    public static func pad(_ packet: Data, mtu: Int) throws -> Data {
        guard (576...9000).contains(mtu) else { throw WireGuardTransportError.invalidMTU }
        var lastUnit = packet.count
        if lastUnit > mtu { lastUnit %= mtu }
        var paddedSize = (lastUnit + 15) & ~15
        if paddedSize > mtu { paddedSize = mtu }
        var result = packet
        result.append(Data(repeating: 0, count: paddedSize - lastUnit))
        return result
    }

    /// Removes WireGuard transport padding using the inner IP length fields,
    /// as the Go receive path does before source-address authorization.
    public static func trimIPPacket(_ packet: Data) throws -> Data {
        guard let version = packet.first.map({ $0 >> 4 }) else { throw WireGuardTransportError.malformedPacket }
        switch version {
        case 4:
            guard packet.count >= 20 else { throw WireGuardTransportError.malformedPacket }
            let headerLength = Int(packet[0] & 0x0f) * 4
            let length = Int(packet[2]) << 8 | Int(packet[3])
            guard headerLength >= 20, headerLength <= length, length <= packet.count else {
                throw WireGuardTransportError.malformedPacket
            }
            return Data(packet.prefix(length))
        case 6:
            guard packet.count >= 40 else { throw WireGuardTransportError.malformedPacket }
            let length = 40 + (Int(packet[4]) << 8 | Int(packet[5]))
            guard length <= packet.count else { throw WireGuardTransportError.malformedPacket }
            return Data(packet.prefix(length))
        default:
            throw WireGuardTransportError.malformedPacket
        }
    }
}

/// WireGuard transport encryption and framing. Replay state is maintained per
/// receiver/session and must not be shared across peers.
public struct WireGuardTransportCipher: Sendable {
    public static let headerLength = 16
    public static let authenticationTagLength = 16
    public static let maximumPacketLength = 65_535
    public static let rejectAfterMessages = UInt64.max - 8192

    private let key: SymmetricKey
    private let receiverIndex: UInt32
    private var replayFilter: WireGuardReplayFilter
    private var highestSentCounter: UInt64?

    public init(key: Data, receiverIndex: UInt32) throws {
        guard key.count == 32 else { throw WireGuardTransportError.invalidKey }
        self.key = SymmetricKey(data: key)
        self.receiverIndex = receiverIndex
        self.replayFilter = WireGuardReplayFilter()
        self.highestSentCounter = nil
    }

    public mutating func seal(plaintext: Data, counter: UInt64,
                              messageType: WireGuardEncryptedMessageType = .transport) throws -> Data {
        guard plaintext.count <= Self.maximumPacketLength - Self.headerLength - Self.authenticationTagLength else {
            throw WireGuardTransportError.malformedPacket
        }
        guard counter < Self.rejectAfterMessages else { throw WireGuardTransportError.counterExhausted }
        if let highestSentCounter, counter <= highestSentCounter {
            throw WireGuardTransportError.replayedOrOutOfWindow
        }
        let nonce = try Self.nonce(counter)
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)
        var packet = Data()
        Self.appendLittleEndian(messageType.rawValue, to: &packet)
        Self.appendLittleEndian(receiverIndex, to: &packet)
        Self.appendLittleEndian(counter, to: &packet)
        packet.append(contentsOf: box.ciphertext)
        packet.append(contentsOf: box.tag)
        highestSentCounter = counter
        return packet
    }

    /// Opens packets within WireGuard's RFC 6479 sliding replay window.
    public mutating func open(_ packet: Data) throws -> (messageType: WireGuardEncryptedMessageType,
                                                         counter: UInt64, plaintext: Data) {
        let bytes = Array(packet)
        guard packet.count >= Self.headerLength + Self.authenticationTagLength,
              packet.count <= Self.maximumPacketLength,
              bytes[1] == 0, bytes[2] == 0, bytes[3] == 0 else {
            throw WireGuardTransportError.malformedPacket
        }
        guard let messageType = WireGuardEncryptedMessageType(rawValue: UInt32(bytes[0])) else {
            throw WireGuardTransportError.unsupportedMessageType
        }
        let actualReceiver = Self.readUInt32(bytes, 4)
        guard actualReceiver == receiverIndex else { throw WireGuardTransportError.wrongReceiver }
        let counter = Self.readUInt64(bytes, 8)
        guard counter < Self.rejectAfterMessages else { throw WireGuardTransportError.counterExhausted }
        let nonce = try Self.nonce(counter)
        let box = try ChaChaPoly.SealedBox(nonce: nonce,
                                           ciphertext: Data(bytes[Self.headerLength..<(bytes.count - 16)]),
                                           tag: Data(bytes.suffix(16)))
        let plaintext: Data
        do {
            plaintext = try ChaChaPoly.open(box, using: key)
        } catch {
            throw WireGuardTransportError.authenticationFailed
        }
        guard replayFilter.validate(counter: counter, limit: Self.rejectAfterMessages) else {
            throw WireGuardTransportError.replayedOrOutOfWindow
        }
        return (messageType, counter, plaintext)
    }

    private static func nonce(_ counter: UInt64) throws -> ChaChaPoly.Nonce {
        var bytes = Data([0, 0, 0, 0])
        appendLittleEndian(counter, to: &bytes)
        return try ChaChaPoly.Nonce(data: bytes)
    }

    private static func appendLittleEndian(_ value: UInt32, to data: inout Data) {
        for shift in stride(from: 0, through: 24, by: 8) { data.append(UInt8((value >> shift) & 0xff)) }
    }

    private static func appendLittleEndian(_ value: UInt64, to data: inout Data) {
        for shift in stride(from: 0, through: 56, by: 8) { data.append(UInt8((value >> shift) & 0xff)) }
    }

    private static func readUInt32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[offset + $1]) << UInt32($1 * 8) }
    }

    private static func readUInt64(_ bytes: [UInt8], _ offset: Int) -> UInt64 {
        (0..<8).reduce(UInt64(0)) { $0 | UInt64(bytes[offset + $1]) << UInt64($1 * 8) }
    }
}

/// RFC 6479 ring filter, matching the bundled Go WireGuard implementation.
struct WireGuardReplayFilter: Sendable {
    private static let blockShift = 6
    private static let blockCount = 128
    private static let blockMask: UInt64 = UInt64(blockCount - 1)
    private static let windowSize: UInt64 = UInt64((blockCount - 1) * 64)
    private var last: UInt64 = 0
    private var ring = [UInt64](repeating: 0, count: blockCount)

    mutating func validate(counter: UInt64, limit: UInt64) -> Bool {
        guard counter < limit else { return false }
        let indexBlock = counter >> Self.blockShift
        if counter > last {
            let current = last >> Self.blockShift
            var diff = indexBlock - current
            if diff > UInt64(Self.blockCount) { diff = UInt64(Self.blockCount) }
            if diff > 0 {
                for offset in 1...diff {
                    ring[Int((current + offset) & Self.blockMask)] = 0
                }
            }
            last = counter
        } else if last - counter > Self.windowSize {
            return false
        }
        let block = Int(indexBlock & Self.blockMask)
        let bit = UInt64(1) << (counter & 63)
        guard ring[block] & bit == 0 else { return false }
        ring[block] |= bit
        return true
    }
}
