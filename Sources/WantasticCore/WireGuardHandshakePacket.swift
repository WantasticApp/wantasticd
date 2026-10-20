import Foundation
import CryptoKit

public struct WireGuardInitiationPacket: Equatable, Sendable {
    public let senderIndex: UInt32
    public let payload: WireGuardInitiationPayload
    public let mac1: Data
    public let mac2: Data
}

public struct WireGuardResponsePacket: Equatable, Sendable {
    public let senderIndex: UInt32
    public let receiverIndex: UInt32
    public let payload: WireGuardResponsePayload
    public let mac1: Data
    public let mac2: Data
}

public struct WireGuardCookieReply: Equatable, Sendable {
    public let receiverIndex: UInt32
    public let nonce: Data
    public let encryptedCookie: Data
}

public enum WireGuardPacketError: Error, Equatable {
    case malformed
    case invalidKey
    case invalidCookie
    case cookieAuthenticationFailed
}

/// Serializes the fixed WireGuard handshake packets. Decoding validates shape;
/// callers must verify MAC1 before passing initiation/response payloads to the
/// Noise transcript.
public enum WireGuardHandshakePacketCodec {
    public static let initiationLength = 148
    public static let responseLength = 92
    public static let cookieReplyLength = 64
    private static let initiationPrefixLength = 116
    private static let responsePrefixLength = 60

    public static func encodeInitiationPrefix(senderIndex: UInt32,
                                              payload: WireGuardInitiationPayload) throws -> Data {
        guard payload.ephemeralPublicKey.count == 32, payload.encryptedStaticKey.count == 48,
              payload.encryptedTimestamp.count == 28 else { throw WireGuardPacketError.malformed }
        var packet = Data([1, 0, 0, 0])
        appendLittleEndian(senderIndex, to: &packet)
        packet.append(contentsOf: payload.ephemeralPublicKey)
        packet.append(contentsOf: payload.encryptedStaticKey)
        packet.append(contentsOf: payload.encryptedTimestamp)
        return packet
    }

    public static func encodeResponsePrefix(senderIndex: UInt32, receiverIndex: UInt32,
                                            payload: WireGuardResponsePayload) throws -> Data {
        guard payload.ephemeralPublicKey.count == 32, payload.encryptedEmpty.count == 16 else {
            throw WireGuardPacketError.malformed
        }
        var packet = Data([2, 0, 0, 0])
        appendLittleEndian(senderIndex, to: &packet)
        appendLittleEndian(receiverIndex, to: &packet)
        packet.append(contentsOf: payload.ephemeralPublicKey)
        packet.append(contentsOf: payload.encryptedEmpty)
        return packet
    }

    public static func decodeInitiation(_ packet: Data) throws -> WireGuardInitiationPacket {
        let bytes = Array(packet)
        guard bytes.count == initiationLength, bytes[0] == 1, bytes[1...3].allSatisfy({ $0 == 0 }) else {
            throw WireGuardPacketError.malformed
        }
        let payload = WireGuardInitiationPayload(
            ephemeralPublicKey: Data(bytes[8..<40]),
            encryptedStaticKey: Data(bytes[40..<88]),
            encryptedTimestamp: Data(bytes[88..<116])
        )
        return WireGuardInitiationPacket(senderIndex: readLittleEndian(bytes, 4), payload: payload,
                                         mac1: Data(bytes[116..<132]), mac2: Data(bytes[132..<148]))
    }

    public static func decodeResponse(_ packet: Data) throws -> WireGuardResponsePacket {
        let bytes = Array(packet)
        guard bytes.count == responseLength, bytes[0] == 2, bytes[1...3].allSatisfy({ $0 == 0 }) else {
            throw WireGuardPacketError.malformed
        }
        let payload = WireGuardResponsePayload(ephemeralPublicKey: Data(bytes[12..<44]),
                                               encryptedEmpty: Data(bytes[44..<60]))
        return WireGuardResponsePacket(senderIndex: readLittleEndian(bytes, 4),
                                       receiverIndex: readLittleEndian(bytes, 8), payload: payload,
                                       mac1: Data(bytes[60..<76]), mac2: Data(bytes[76..<92]))
    }

    public static func encodeCookieReply(_ reply: WireGuardCookieReply) throws -> Data {
        guard reply.nonce.count == 24, reply.encryptedCookie.count == 32 else {
            throw WireGuardPacketError.malformed
        }
        var packet = Data([3, 0, 0, 0])
        appendLittleEndian(reply.receiverIndex, to: &packet)
        packet.append(contentsOf: reply.nonce)
        packet.append(contentsOf: reply.encryptedCookie)
        return packet
    }

    public static func decodeCookieReply(_ packet: Data) throws -> WireGuardCookieReply {
        let bytes = Array(packet)
        guard bytes.count == cookieReplyLength, bytes[0] == 3, bytes[1...3].allSatisfy({ $0 == 0 }) else {
            throw WireGuardPacketError.malformed
        }
        return WireGuardCookieReply(receiverIndex: readLittleEndian(bytes, 4),
                                    nonce: Data(bytes[8..<32]), encryptedCookie: Data(bytes[32..<64]))
    }

    fileprivate static func validUnsignedHandshakePrefix(_ packet: Data) -> Bool {
        let bytes = Array(packet)
        return (bytes.count == initiationPrefixLength && bytes[0] == 1 ||
                bytes.count == responsePrefixLength && bytes[0] == 2) &&
            bytes[1...3].allSatisfy({ $0 == 0 })
    }

    private static func appendLittleEndian(_ value: UInt32, to data: inout Data) {
        data.append(UInt8(value & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 24) & 0xff))
    }

    private static func readLittleEndian(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | (UInt32(bytes[offset + 1]) << 8) |
            (UInt32(bytes[offset + 2]) << 16) | (UInt32(bytes[offset + 3]) << 24)
    }
}

/// WireGuard MAC1/MAC2 using keyed BLAKE2s-128, matching the Go CookieGenerator
/// and CookieChecker. MAC2 cookies are supplied by the caller after the
/// separate XChaCha20-Poly1305 cookie-reply flow has authenticated them.
public struct WireGuardMessageAuthenticator: Sendable {
    private let mac1Key: Data
    private let cookieEncryptionKey: Data

    public init(receiverStaticPublicKey: Data) throws {
        guard receiverStaticPublicKey.count == 32 else { throw WireGuardPacketError.invalidKey }
        var label = Data("mac1----".utf8)
        label.append(contentsOf: receiverStaticPublicKey)
        mac1Key = WireGuardKDF.blake2s(label)
        label = Data("cookie--".utf8)
        label.append(contentsOf: receiverStaticPublicKey)
        cookieEncryptionKey = WireGuardKDF.blake2s(label)
    }

    /// Opens a WireGuard type-3 cookie reply. WireGuard authenticates the
    /// encrypted cookie against the MAC1 from the handshake packet that
    /// triggered the reply; callers must also match the receiver index.
    public func openCookieReply(_ reply: WireGuardCookieReply,
                                authenticatingLastMAC1 mac1: Data) throws -> Data {
        guard reply.nonce.count == 24, reply.encryptedCookie.count == 32,
              mac1.count == 16 else { throw WireGuardPacketError.malformed }
        do {
            let cookie = try Self.xchacha20Poly1305Open(key: cookieEncryptionKey, nonce: reply.nonce,
                                                        ciphertext: reply.encryptedCookie, aad: mac1)
            guard cookie.count == 16 else { throw WireGuardPacketError.invalidCookie }
            return cookie
        } catch let error as WireGuardPacketError {
            throw error
        } catch {
            throw WireGuardPacketError.cookieAuthenticationFailed
        }
    }

    public func addMACs(to unsignedPacket: Data, cookie: Data? = nil) throws -> Data {
        guard WireGuardHandshakePacketCodec.validUnsignedHandshakePrefix(unsignedPacket) else {
            throw WireGuardPacketError.malformed
        }
        if let cookie, cookie.count != 16 { throw WireGuardPacketError.invalidCookie }
        var packet = Data()
        packet.append(contentsOf: unsignedPacket)
        packet.append(Data(repeating: 0, count: 32))

        let mac1 = WireGuardKDF.blake2s128(key: mac1Key, message: unsignedPacket)
        let mac1Start = packet.count - 32
        packet.replaceSubrange(mac1Start..<(mac1Start + 16), with: mac1)
        if let cookie {
            let mac2Input = Data(packet.prefix(packet.count - 16))
            let mac2 = WireGuardKDF.blake2s128(key: cookie, message: mac2Input)
            packet.replaceSubrange((packet.count - 16)..<packet.count, with: mac2)
        }
        return packet
    }

    public func verifiesMAC1(in packet: Data) -> Bool {
        let bytes = Array(packet)
        guard packet.count == WireGuardHandshakePacketCodec.initiationLength ||
                packet.count == WireGuardHandshakePacketCodec.responseLength,
              bytes[1...3].allSatisfy({ $0 == 0 }),
              (bytes[0] == 1 && packet.count == WireGuardHandshakePacketCodec.initiationLength) ||
                (bytes[0] == 2 && packet.count == WireGuardHandshakePacketCodec.responseLength) else { return false }
        let mac1Start = packet.count - 32
        let actual = Data(bytes[mac1Start..<(mac1Start + 16)])
        let expected = WireGuardKDF.blake2s128(key: mac1Key, message: Data(bytes[..<mac1Start]))
        return constantTimeEqual(actual, expected)
    }

    public func verifiesMAC2(in packet: Data, cookie: Data) -> Bool {
        guard cookie.count == 16, verifiesMAC1(in: packet) else { return false }
        let bytes = Array(packet)
        let mac2Start = bytes.count - 16
        let expected = WireGuardKDF.blake2s128(key: cookie, message: Data(bytes[..<mac2Start]))
        let actual = Data(bytes[mac2Start...])
        return constantTimeEqual(actual, expected)
    }

    private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        let left = Array(lhs)
        let right = Array(rhs)
        var difference: UInt8 = 0
        for index in left.indices { difference |= left[index] ^ right[index] }
        return difference == 0
    }

    private static func hChaCha20(key: [UInt8], nonce: [UInt8]) -> [UInt8] {
        precondition(key.count == 32 && nonce.count == 16)
        let constants: [UInt8] = Array("expand 32-byte k".utf8)
        func word(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
            UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8 |
                UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
        }
        var state = (0..<4).map { word(constants, $0 * 4) } + (0..<8).map { word(key, $0 * 4) } +
            (0..<4).map { word(nonce, $0 * 4) }
        @inline(__always) func rotate(_ value: UInt32, _ count: UInt32) -> UInt32 {
            (value << count) | (value >> (32 - count))
        }
        @inline(__always) func quarter(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ s: inout [UInt32]) {
            s[a] &+= s[b]; s[d] ^= s[a]; s[d] = rotate(s[d], 16)
            s[c] &+= s[d]; s[b] ^= s[c]; s[b] = rotate(s[b], 12)
            s[a] &+= s[b]; s[d] ^= s[a]; s[d] = rotate(s[d], 8)
            s[c] &+= s[d]; s[b] ^= s[c]; s[b] = rotate(s[b], 7)
        }
        for _ in 0..<10 {
            quarter(0, 4, 8, 12, &state); quarter(1, 5, 9, 13, &state)
            quarter(2, 6, 10, 14, &state); quarter(3, 7, 11, 15, &state)
            quarter(0, 5, 10, 15, &state); quarter(1, 6, 11, 12, &state)
            quarter(2, 7, 8, 13, &state); quarter(3, 4, 9, 14, &state)
        }
        return [0, 1, 2, 3, 12, 13, 14, 15].flatMap { index in
            let value = state[index]
            return [UInt8(value & 0xff), UInt8((value >> 8) & 0xff),
                    UInt8((value >> 16) & 0xff), UInt8((value >> 24) & 0xff)]
        }
    }

    static func xchacha20Poly1305Open(key: Data, nonce: Data, ciphertext: Data, aad: Data) throws -> Data {
        guard key.count == 32, nonce.count == 24, ciphertext.count >= 16 else {
            throw WireGuardPacketError.malformed
        }
        let nonceBytes = Array(nonce)
        let subkey = hChaCha20(key: Array(key), nonce: Array(nonceBytes[0..<16]))
        let shortNonce = try ChaChaPoly.Nonce(data: Data([0, 0, 0, 0] + nonceBytes[16..<24]))
        let box = try ChaChaPoly.SealedBox(nonce: shortNonce,
                                           ciphertext: Data(ciphertext.dropLast(16)),
                                           tag: Data(ciphertext.suffix(16)))
        return try ChaChaPoly.open(box, using: SymmetricKey(data: Data(subkey)), authenticating: aad)
    }

    static func xchacha20Poly1305Seal(key: Data, nonce: Data, plaintext: Data, aad: Data) throws -> Data {
        guard key.count == 32, nonce.count == 24 else { throw WireGuardPacketError.malformed }
        let nonceBytes = Array(nonce)
        let subkey = hChaCha20(key: Array(key), nonce: Array(nonceBytes[0..<16]))
        let shortNonce = try ChaChaPoly.Nonce(data: Data([0, 0, 0, 0] + nonceBytes[16..<24]))
        let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: Data(subkey)), nonce: shortNonce,
                                      authenticating: aad)
        return box.ciphertext + box.tag
    }
}
