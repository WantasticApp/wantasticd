import Foundation

public struct P2PEndpoint: Codable, Equatable, Hashable, Sendable {
    /// IPv4 (4 bytes) or IPv6 (16 bytes), in network byte order.
    public let address: Data
    public let port: UInt16

    public init(address: Data, port: UInt16) {
        self.address = address
        self.port = port
    }
}

public struct P2PMessage: Equatable, Sendable {
    public let subtype: UInt8
    public let publicKey: Data
    public let localAddress: Data
    public let localPort: UInt16
    public let observedAddress: Data
    public let observedPort: UInt16
    public let targetID: UInt32
    public let nonce: Data
    public let payload: Data

    public init(subtype: UInt8, publicKey: Data = Data(repeating: 0, count: 32),
                localAddress: Data = Data(repeating: 0, count: 16), localPort: UInt16 = 0,
                observedAddress: Data = Data(repeating: 0, count: 16), observedPort: UInt16 = 0,
                targetID: UInt32 = 0, nonce: Data = Data(repeating: 0, count: 8), payload: Data = Data()) throws {
        guard publicKey.count == 32, localAddress.count == 16,
              observedAddress.count == 16, nonce.count == 8 else { throw P2PProtocolError.invalidFieldLength }
        self.subtype = subtype
        self.publicKey = publicKey
        self.localAddress = localAddress
        self.localPort = localPort
        self.observedAddress = observedAddress
        self.observedPort = observedPort
        self.targetID = targetID
        self.nonce = nonce
        self.payload = payload
    }
}

public enum P2PProtocolError: Error, Equatable {
    case invalidFieldLength
    case tooLarge
    case malformedDatagram
}

/// Raw Go message type 6 datagrams used for P2P coordinator messages and
/// authenticated hole-punch probes. Unlike WireGuard transport packets, this
/// envelope is not encrypted; only the punch probe itself is peer-authenticated.
public protocol WireGuardDatagramChannel: Sendable {
    func start() async throws
    func send(_ datagram: Data) async throws
    func receive() async throws -> Data
    func close() async
}

public protocol P2PControlChannel: Sendable {
    var p2pControlPayloads: AsyncStream<Data> { get }
    func sendP2PControlPayload(_ payload: Data) async throws
    func openP2PPunchPath(to endpoint: P2PEndpoint) async throws -> any P2PPunchPath
}

/// A peer-specific raw UDP flow bound to the coordinator socket's local port.
/// A successful authenticated punch proves peer reachability only; it does not
/// by itself establish or promote a WireGuard session.
public protocol P2PPunchPath: WireGuardDatagramChannel {
    var localEndpoint: P2PEndpoint { get }
}

public enum P2PMessageSubtype {
    public static let register: UInt8 = 1
    public static let registerAck: UInt8 = 2
    public static let peerList: UInt8 = 3
    public static let punchRequest: UInt8 = 4
    public static let punchRelay: UInt8 = 5
    public static let punchPacket: UInt8 = 6
    public static let heartbeat: UInt8 = 7
}

/// Wire-compatible codec for the Go WireGuard engine's encrypted P2P message
/// type and WPC1 endpoint-candidate extension.
public enum P2PProtocolCodec {
    public static let wireGuardMessageType: UInt8 = 6
    public static let messageHeaderLength = 84
    public static let outerHeaderLength = 4
    public static let maximumDatagramBytes = 65_535
    private static let candidateMagic = Data([0x57, 0x50, 0x43, 0x31]) // WPC1
    private static let candidateLength = 18
    private static let maxPayload = 1_048_576

    public static func encode(_ message: P2PMessage) throws -> Data {
        guard message.payload.count <= maxPayload - messageHeaderLength else { throw P2PProtocolError.tooLarge }
        var data = Data(repeating: 0, count: messageHeaderLength)
        data[0] = message.subtype
        data.replaceSubrange(4..<36, with: message.publicKey)
        data.replaceSubrange(36..<52, with: message.localAddress)
        put(message.localPort, into: &data, at: 52)
        data.replaceSubrange(54..<70, with: message.observedAddress)
        put(message.observedPort, into: &data, at: 70)
        put(message.targetID, into: &data, at: 72)
        data.replaceSubrange(76..<84, with: message.nonce)
        data.append(message.payload)
        return data
    }

    public static func decodeMessage(_ data: Data) throws -> P2PMessage {
        let data = Data(data)
        guard data.count >= messageHeaderLength else { throw WUSPTransportError.malformed }
        guard data.count <= maxPayload else { throw P2PProtocolError.tooLarge }
        return try P2PMessage(subtype: data[0], publicKey: data.subdata(in: 4..<36),
                              localAddress: data.subdata(in: 36..<52), localPort: read16(data, 52),
                              observedAddress: data.subdata(in: 54..<70), observedPort: read16(data, 70),
                              targetID: read32(data, 72), nonce: data.subdata(in: 76..<84),
                              payload: data.subdata(in: 84..<data.count))
    }

    public static func encodeDatagram(payload: Data) throws -> Data {
        guard !payload.isEmpty else { throw P2PProtocolError.malformedDatagram }
        guard payload.count <= maximumDatagramBytes - outerHeaderLength else { throw P2PProtocolError.tooLarge }
        return Data([wireGuardMessageType, 0, 0, 0]) + payload
    }

    public static func decodeDatagram(_ datagram: Data) throws -> Data {
        guard datagram.count > outerHeaderLength,
              datagram.count <= maximumDatagramBytes,
              datagram[0] == wireGuardMessageType,
              datagram[1] == 0, datagram[2] == 0, datagram[3] == 0 else {
            throw P2PProtocolError.malformedDatagram
        }
        return Data(datagram.dropFirst(outerHeaderLength))
    }

    /// Go skips invalid endpoints, removes duplicates and caps the count at 255.
    public static func encodeCandidates(_ endpoints: [P2PEndpoint]) -> Data {
        var candidates = Data()
        var seen = Set<Data>()
        var count: UInt8 = 0
        for endpoint in endpoints {
            guard endpoint.port != 0, let address = ipv6Mapped(endpoint.address) else { continue }
            var encoded = address
            encoded.append(UInt8(endpoint.port >> 8))
            encoded.append(UInt8(endpoint.port & 0xff))
            guard seen.insert(encoded).inserted else { continue }
            guard count < .max else { break }
            candidates.append(encoded)
            count += 1
        }
        guard count > 0 else { return Data() }
        var result = candidateMagic
        result.append(count)
        result.append(candidates)
        return result
    }

    /// Parses from an offset because peer-list payloads prefix each peer record.
    /// Trailing payload bytes are preserved/ignored, matching the Go decoder.
    public static func decodeCandidates(_ payload: Data, offset: Int = 0) -> [P2PEndpoint] {
        guard offset >= 0, offset <= payload.count - 5,
              payload.subdata(in: offset..<(offset + 4)) == candidateMagic else { return [] }
        let count = Int(payload[offset + 4])
        let start = offset + 5
        guard count <= (payload.count - start) / candidateLength else { return [] }
        var result: [P2PEndpoint] = []
        result.reserveCapacity(count)
        for index in 0..<count {
            let base = start + index * candidateLength
            let rawAddress = payload.subdata(in: base..<(base + 16))
            let port = read16(payload, base + 16)
            guard port > 0 else { continue }
            let address = isIPv4Mapped(rawAddress) ? rawAddress.suffix(4) : rawAddress[...]
            result.append(P2PEndpoint(address: Data(address), port: port))
        }
        return result
    }

    public static func appendCandidates(_ endpoints: [P2PEndpoint], to prefix: Data) -> Data {
        let encoded = encodeCandidates(endpoints)
        guard !encoded.isEmpty else { return prefix }
        var result = prefix
        result.append(encoded)
        return result
    }

    private static func ipv6Mapped(_ address: Data) -> Data? {
        if address.count == 16 { return address }
        guard address.count == 4 else { return nil }
        var result = Data(repeating: 0, count: 10)
        result.append(contentsOf: [0xff, 0xff])
        result.append(address)
        return result
    }

    private static func isIPv4Mapped(_ address: Data) -> Bool {
        address.count == 16 && address.prefix(12) == Data(repeating: 0, count: 10) + Data([0xff, 0xff])
    }

    private static func put(_ value: UInt16, into data: inout Data, at offset: Int) {
        data[offset] = UInt8(value >> 8)
        data[offset + 1] = UInt8(value & 0xff)
    }

    private static func put(_ value: UInt32, into data: inout Data, at offset: Int) {
        data[offset] = UInt8((value >> 24) & 0xff)
        data[offset + 1] = UInt8((value >> 16) & 0xff)
        data[offset + 2] = UInt8((value >> 8) & 0xff)
        data[offset + 3] = UInt8(value & 0xff)
    }

    private static func read16(_ data: Data, _ offset: Int) -> UInt16 {
        (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
    }

    private static func read32(_ data: Data, _ offset: Int) -> UInt32 {
        (UInt32(data[offset]) << 24) | (UInt32(data[offset + 1]) << 16) |
            (UInt32(data[offset + 2]) << 8) | UInt32(data[offset + 3])
    }
}
