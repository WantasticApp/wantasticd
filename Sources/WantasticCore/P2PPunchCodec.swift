import Foundation

public enum P2PPunchError: Error, Equatable {
    case invalidNonce
    case invalidSharedSecret
}

/// Authenticated direct-path probe used by the Go P2P coordinator. This only
/// defines/verifies the punch datagram; peer discovery, UDP transmission, and
/// safe route promotion are managed by the caller.
public enum P2PPunchCodec {
    public static let packetLength = 41
    public static let maximumPredictedTargets = 16
    private static let predictionDeltas = [1, -1, 2, -2, 3, -3, 5, -5, 8, -8, 13, -13]

    public static func encode(nonce: Data, sharedSecret: Data) throws -> Data {
        guard nonce.count == 8 else { throw P2PPunchError.invalidNonce }
        guard sharedSecret.count == 32 else { throw P2PPunchError.invalidSharedSecret }
        var packet = Data([P2PMessageSubtype.punchPacket])
        packet.append(nonce)
        packet.append(WireGuardKDF.keyedBlake2s(key: sharedSecret, message: nonce))
        return packet
    }

    public static func verify(_ packet: Data, nonce: Data, sharedSecret: Data) -> Bool {
        let packet = Data(packet)
        guard packet.count == packetLength, packet[0] == P2PMessageSubtype.punchPacket,
              nonce.count == 8, sharedSecret.count == 32,
              packet.subdata(in: 1..<9) == nonce else { return false }
        let expected = WireGuardKDF.keyedBlake2s(key: sharedSecret, message: nonce)
        var difference: UInt8 = 0
        for (actual, expected) in zip(packet.suffix(32), expected) {
            difference |= actual ^ expected
        }
        return difference == 0
    }

    /// Wraps the 41-byte probe in the Go engine's little-endian type-6 packet.
    public static func encodeOuter(_ packet: Data) throws -> Data {
        guard packet.count == packetLength, packet.first == P2PMessageSubtype.punchPacket else {
            throw P2PProtocolError.invalidFieldLength
        }
        var result = Data([P2PProtocolCodec.wireGuardMessageType, 0, 0, 0])
        result.append(packet)
        return result
    }

    /// Reproduces the Go punch target ordering: advertised candidates, the
    /// coordinator-observed address, the local address, then a bounded set of
    /// nearby public UDP ports. Assigned overlay addresses are never probed.
    public static func buildTargets(candidates: [P2PEndpoint],
                                    observed: P2PEndpoint?, local: P2PEndpoint?,
                                    assignedOverlayAddress: Data? = nil) -> [P2PEndpoint] {
        var targets: [P2PEndpoint] = []
        var seen = Set<String>()
        for candidate in candidates + [observed, local].compactMap({ $0 }) {
            append(candidate, assignedOverlayAddress: assignedOverlayAddress,
                   to: &targets, seen: &seen)
        }
        let originalCount = targets.count
        guard originalCount < maximumPredictedTargets else { return targets }
        for index in 0..<originalCount where targets.count < maximumPredictedTargets {
            let endpoint = targets[index]
            guard isPublicInternetAddress(endpoint.address) else { continue }
            for delta in predictionDeltas where targets.count < maximumPredictedTargets {
                let port = Int(endpoint.port) + delta
                guard (1...65_535).contains(port) else { continue }
                append(P2PEndpoint(address: endpoint.address, port: UInt16(port)),
                       assignedOverlayAddress: assignedOverlayAddress,
                       to: &targets, seen: &seen)
            }
        }
        return targets
    }

    private static func append(_ endpoint: P2PEndpoint, assignedOverlayAddress: Data?,
                               to targets: inout [P2PEndpoint], seen: inout Set<String>) {
        guard endpoint.port > 0, let address = normalize(endpoint.address),
              !address.allSatisfy({ $0 == 0 }),
              normalize(assignedOverlayAddress ?? Data()) != address else { return }
        let identity = address.map { String(format: "%02x", $0) }.joined() + ":\(endpoint.port)"
        guard seen.insert(identity).inserted else { return }
        targets.append(P2PEndpoint(address: address, port: endpoint.port))
    }

    private static func normalize(_ address: Data) -> Data? {
        if address.count == 4 { return address }
        guard address.count == 16 else { return nil }
        let prefix = Data(repeating: 0, count: 10) + Data([0xff, 0xff])
        return address.prefix(12) == prefix ? Data(address.suffix(4)) : address
    }

    private static func isPublicInternetAddress(_ address: Data) -> Bool {
        guard let address = normalize(address), !address.allSatisfy({ $0 == 0 }) else { return false }
        if address.count == 4 {
            let b = [UInt8](address)
            return b[0] != 0 && b[0] != 10 && b[0] != 127 && b[0] < 224 &&
                !(b[0] == 169 && b[1] == 254) &&
                !(b[0] == 172 && (16...31).contains(b[1])) &&
                !(b[0] == 192 && b[1] == 168) && b != [255, 255, 255, 255]
        }
        let b = [UInt8](address)
        return b[0] != 0xff && !(b[0] == 0xfe && (b[1] & 0xc0) == 0x80) &&
            !(b[0] == 0xfc || b[0] == 0xfd) && !(b.dropFirst().allSatisfy({ $0 == 0 }) && b[15] == 1)
    }
}
