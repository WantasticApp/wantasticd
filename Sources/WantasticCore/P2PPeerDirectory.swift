import Foundation

/// One peer from the Go tunnel's P2P peer-list payload. This is a wire decoder,
/// not an authenticated transport: callers must only pass payloads received
/// through the native tunnel's authenticated control channel.
public struct P2PPeerRecord: Codable, Equatable, Sendable {
    public let id: UInt32
    public let publicKey: Data
    public let localEndpoint: P2PEndpoint?
    public let observedEndpoint: P2PEndpoint?
    public let natType: UInt8
    public let p2pCapable: Bool
    public let offersExitNode: Bool
    public let assignedIPv4: String?
    public let udpReachable: Bool
    public let direct: Bool

    public init(id: UInt32, publicKey: Data, localEndpoint: P2PEndpoint?,
                observedEndpoint: P2PEndpoint?, natType: UInt8, p2pCapable: Bool,
                offersExitNode: Bool, assignedIPv4: String?, udpReachable: Bool = false,
                direct: Bool = false) {
        self.id = id
        self.publicKey = publicKey
        self.localEndpoint = localEndpoint
        self.observedEndpoint = observedEndpoint
        self.natType = natType
        self.p2pCapable = p2pCapable
        self.offersExitNode = offersExitNode
        self.assignedIPv4 = assignedIPv4
        self.udpReachable = udpReachable
        self.direct = direct
    }

    public var deviceRecord: DeviceRecord {
        DeviceRecord(id: publicKey.map { String(format: "%02x", $0) }.joined(),
                     name: assignedIPv4 ?? "Device \(id)", address: assignedIPv4,
                     online: true, direct: direct, p2pReachable: udpReachable)
    }

    public func withNetworkStatus(udpReachable: Bool, direct: Bool) -> P2PPeerRecord {
        P2PPeerRecord(id: id, publicKey: publicKey, localEndpoint: localEndpoint,
                      observedEndpoint: observedEndpoint, natType: natType,
                      p2pCapable: p2pCapable, offersExitNode: offersExitNode,
                      assignedIPv4: assignedIPv4, udpReachable: udpReachable,
                      direct: direct)
    }
}

public enum P2PPeerDirectoryError: Error, Equatable {
    case malformed
    case tooManyPeers
}

/// Decodes the 78-byte peer records emitted by
/// internal/device/wireguard-go/device/p2p_client.go. Candidate extensions
/// following the fixed records are intentionally ignored, as Go does here.
public enum P2PPeerDirectoryCodec {
    public static let recordLength = 78
    public static let maxPeerCount = 4096

    public static func decode(_ payload: Data) throws -> [P2PPeerRecord] {
        guard payload.count >= 4 else { throw P2PPeerDirectoryError.malformed }
        let count = Int(read32(payload, 0))
        guard count <= maxPeerCount else { throw P2PPeerDirectoryError.tooManyPeers }
        guard count <= (payload.count - 4) / recordLength else { throw P2PPeerDirectoryError.malformed }

        var peers: [P2PPeerRecord] = []
        var seenIDs = Set<UInt32>()
        var seenPublicKeys = Set<Data>()
        peers.reserveCapacity(count)
        for index in 0..<count {
            let offset = 4 + index * recordLength
            let peerID = read32(payload, offset)
            guard peerID > 0, seenIDs.insert(peerID).inserted else {
                throw P2PPeerDirectoryError.malformed
            }
            let key = payload.subdata(in: (offset + 4)..<(offset + 36))
            guard seenPublicKeys.insert(key).inserted else { throw P2PPeerDirectoryError.malformed }
            let local = endpoint(address: payload.subdata(in: (offset + 36)..<(offset + 52)), port: read16(payload, offset + 52))
            let observed = endpoint(address: payload.subdata(in: (offset + 54)..<(offset + 70)), port: read16(payload, offset + 70))
            let nat = payload[offset + 72]
            let flags = payload[offset + 73]
            let assigned = payload.subdata(in: (offset + 74)..<(offset + 78))
            let address = assigned == Data(repeating: 0, count: 4) ? nil : assigned.map { String($0) }.joined(separator: ".")
            peers.append(P2PPeerRecord(id: peerID, publicKey: key, localEndpoint: local,
                                       observedEndpoint: observed, natType: nat,
                                       p2pCapable: flags & 1 != 0, offersExitNode: flags & 2 != 0,
                                       assignedIPv4: address))
        }
        return peers
    }

    private static func endpoint(address: Data, port: UInt16) -> P2PEndpoint? {
        guard port > 0 else { return nil }
        let bytes = address
        // Go normalizes IPv4-mapped IPv6 addresses to IPv4. Preserve IPv6
        // otherwise; all-zero addresses are not useful candidates.
        let isZero = bytes.allSatisfy { $0 == 0 }
        guard !isZero else { return nil }
        let normalized = bytes.count == 16 && bytes.prefix(10).allSatisfy({ $0 == 0 }) && bytes[10] == 0xff && bytes[11] == 0xff
            ? Data(bytes.suffix(4)) : bytes
        return P2PEndpoint(address: normalized, port: port)
    }

    private static func read16(_ data: Data, _ offset: Int) -> UInt16 {
        (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
    }

    private static func read32(_ data: Data, _ offset: Int) -> UInt32 {
        (UInt32(data[offset]) << 24) | (UInt32(data[offset + 1]) << 16) |
            (UInt32(data[offset + 2]) << 8) | UInt32(data[offset + 3])
    }
}
