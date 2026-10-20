import Foundation
import Darwin

public enum TunnelControlAction: UInt8, Sendable {
    case revokeExitNodeRouting = 0
    case useExitNodeRouting = 1
    case enableExitNodeSharing = 2
    case requestExitNodeRouting = 3
    case setExitNodeOffer = 4
    case disableExitNodeSharing = 5
    case setLocalAccessRoutes = 6
    case applyLocalAccessRoutes = 7
    case removeLocalAccessRoutes = 8
    case syncLocalAccessRoutes = 9
}

public struct TunnelIPv4Prefix: Equatable, Hashable, Sendable {
    public let address: UInt32
    public let prefixLength: UInt8

    public init(_ text: String) throws {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let bits = UInt8(parts[1]), (8...32).contains(bits) else {
            throw TunnelControlError.invalidPrefix
        }
        var address = in_addr()
        guard String(parts[0]).withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else {
            throw TunnelControlError.invalidPrefix
        }
        let raw = UInt32(bigEndian: address.s_addr)
        guard Self.isPrivate(raw) else { throw TunnelControlError.nonPrivateRoute }
        let mask = bits == 0 ? UInt32(0) : UInt32.max << (32 - bits)
        self.address = raw & mask
        self.prefixLength = bits
    }

    fileprivate init(address: UInt32, prefixLength: UInt8) throws {
        guard (8...32).contains(prefixLength), Self.isPrivate(address) else {
            throw Self.isPrivate(address) ? TunnelControlError.invalidPrefix : TunnelControlError.nonPrivateRoute
        }
        let mask = UInt32.max << (32 - prefixLength)
        self.address = address & mask
        self.prefixLength = prefixLength
    }

    public var description: String {
        "\((address >> 24) & 255).\((address >> 16) & 255).\((address >> 8) & 255).\(address & 255)/\(prefixLength)"
    }

    private static func isPrivate(_ address: UInt32) -> Bool {
        let first = address >> 24
        let second = (address >> 16) & 255
        return first == 10 || (first == 172 && (16...31).contains(second)) || (first == 192 && second == 168)
    }
}

public enum TunnelControlMessage: Equatable, Sendable {
    case revokeExitNodeRouting
    case useExitNodeRouting(publicKey: Data)
    case enableExitNodeSharing
    case requestExitNodeRouting(publicKey: Data?)
    case setExitNodeOffer(enabled: Bool)
    case disableExitNodeSharing
    case setLocalAccessRoutes([TunnelIPv4Prefix])
    case applyLocalAccessRoutes(owner: Data, routes: [TunnelIPv4Prefix])
    case removeLocalAccessRoutes(owner: Data)
    case syncLocalAccessRoutes([(owner: Data, routes: [TunnelIPv4Prefix])])

    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.revokeExitNodeRouting, .revokeExitNodeRouting),
             (.enableExitNodeSharing, .enableExitNodeSharing),
             (.disableExitNodeSharing, .disableExitNodeSharing): true
        case let (.useExitNodeRouting(a), .useExitNodeRouting(b)): a == b
        case let (.requestExitNodeRouting(a), .requestExitNodeRouting(b)): a == b
        case let (.setExitNodeOffer(a), .setExitNodeOffer(b)): a == b
        case let (.setLocalAccessRoutes(a), .setLocalAccessRoutes(b)): a == b
        case let (.applyLocalAccessRoutes(ao, ar), .applyLocalAccessRoutes(bo, br)): ao == bo && ar == br
        case let (.removeLocalAccessRoutes(a), .removeLocalAccessRoutes(b)): a == b
        case let (.syncLocalAccessRoutes(a), .syncLocalAccessRoutes(b)):
            a.count == b.count && zip(a, b).allSatisfy { $0.owner == $1.owner && $0.routes == $1.routes }
        default: false
        }
    }
}

public enum TunnelControlError: Error, Equatable {
    case malformed
    case unsupportedAction
    case tooManyRoutes
    case invalidPrefix
    case nonPrivateRoute
}

/// Tracks coordinator-authorized remote subnet advertisements by device. The
/// packet provider applies the resulting routes only after authenticated type-7
/// messages arrive on the configured hub WireGuard peer.
public struct TunnelLocalAccessRouteTable: Equatable, Sendable {
    private var routesByOwner: [Data: [TunnelIPv4Prefix]] = [:]

    public init() {}

    public var routes: [TunnelIPv4Prefix] {
        Array(Set(routesByOwner.values.flatMap { $0 })).sorted { $0.description < $1.description }
    }

    /// Returns the new deduplicated route set for route-changing messages;
    /// returns nil for non-route actions or an unchanged state.
    public mutating func apply(_ message: TunnelControlMessage) throws -> [TunnelIPv4Prefix]? {
        var proposed = routesByOwner
        switch message {
        case let .applyLocalAccessRoutes(owner, routes):
            guard owner.count == 32, routes.count <= TunnelControlCodec.maxRoutesPerOwner else {
                throw TunnelControlError.malformed
            }
            if routes.isEmpty { proposed[owner] = nil }
            else {
                guard proposed[owner] != nil || proposed.count < TunnelControlCodec.maxSnapshotOwners else {
                    throw TunnelControlError.tooManyRoutes
                }
                proposed[owner] = routes
            }
        case let .removeLocalAccessRoutes(owner):
            guard owner.count == 32 else { throw TunnelControlError.malformed }
            proposed[owner] = nil
        case let .syncLocalAccessRoutes(snapshot):
            guard snapshot.count <= TunnelControlCodec.maxSnapshotOwners else {
                throw TunnelControlError.tooManyRoutes
            }
            proposed.removeAll(keepingCapacity: true)
            for entry in snapshot {
                guard entry.owner.count == 32,
                      !entry.routes.isEmpty,
                      entry.routes.count <= TunnelControlCodec.maxRoutesPerOwner else {
                    throw TunnelControlError.malformed
                }
                proposed[entry.owner] = entry.routes
            }
        default:
            return nil
        }
        guard proposed != routesByOwner else { return nil }
        routesByOwner = proposed
        return routes
    }
}

/// Mirrors Go's effectiveExitRoutes policy: an exit node routes the address
/// families assigned to the interface, falling back to dual stack only when
/// the interface has no addresses.
public enum TunnelExitRoutePolicyError: Error, Equatable {
    case invalidAddress
}

public enum TunnelExitRoutePolicy {
    public static func routeTargets(for assignedAddresses: [String]) throws -> [String] {
        var hasIPv4 = false
        var hasIPv6 = false
        for address in assignedAddresses {
            let parts = address.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 2, let bits = UInt8(parts[1]) else {
                throw TunnelExitRoutePolicyError.invalidAddress
            }
            var ipv4 = in_addr()
            if String(parts[0]).withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1, bits <= 32 {
                hasIPv4 = true
                continue
            }
            var ipv6 = in6_addr()
            if String(parts[0]).withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1, bits <= 128 {
                hasIPv6 = true
                continue
            }
            throw TunnelExitRoutePolicyError.invalidAddress
        }
        if !hasIPv4 && !hasIPv6 { hasIPv4 = true; hasIPv6 = true }
        var routes: [String] = []
        if hasIPv4 { routes.append("0.0.0.0/0") }
        if hasIPv6 { routes.append("::/0") }
        return routes
    }
}

/// Codec for the Go tunnel's decrypted MessageTUNControlType payload. Parsing
/// does not authenticate the sender; route-changing messages must only be
/// acted on after the native WireGuard layer binds the packet to the configured
/// coordinator peer, matching Go's isServerTUNControlPeer check.
public enum TunnelControlCodec {
    public static let maxRoutesPerOwner = 16
    public static let maxSnapshotOwners = 32
    private static let routeEntrySize = 5

    public static func encodeExitNodeSelection(publicKeyHex: String?) throws -> Data {
        var data = Data([TunnelControlAction.requestExitNodeRouting.rawValue])
        if let key = publicKeyHex, !key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           key.caseInsensitiveCompare("none") != .orderedSame {
            guard let bytes = Data(hex: key.trimmingCharacters(in: .whitespacesAndNewlines)), bytes.count == 32 else {
                throw TunnelControlError.malformed
            }
            data.append(bytes)
        } else {
            data.append(Data(repeating: 0, count: 32))
        }
        return data
    }

    public static func encodeExitNodeOffer(enabled: Bool) -> Data {
        Data([TunnelControlAction.setExitNodeOffer.rawValue, enabled ? 1 : 0])
    }

    public static func encodeLocalAccessAdvertisement(_ routeStrings: [String]) throws -> Data {
        let routes = try normalizedRoutes(routeStrings)
        var data = Data([TunnelControlAction.setLocalAccessRoutes.rawValue, UInt8(routes.count)])
        for route in routes { append(route, to: &data) }
        return data
    }

    public static func decode(_ data: Data) throws -> TunnelControlMessage {
        guard let rawAction = data.first, let action = TunnelControlAction(rawValue: rawAction) else {
            throw data.isEmpty ? TunnelControlError.malformed : TunnelControlError.unsupportedAction
        }
        switch action {
        case .revokeExitNodeRouting:
            try requireLength(data, 1); return .revokeExitNodeRouting
        case .useExitNodeRouting:
            try requireLength(data, 33); return .useExitNodeRouting(publicKey: data.subdata(in: 1..<33))
        case .enableExitNodeSharing:
            try requireLength(data, 1); return .enableExitNodeSharing
        case .requestExitNodeRouting:
            try requireLength(data, 33)
            let key = data.subdata(in: 1..<33)
            return .requestExitNodeRouting(publicKey: key.allSatisfy { $0 == 0 } ? nil : key)
        case .setExitNodeOffer:
            try requireLength(data, 2)
            guard data[1] <= 1 else { throw TunnelControlError.malformed }
            return .setExitNodeOffer(enabled: data[1] == 1)
        case .disableExitNodeSharing:
            try requireLength(data, 1); return .disableExitNodeSharing
        case .setLocalAccessRoutes:
            let routes = try decodeRoutes(data, offset: 1)
            return .setLocalAccessRoutes(routes)
        case .applyLocalAccessRoutes:
            guard data.count >= 34 else { throw TunnelControlError.malformed }
            return .applyLocalAccessRoutes(owner: data.subdata(in: 1..<33), routes: try decodeRoutes(data, offset: 33))
        case .removeLocalAccessRoutes:
            try requireLength(data, 33); return .removeLocalAccessRoutes(owner: data.subdata(in: 1..<33))
        case .syncLocalAccessRoutes:
            return .syncLocalAccessRoutes(try decodeSnapshot(data))
        }
    }

    /// Decodes a type-7 plaintext after WireGuard has applied its standard
    /// zero padding. Padding is bounded to the transport's 15-byte block and
    /// is removed only when the remaining bytes form a complete control frame.
    public static func decodePaddedWireGuardPayload(_ data: Data) throws -> TunnelControlMessage {
        if let message = try? decode(data) { return message }
        guard data.count > 1 else { return try decode(data) }
        for paddingLength in 1...min(15, data.count - 1) {
            let payloadEnd = data.count - paddingLength
            guard data[payloadEnd...].allSatisfy({ $0 == 0 }) else { break }
            if let message = try? decode(Data(data[..<payloadEnd])) { return message }
        }
        return try decode(data)
    }

    private static func normalizedRoutes(_ values: [String]) throws -> [TunnelIPv4Prefix] {
        guard values.count <= maxRoutesPerOwner else { throw TunnelControlError.tooManyRoutes }
        return Array(Set(try values.map(TunnelIPv4Prefix.init))).sorted { $0.description < $1.description }
    }

    private static func decodeRoutes(_ data: Data, offset: Int) throws -> [TunnelIPv4Prefix] {
        guard offset >= 0, data.count > offset else { throw TunnelControlError.malformed }
        let count = Int(data[offset])
        guard count <= maxRoutesPerOwner, data.count == offset + 1 + count * routeEntrySize else {
            throw count > maxRoutesPerOwner ? TunnelControlError.tooManyRoutes : TunnelControlError.malformed
        }
        var routes: [TunnelIPv4Prefix] = []
        var seen = Set<TunnelIPv4Prefix>()
        for index in 0..<count {
            let start = offset + 1 + index * routeEntrySize
            let address = data[(start + 1)..<(start + 5)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            let route = try TunnelIPv4Prefix(address: address, prefixLength: data[start])
            if seen.insert(route).inserted { routes.append(route) }
        }
        return routes
    }

    private static func decodeSnapshot(_ data: Data) throws -> [(owner: Data, routes: [TunnelIPv4Prefix])] {
        guard data.count >= 2 else { throw TunnelControlError.malformed }
        let ownerCount = Int(data[1])
        guard ownerCount <= maxSnapshotOwners else { throw TunnelControlError.tooManyRoutes }
        var offset = 2
        var result: [(owner: Data, routes: [TunnelIPv4Prefix])] = []
        var totalRoutes = 0
        for _ in 0..<ownerCount {
            guard data.count >= offset + 33 else { throw TunnelControlError.malformed }
            let owner = data.subdata(in: offset..<(offset + 32))
            offset += 32
            let count = Int(data[offset])
            offset += 1
            guard count > 0, count <= maxRoutesPerOwner else { throw TunnelControlError.malformed }
            totalRoutes += count
            guard totalRoutes <= maxSnapshotOwners, data.count >= offset + count * routeEntrySize else {
                throw TunnelControlError.malformed
            }
            var routes: [TunnelIPv4Prefix] = []
            for _ in 0..<count {
                let address = data[(offset + 1)..<(offset + 5)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                routes.append(try TunnelIPv4Prefix(address: address, prefixLength: data[offset]))
                offset += routeEntrySize
            }
            result.append((owner, routes))
        }
        guard offset == data.count else { throw TunnelControlError.malformed }
        return result
    }

    private static func append(_ route: TunnelIPv4Prefix, to data: inout Data) {
        data.append(route.prefixLength)
        data.append(UInt8((route.address >> 24) & 255))
        data.append(UInt8((route.address >> 16) & 255))
        data.append(UInt8((route.address >> 8) & 255))
        data.append(UInt8(route.address & 255))
    }

    private static func requireLength(_ data: Data, _ length: Int) throws {
        guard data.count == length else { throw TunnelControlError.malformed }
    }
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var result = Data()
        result.reserveCapacity(hex.count / 2)
        var cursor = hex.startIndex
        while cursor < hex.endIndex {
            let next = hex.index(cursor, offsetBy: 2)
            guard let value = UInt8(hex[cursor..<next], radix: 16) else { return nil }
            result.append(value)
            cursor = next
        }
        self = result
    }
}
