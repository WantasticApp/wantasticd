import Foundation

public struct WUSPControlFragment: Equatable, Sendable {
    public let messageID: UInt64
    public let index: UInt32
    public let count: UInt32
    public let rawSize: UInt32
    public let compressed: Bool
    public let data: Data
}

public enum WUSPControlFragmentError: Error, Equatable {
    case malformed
    case unsupported
    case tooLarge
}

/// Go-compatible 23-byte WUSP control-fragment framing used inside encrypted
/// WireGuard message type 8. Compression remains disabled, matching the Go
/// sender; receive reassembly is bounded to constrain untrusted peer input.
public enum WUSPControlFragmentCodec {
    public static let magic: UInt8 = 0x54
    public static let version: UInt8 = 1
    public static let headerLength = 23
    public static let maximumDatagramPayload = 1200
    public static let maximumFragmentCount = 1024
    public static let maximumReassembledSize = 4 * 1024 * 1024

    public enum Decoded: Equatable, Sendable {
        case raw(Data)
        case fragment(WUSPControlFragment)
    }

    public static func encode(_ fragment: WUSPControlFragment) throws -> Data {
        try validate(fragment)
        guard !fragment.compressed else { throw WUSPControlFragmentError.unsupported }
        var frame = Data([magic, version, 0])
        appendLE(fragment.messageID, to: &frame)
        appendLE(fragment.index, to: &frame)
        appendLE(fragment.count, to: &frame)
        appendLE(fragment.rawSize, to: &frame)
        frame.append(fragment.data)
        return frame
    }

    /// Returns raw data when the Go magic byte is absent, as the Go decoder does.
    public static func decode(_ frame: Data) throws -> Decoded {
        guard frame.first == magic else { return .raw(frame) }
        guard frame.count > headerLength, frame[1] == version else {
            throw frame.count <= headerLength ? WUSPControlFragmentError.malformed : .unsupported
        }
        let flags = frame[2]
        guard flags & 0xfe == 0 else { throw WUSPControlFragmentError.unsupported }
        let fragment = WUSPControlFragment(
            messageID: readLE64(frame, 3), index: readLE32(frame, 11),
            count: readLE32(frame, 15), rawSize: readLE32(frame, 19),
            compressed: flags & 1 != 0, data: Data(frame.dropFirst(headerLength))
        )
        try validate(fragment)
        guard !fragment.compressed else { throw WUSPControlFragmentError.unsupported }
        return .fragment(fragment)
    }

    public static func fragment(_ payload: Data, messageID: UInt64,
                                maximumPayload: Int = maximumDatagramPayload) throws -> [Data] {
        guard !payload.isEmpty, messageID != 0 else { throw WUSPControlFragmentError.malformed }
        guard maximumPayload > headerLength, maximumPayload <= maximumDatagramPayload else {
            throw WUSPControlFragmentError.tooLarge
        }
        guard payload.count <= maximumReassembledSize else { throw WUSPControlFragmentError.tooLarge }
        let chunkSize = maximumPayload - headerLength
        let count = (payload.count + chunkSize - 1) / chunkSize
        guard count <= maximumFragmentCount else { throw WUSPControlFragmentError.tooLarge }
        return try (0..<count).map { index in
            let start = index * chunkSize
            let end = min(start + chunkSize, payload.count)
            let fragment = WUSPControlFragment(messageID: messageID, index: UInt32(index),
                                               count: UInt32(count), rawSize: 0, compressed: false,
                                               data: Data(payload[start..<end]))
            return try encode(fragment)
        }
    }

    public static func reassemble(_ fragments: [WUSPControlFragment]) throws -> Data {
        guard let first = fragments.first else { throw WUSPControlFragmentError.malformed }
        try validate(first)
        guard !first.compressed else { throw WUSPControlFragmentError.unsupported }
        guard fragments.count == Int(first.count), fragments.count <= maximumFragmentCount else {
            throw WUSPControlFragmentError.malformed
        }
        var ordered = [Data?](repeating: nil, count: fragments.count)
        var totalBytes = 0
        for item in fragments {
            try validate(item)
            guard item.messageID == first.messageID, item.count == first.count,
                  item.rawSize == first.rawSize, item.compressed == first.compressed,
                  ordered[Int(item.index)] == nil else { throw WUSPControlFragmentError.malformed }
            totalBytes += item.data.count
            guard totalBytes <= maximumReassembledSize else { throw WUSPControlFragmentError.tooLarge }
            ordered[Int(item.index)] = item.data
        }
        guard ordered.allSatisfy({ $0 != nil }) else { throw WUSPControlFragmentError.malformed }
        return ordered.reduce(into: Data()) { result, part in
            if let part { result.append(part) }
        }
    }

    private static func validate(_ fragment: WUSPControlFragment) throws {
        guard fragment.messageID != 0, fragment.count > 0,
              fragment.count <= maximumFragmentCount,
              fragment.index < fragment.count, !fragment.data.isEmpty else {
            throw WUSPControlFragmentError.malformed
        }
        if fragment.compressed && fragment.rawSize == 0 { throw WUSPControlFragmentError.malformed }
    }

    private static func appendLE(_ value: UInt32, to data: inout Data) {
        for shift in stride(from: 0, through: 24, by: 8) { data.append(UInt8((value >> shift) & 0xff)) }
    }

    private static func appendLE(_ value: UInt64, to data: inout Data) {
        for shift in stride(from: 0, through: 56, by: 8) { data.append(UInt8((value >> shift) & 0xff)) }
    }

    private static func readLE32(_ data: Data, _ offset: Int) -> UInt32 {
        (0..<4).reduce(UInt32(0)) { $0 | UInt32(data[offset + $1]) << UInt32($1 * 8) }
    }

    private static func readLE64(_ data: Data, _ offset: Int) -> UInt64 {
        (0..<8).reduce(UInt64(0)) { $0 | UInt64(data[offset + $1]) << UInt64($1 * 8) }
    }
}

/// Bounded, per-peer fragment collector matching the Go agent's 30-second
/// WUSP assembly lifetime and duplicate-fragment behavior.
public struct WUSPControlFragmentAssembler: Sendable {
    private struct Assembly: Sendable {
        var updatedAt: Date
        let count: UInt32
        var fragments: [WUSPControlFragment?]
        var received = 0
        var byteCount = 0
    }

    public static let lifetime: TimeInterval = 30
    public static let maximumPendingMessages = 64
    public static let maximumBufferedBytes = 8 * 1024 * 1024
    private var pending: [UInt64: Assembly] = [:]
    private var bufferedBytes = 0

    public init() {}

    public var pendingMessageCount: Int { pending.count }

    /// Returns a complete control payload, raw non-fragment data, or nil while
    /// a fragmented message is still incomplete.
    public mutating func consume(_ frame: Data, now: Date = Date()) throws -> Data? {
        pruneExpired(now: now)
        guard case let .fragment(fragment) = try WUSPControlFragmentCodec.decode(frame) else {
            return frame
        }
        guard !fragment.compressed else { throw WUSPControlFragmentError.unsupported }

        var assembly = pending[fragment.messageID]
        if let existing = assembly, existing.count != fragment.count {
            remove(fragment.messageID)
            throw WUSPControlFragmentError.malformed
        }
        if assembly == nil {
            guard pending.count < Self.maximumPendingMessages else { throw WUSPControlFragmentError.tooLarge }
            assembly = Assembly(updatedAt: now, count: fragment.count,
                                fragments: [WUSPControlFragment?](repeating: nil, count: Int(fragment.count)))
        }
        guard var current = assembly else { throw WUSPControlFragmentError.malformed }
        current.updatedAt = now
        let index = Int(fragment.index)
        if current.fragments[index] == nil {
            let nextBytes = bufferedBytes + fragment.data.count
            guard nextBytes <= Self.maximumBufferedBytes else { throw WUSPControlFragmentError.tooLarge }
            current.fragments[index] = fragment
            current.received += 1
            current.byteCount += fragment.data.count
            bufferedBytes = nextBytes
        }
        pending[fragment.messageID] = current
        guard current.received == Int(current.count) else { return nil }

        remove(fragment.messageID)
        let complete = current.fragments.compactMap { $0 }
        return try WUSPControlFragmentCodec.reassemble(complete)
    }

    private mutating func pruneExpired(now: Date) {
        let expired = pending.compactMap { key, value in
            now.timeIntervalSince(value.updatedAt) > Self.lifetime ? key : nil
        }
        for key in expired { remove(key) }
    }

    private mutating func remove(_ messageID: UInt64) {
        if let assembly = pending.removeValue(forKey: messageID) {
            bufferedBytes -= assembly.byteCount
        }
    }
}
