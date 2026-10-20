import Foundation

public enum WUSPTransferStreamPhase: UInt8, Equatable, Sendable {
    case open = 1
    case chunk = 2
    case acknowledgement = 3
    case complete = 4
    case abort = 5
}

public struct WUSPTransferStreamFrame: Equatable, Sendable {
    public var sessionID: UInt64
    public var requestID: UInt64
    public var method: WUSPMethod
    public var phase: WUSPTransferStreamPhase
    public var sequence: UInt32
    public var acknowledgementSequence: UInt32
    public var offset: UInt64
    public var totalSize: UInt64
    public var path: String
    public var filename: String
    public var contentType: String
    public var metadata: [String: String]
    public var data: Data
    public var isFinal: Bool

    public init(sessionID: UInt64, requestID: UInt64, method: WUSPMethod,
                phase: WUSPTransferStreamPhase, sequence: UInt32 = 0,
                acknowledgementSequence: UInt32 = 0, offset: UInt64 = 0,
                totalSize: UInt64 = 0, path: String = "", filename: String = "",
                contentType: String = "", metadata: [String: String] = [:],
                data: Data = Data(), isFinal: Bool = false) {
        self.sessionID = sessionID
        self.requestID = requestID
        self.method = method
        self.phase = phase
        self.sequence = sequence
        self.acknowledgementSequence = acknowledgementSequence
        self.offset = offset
        self.totalSize = totalSize
        self.path = path
        self.filename = filename
        self.contentType = contentType
        self.metadata = metadata
        self.data = data
        self.isFinal = isFinal
    }
}

/// Encodes Go's WUSP transfer-stream frame format, including its optional raw
/// LZ4 block compression and zero-padding-tolerant datagram decoding.
public enum WUSPTransferStreamCodec {
    private static let magic: UInt8 = 0x53
    private static let version: UInt8 = 1
    private static let fixedHeaderBytes = 45
    private static let maximumBytes = 1_048_576

    public static func encode(_ frame: WUSPTransferStreamFrame) throws -> Data {
        try validate(frame)
        var flags: UInt8 = frame.isFinal ? 1 : 0
        if !frame.path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { flags |= 1 << 1 }
        if !frame.filename.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { flags |= 1 << 2 }
        if !frame.contentType.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { flags |= 1 << 3 }
        if !frame.metadata.isEmpty { flags |= 1 << 4 }

        var payload = frame.data
        var rawSize: Int?
        if shouldCompress(payload), let compressed = WUSPMessageCodec.compressLZ4(payload),
           compressed.count < payload.count {
            flags |= 1 << 5
            rawSize = payload.count
            payload = compressed
        }
        if !frame.data.isEmpty { flags |= 1 << 6 }

        var output = Data([magic, version, frame.phase.rawValue, frame.method.wireID, flags])
        output.appendLittleEndian(frame.sessionID)
        output.appendLittleEndian(frame.requestID)
        output.appendLittleEndian(frame.sequence)
        output.appendLittleEndian(frame.acknowledgementSequence)
        output.appendLittleEndian(frame.offset)
        output.appendLittleEndian(frame.totalSize)
        if flags & (1 << 1) != 0 { try output.appendLengthPrefixed(Data(frame.path.utf8)) }
        if flags & (1 << 2) != 0 { try output.appendLengthPrefixed(Data(frame.filename.utf8)) }
        if flags & (1 << 3) != 0 { try output.appendLengthPrefixed(Data(frame.contentType.utf8)) }
        if flags & (1 << 4) != 0 { try output.appendMetadata(frame.metadata) }
        if flags & (1 << 6) != 0 {
            if let rawSize { output.appendVarint(UInt64(rawSize)) }
            try output.appendLengthPrefixed(payload)
        }
        guard output.count <= maximumBytes else { throw WUSPTransportError.tooLarge }
        return output
    }

    public static func decode(_ data: Data) throws -> WUSPTransferStreamFrame {
        guard data.count >= fixedHeaderBytes else { throw WUSPTransportError.malformed }
        guard data.count <= maximumBytes else { throw WUSPTransportError.tooLarge }
        let bytes = [UInt8](data)
        guard bytes[0] == magic, bytes[1] == version else { throw WUSPTransportError.unsupported }
        guard let phase = WUSPTransferStreamPhase(rawValue: bytes[2]),
              let method = WUSPMethod.allCases.first(where: { $0.wireID == bytes[3] }) else {
            throw WUSPTransportError.unsupported
        }
        let flags = bytes[4]
        guard flags & 0b1000_0000 == 0 else { throw WUSPTransportError.unsupported }
        var reader = TransferFrameReader(rawBytes: bytes, offset: 5)
        let sessionID = try reader.littleEndian64()
        let requestID = try reader.littleEndian64()
        let sequence = try reader.littleEndian32()
        let acknowledgementSequence = try reader.littleEndian32()
        let offset = try reader.littleEndian64()
        let totalSize = try reader.littleEndian64()
        let path = flags & (1 << 1) != 0 ? try reader.string() : ""
        let filename = flags & (1 << 2) != 0 ? try reader.string() : ""
        let contentType = flags & (1 << 3) != 0 ? try reader.string() : ""
        let metadata = flags & (1 << 4) != 0 ? try reader.metadata() : [:]
        var payload = Data()
        if flags & (1 << 6) != 0 {
            let rawSize: UInt64? = flags & (1 << 5) != 0 ? try reader.varint() : nil
            payload = try reader.bytes()
            if let rawSize {
                guard rawSize > 0, rawSize <= UInt64(maximumBytes),
                      rawSize <= UInt64(Int.max) else { throw WUSPTransportError.tooLarge }
                payload = try WUSPMessageCodec.decompressLZ4(payload, rawSize: Int(rawSize))
            }
        } else if flags & (1 << 5) != 0 {
            throw WUSPTransportError.malformed
        }
        guard reader.remaining.allSatisfy({ $0 == 0 }) else { throw WUSPTransportError.malformed }
        let frame = WUSPTransferStreamFrame(
            sessionID: sessionID, requestID: requestID, method: method, phase: phase,
            sequence: sequence, acknowledgementSequence: acknowledgementSequence,
            offset: offset, totalSize: totalSize, path: path, filename: filename,
            contentType: contentType, metadata: metadata, data: payload,
            isFinal: flags & 1 != 0)
        try validate(frame)
        return frame
    }

    private static func validate(_ frame: WUSPTransferStreamFrame) throws {
        guard frame.method == .upload || frame.method == .download else {
            throw WUSPTransportError.unsupported
        }
        if frame.phase == .chunk && frame.data.isEmpty {
            throw WUSPTransportError.malformed
        }
        guard frame.metadata.count <= 16_384 else { throw WUSPTransportError.tooLarge }
    }

    private static func shouldCompress(_ data: Data) -> Bool {
        guard data.count >= 256 else { return false }
        let sample = data.prefix(256)
        var previous: UInt8?
        var repeated = 0
        var distinct = Set<UInt8>()
        for byte in sample {
            if byte == previous { repeated += 1 }
            previous = byte
            distinct.insert(byte)
        }
        return repeated >= sample.count / 16 || distinct.count <= sample.count / 2
    }
}

private struct TransferFrameReader {
    let rawBytes: [UInt8]
    var offset: Int

    var remaining: ArraySlice<UInt8> { rawBytes[offset...] }

    mutating func take(_ count: Int) throws -> [UInt8] {
        guard count >= 0, count <= rawBytes.count - offset else { throw WUSPTransportError.malformed }
        defer { offset += count }
        return Array(rawBytes[offset..<(offset + count)])
    }

    mutating func littleEndian32() throws -> UInt32 {
        let value = try take(4)
        return value.enumerated().reduce(UInt32(0)) { $0 | (UInt32($1.element) << (8 * $1.offset)) }
    }

    mutating func littleEndian64() throws -> UInt64 {
        let value = try take(8)
        return value.enumerated().reduce(UInt64(0)) { $0 | (UInt64($1.element) << (8 * $1.offset)) }
    }

    mutating func varint() throws -> UInt64 {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        for _ in 0..<10 {
            guard offset < rawBytes.count else { throw WUSPTransportError.malformed }
            let byte = rawBytes[offset]
            offset += 1
            guard shift < 64, !(shift == 63 && byte > 1) else { throw WUSPTransportError.malformed }
            value |= UInt64(byte & 0x7f) << shift
            if byte & 0x80 == 0 { return value }
            shift += 7
        }
        throw WUSPTransportError.malformed
    }

    mutating func bytesValue() throws -> Data {
        let length = try varint()
        guard length <= 1_048_576, length <= UInt64(rawBytes.count - offset) else {
            throw WUSPTransportError.malformed
        }
        return Data(try take(Int(length)))
    }

    mutating func string() throws -> String {
        guard let value = String(data: try bytesValue(), encoding: .utf8) else {
            throw WUSPTransportError.malformed
        }
        return value
    }

    mutating func metadata() throws -> [String: String] {
        let count = try varint()
        guard count <= 16_384 else { throw WUSPTransportError.tooLarge }
        var result: [String: String] = [:]
        for _ in 0..<count {
            let key = try string()
            guard result[key] == nil else { throw WUSPTransportError.malformed }
            result[key] = try string()
        }
        return result
    }

    mutating func bytes() throws -> Data { try bytesValue() }
}

private extension Data {
    mutating func appendLittleEndian<T: FixedWidthInteger>(_ value: T) {
        var littleEndianValue = value.littleEndian
        Swift.withUnsafeBytes(of: &littleEndianValue) { append(contentsOf: $0) }
    }

    mutating func appendVarint(_ value: UInt64) {
        var value = value
        while value >= 0x80 {
            append(UInt8(value & 0x7f) | 0x80)
            value >>= 7
        }
        append(UInt8(value))
    }

    mutating func appendLengthPrefixed(_ value: Data) throws {
        guard value.count <= 1_048_576 else { throw WUSPTransportError.tooLarge }
        appendVarint(UInt64(value.count))
        append(value)
    }

    mutating func appendMetadata(_ metadata: [String: String]) throws {
        guard metadata.count <= 16_384 else { throw WUSPTransportError.tooLarge }
        appendVarint(UInt64(metadata.count))
        for key in metadata.keys.sorted() {
            try appendLengthPrefixed(Data(key.utf8))
            try appendLengthPrefixed(Data((metadata[key] ?? "").utf8))
        }
    }
}
