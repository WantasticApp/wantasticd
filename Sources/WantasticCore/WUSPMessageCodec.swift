import Foundation

public enum WUSPValue: Equatable, Sendable {
    case null
    case bool(Bool)
    case unsigned(UInt64)
    case signed(Int64)
    case decimal(Double)
    case string(String)
    case bytes(Data)
    case timeNanoseconds(Int64)
    case ipv4(Data)
    case ipv6(Data)
    case ipv4Prefix(Data, UInt8)
    case ipv6Prefix(Data, UInt8)
    case mac(Data)
    case list([WUSPValue])
}

public struct WUSPMessageField: Equatable, Sendable {
    public let path: String
    public let value: WUSPValue

    public init(path: String, value: WUSPValue) {
        self.path = path
        self.value = value
    }
}

public struct WUSPMessage: Equatable, Sendable {
    public let deviceID: String?
    public let timestampNanoseconds: Int64?
    public let fields: [WUSPMessageField]

    public init(deviceID: String? = nil, timestampNanoseconds: Int64? = nil, fields: [WUSPMessageField]) {
        self.deviceID = deviceID
        self.timestampNanoseconds = timestampNanoseconds
        self.fields = fields
    }
}

/// Raw, uncompressed WU message frames. All fields use inline paths (field ID
/// zero), matching wantasticd's WUSP envelope encoder which clears registry IDs
/// to avoid schema-version drift between controller and agent.
public enum WUSPMessageCodec {
    private static let maxBytes = 1_048_576
    private static let maxFields = 16_384
    // FNV-1a-32 truncated to 16 bits for wantasticd's registered TR-181 paths.
    // Inline field IDs keep schema drift safe; the header fingerprint still
    // must match Go so nested WU frames are byte-compatible.
    private static let schemaFingerprint: UInt16 = 0xdb27

    public static func encode(_ message: WUSPMessage, compress: Bool = false) throws -> Data {
        guard message.fields.count <= maxFields else { throw WUSPTransportError.tooLarge }
        var flags: UInt8 = 0
        if message.deviceID?.isEmpty == false { flags |= 1 << 1 }
        if message.timestampNanoseconds != nil { flags |= 1 << 2 }
        var writer = MessageWriter()
        writer.data.append(contentsOf: [
            0x57, 0x55, 1,
            UInt8(truncatingIfNeeded: schemaFingerprint),
            UInt8(truncatingIfNeeded: schemaFingerprint >> 8),
            flags, 0, 0,
        ])
        if let deviceID = message.deviceID, !deviceID.isEmpty { try writer.string(deviceID) }
        if let timestamp = message.timestampNanoseconds { writer.zigzag(timestamp) }
        writer.varint(UInt64(message.fields.count))
        for field in message.fields {
            guard !field.path.isEmpty else { throw WUSPTransportError.malformed }
            writer.varint(0)
            try writer.string(field.path)
            try writer.value(field.value)
        }
        guard writer.data.count <= maxBytes else { throw WUSPTransportError.tooLarge }
        guard compress else { return writer.data }
        let payload = writer.data.subdata(in: 8..<writer.data.count)
        var rawSize = UInt32(payload.count).littleEndian
        guard let compressed = compressLZ4(payload) else { return writer.data }
        var frame = Data(writer.data.prefix(8))
        frame[5] |= 1
        withUnsafeBytes(of: &rawSize) { frame.append(contentsOf: $0) }
        frame.append(compressed)
        return frame
    }

    static func compressLZ4(_ source: Data) -> Data? {
        let input = [UInt8](source)
        let minMatch = 4
        let lastLiterals = 5
        guard input.count > minMatch + lastLiterals else { return nil }
        var table = [Int](repeating: -1, count: 4096)
        var output: [UInt8] = []
        output.reserveCapacity(input.count + input.count / 255 + 16)
        var inputOffset = 0
        var anchor = 0
        let limit = input.count - minMatch - lastLiterals

        while inputOffset <= limit {
            let raw = UInt32(input[inputOffset]) |
                (UInt32(input[inputOffset + 1]) << 8) |
                (UInt32(input[inputOffset + 2]) << 16) |
                (UInt32(input[inputOffset + 3]) << 24)
            let hash = Int((raw &* 2_654_435_761) >> 20)
            let reference = table[hash]
            table[hash] = inputOffset
            guard reference >= 0, reference < inputOffset, inputOffset - reference <= 65_535,
                  input[reference] == input[inputOffset], input[reference + 1] == input[inputOffset + 1],
                  input[reference + 2] == input[inputOffset + 2], input[reference + 3] == input[inputOffset + 3] else {
                inputOffset += 1
                continue
            }

            var matchLength = minMatch
            let maxMatch = min(input.count - inputOffset, 65_535 + minMatch)
            while matchLength < maxMatch && input[reference + matchLength] == input[inputOffset + matchLength] {
                matchLength += 1
            }
            let literalLength = inputOffset - anchor
            let tokenIndex = output.count
            output.append(0)
            output[tokenIndex] = UInt8(min(literalLength, 15) << 4) | UInt8(min(matchLength - minMatch, 15))
            appendLength(literalLength, to: &output)
            output.append(contentsOf: input[anchor..<inputOffset])
            let distance = UInt16(inputOffset - reference)
            output.append(UInt8(distance & 0xff))
            output.append(UInt8(distance >> 8))
            appendLength(matchLength - minMatch, to: &output)
            inputOffset += matchLength
            anchor = inputOffset
            if inputOffset <= limit {
                let next = UInt32(input[inputOffset]) |
                    (UInt32(input[inputOffset + 1]) << 8) |
                    (UInt32(input[inputOffset + 2]) << 16) |
                    (UInt32(input[inputOffset + 3]) << 24)
                table[Int((next &* 2_654_435_761) >> 20)] = inputOffset
            }
        }
        let finalLength = input.count - anchor
        output.append(UInt8(min(finalLength, 15) << 4))
        appendLength(finalLength, to: &output)
        output.append(contentsOf: input[anchor..<input.count])
        guard output.count < input.count else { return nil }
        return Data(output)
    }

    private static func appendLength(_ length: Int, to output: inout [UInt8]) {
        guard length >= 15 else { return }
        var remainder = length - 15
        while remainder >= 255 { output.append(255); remainder -= 255 }
        output.append(UInt8(remainder))
    }

    public static func decode(_ data: Data) throws -> WUSPMessage {
        guard data.count >= 8, data.count <= maxBytes,
              data[0] == 0x57, data[1] == 0x55, data[2] == 1,
              data[5] & 0b1111_1000 == 0,
              data[6] == 0, data[7] == 0 else { throw WUSPTransportError.malformed }
        let frame: Data
        if data[5] & 1 != 0 {
            guard data.count >= 12 else { throw WUSPTransportError.malformed }
            let rawSize = data[8..<12].enumerated().reduce(UInt32(0)) {
                $0 | (UInt32($1.element) << (8 * $1.offset))
            }
            guard rawSize > 0, rawSize <= maxBytes else { throw WUSPTransportError.tooLarge }
            let compressed = data.subdata(in: 12..<data.count)
            let expanded = try decompressLZ4(compressed, rawSize: Int(rawSize))
            var header = Data(data.prefix(8))
            header[5] &= ~UInt8(1)
            header.append(expanded)
            frame = header
        } else {
            frame = data
        }
        var reader = MessageReader(data: frame, offset: 8)
        let deviceID = frame[5] & (1 << 1) != 0 ? try reader.string() : nil
        let timestamp = frame[5] & (1 << 2) != 0 ? try reader.zigzag() : nil
        let count = try reader.varint()
        guard count <= UInt64(maxFields) else { throw WUSPTransportError.tooLarge }
        var fields: [WUSPMessageField] = []
        fields.reserveCapacity(Int(count))
        for _ in 0..<count {
            guard try reader.varint() == 0 else { throw WUSPTransportError.unsupported }
            let path = try reader.string()
            guard !path.isEmpty else { throw WUSPTransportError.malformed }
            fields.append(WUSPMessageField(path: path, value: try reader.value()))
        }
        guard reader.offset == frame.count else { throw WUSPTransportError.malformed }
        return WUSPMessage(deviceID: deviceID, timestampNanoseconds: timestamp, fields: fields)
    }

    static func decompressLZ4(_ source: Data, rawSize: Int) throws -> Data {
        let input = [UInt8](source)
        var output = [UInt8](repeating: 0, count: rawSize)
        var inputOffset = 0
        var outputOffset = 0
        while inputOffset < input.count {
            let token = input[inputOffset]
            inputOffset += 1
            var literalLength = Int(token >> 4)
            if literalLength == 15 {
                while true {
                    guard inputOffset < input.count else { throw WUSPTransportError.malformed }
                    let extra = Int(input[inputOffset]); inputOffset += 1
                    guard literalLength <= rawSize, extra <= rawSize - literalLength else {
                        throw WUSPTransportError.tooLarge
                    }
                    literalLength += extra
                    if extra < 255 { break }
                }
            }
            guard literalLength <= input.count - inputOffset,
                  literalLength <= output.count - outputOffset else { throw WUSPTransportError.malformed }
            for index in 0..<literalLength { output[outputOffset + index] = input[inputOffset + index] }
            inputOffset += literalLength
            outputOffset += literalLength
            if inputOffset == input.count { break }
            guard input.count - inputOffset >= 2 else { throw WUSPTransportError.malformed }
            let distance = Int(input[inputOffset]) | (Int(input[inputOffset + 1]) << 8)
            inputOffset += 2
            guard distance > 0, distance <= outputOffset else { throw WUSPTransportError.malformed }
            var matchLength = Int(token & 0x0f) + 4
            if token & 0x0f == 15 {
                while true {
                    guard inputOffset < input.count else { throw WUSPTransportError.malformed }
                    let extra = Int(input[inputOffset]); inputOffset += 1
                    guard matchLength <= rawSize, extra <= rawSize - matchLength else {
                        throw WUSPTransportError.tooLarge
                    }
                    matchLength += extra
                    if extra < 255 { break }
                }
            }
            guard matchLength <= output.count - outputOffset else { throw WUSPTransportError.malformed }
            for index in 0..<matchLength { output[outputOffset + index] = output[outputOffset - distance + index] }
            outputOffset += matchLength
        }
        guard outputOffset == rawSize else { throw WUSPTransportError.malformed }
        return Data(output)
    }

    private struct MessageWriter {
        var data = Data()
        mutating func varint(_ value: UInt64) {
            var value = value
            while value >= 0x80 { data.append(UInt8(value & 0x7f) | 0x80); value >>= 7 }
            data.append(UInt8(value))
        }
        mutating func zigzag(_ value: Int64) { varint(UInt64(bitPattern: (value << 1) ^ (value >> 63))) }
        mutating func string(_ value: String) throws { try bytes(Data(value.utf8)) }
        mutating func bytes(_ value: Data) throws {
            guard value.count <= maxBytes else { throw WUSPTransportError.tooLarge }
            varint(UInt64(value.count)); data.append(value)
        }
        mutating func value(_ itemValue: WUSPValue) throws {
            switch itemValue {
            case .null: data.append(0)
            case .bool(false): data.append(1)
            case .bool(true): data.append(2)
            case .unsigned(let number): data.append(3); varint(number)
            case .signed(let number): data.append(4); zigzag(number)
            case .decimal(let number):
                guard number.isFinite else { throw WUSPTransportError.malformed }
                data.append(5)
                var bits = number.bitPattern.littleEndian
                withUnsafeBytes(of: &bits) { data.append(contentsOf: $0) }
            case .string(let string): data.append(6); try self.string(string)
            case .bytes(let bytes): data.append(7); try self.bytes(bytes)
            case .timeNanoseconds(let time): data.append(8); zigzag(time)
            case .ipv4(let address): data.append(9); try fixed(address, count: 4)
            case .ipv6(let address): data.append(10); try fixed(address, count: 16)
            case .ipv4Prefix(let address, let prefix):
                data.append(11); try fixed(address, count: 4); data.append(prefix)
            case .ipv6Prefix(let address, let prefix):
                data.append(12); try fixed(address, count: 16); data.append(prefix)
            case .mac(let address): data.append(13); try fixed(address, count: 6)
            case .list(let items):
                guard items.count <= maxFields else { throw WUSPTransportError.tooLarge }
                data.append(14); varint(UInt64(items.count))
                for item in items { try self.value(item) }
            }
        }
        mutating func fixed(_ bytes: Data, count: Int) throws {
            guard bytes.count == count else { throw WUSPTransportError.malformed }
            data.append(bytes)
        }
    }

    private struct MessageReader {
        let data: Data
        var offset: Int
        mutating func byte() throws -> UInt8 {
            guard offset < data.count else { throw WUSPTransportError.malformed }
            defer { offset += 1 }
            return data[offset]
        }
        mutating func varint() throws -> UInt64 {
            var value: UInt64 = 0
            var shift: UInt64 = 0
            for _ in 0..<10 {
                let next = try byte()
                guard shift < 64, !(shift == 63 && next > 1) else { throw WUSPTransportError.malformed }
                value |= UInt64(next & 0x7f) << shift
                if next & 0x80 == 0 { return value }
                shift += 7
            }
            throw WUSPTransportError.malformed
        }
        mutating func zigzag() throws -> Int64 {
            let value = try varint()
            return Int64(bitPattern: (value >> 1) ^ (0 &- (value & 1)))
        }
        mutating func bytes() throws -> Data {
            let length = try varint()
            guard length <= UInt64(maxBytes), length <= UInt64(data.count - offset) else {
                throw WUSPTransportError.malformed
            }
            defer { offset += Int(length) }
            return data.subdata(in: offset..<(offset + Int(length)))
        }
        mutating func string() throws -> String {
            guard let result = String(data: try bytes(), encoding: .utf8) else { throw WUSPTransportError.malformed }
            return result
        }
        mutating func fixed(_ count: Int) throws -> Data {
            guard data.count - offset >= count else { throw WUSPTransportError.malformed }
            defer { offset += count }
            return data.subdata(in: offset..<(offset + count))
        }
        mutating func value() throws -> WUSPValue {
            switch try byte() {
            case 0: return .null
            case 1: return .bool(false)
            case 2: return .bool(true)
            case 3: return .unsigned(try varint())
            case 4: return .signed(try zigzag())
            case 5:
                let raw = try fixed(8)
                let bits = raw.enumerated().reduce(UInt64(0)) { $0 | (UInt64($1.element) << (8 * $1.offset)) }
                let number = Double(bitPattern: bits)
                guard number.isFinite else { throw WUSPTransportError.malformed }
                return .decimal(number)
            case 6: return .string(try string())
            case 7: return .bytes(try bytes())
            case 8: return .timeNanoseconds(try zigzag())
            case 9: return .ipv4(try fixed(4))
            case 10: return .ipv6(try fixed(16))
            case 11: return .ipv4Prefix(try fixed(4), try byte())
            case 12: return .ipv6Prefix(try fixed(16), try byte())
            case 13: return .mac(try fixed(6))
            case 14:
                let count = try varint()
                guard count <= UInt64(maxFields) else { throw WUSPTransportError.tooLarge }
                var values: [WUSPValue] = []
                values.reserveCapacity(Int(count))
                for _ in 0..<count { values.append(try value()) }
                return .list(values)
            default: throw WUSPTransportError.unsupported
            }
        }
    }
}
