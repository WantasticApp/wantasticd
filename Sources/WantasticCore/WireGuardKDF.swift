import Foundation

/// WireGuard's BLAKE2s-256 hash, HMAC, and one-to-three-output KDF.
/// The implementation follows RFC 7693 and is kept private to the WireGuard
/// handshake layer so it cannot be confused with the app's SHA-256 APIs.
public enum WireGuardKDF {
    public static func blake2s(_ input: Data) -> Data {
        Blake2s.hash(input)
    }

    /// Keyed BLAKE2s, matching Go's `blake2s.New256(sharedSecret)` P2P tag.
    public static func keyedBlake2s(key: Data, message: Data) -> Data {
        Blake2s.hash(message, key: key)
    }

    static func blake2s128(key: Data, message: Data) -> Data {
        Blake2s.hash(message, outputLength: 16, key: key)
    }

    public static func hmac(key: Data, message: Data) -> Data {
        let blockSize = 64
        var normalizedKey = key.count > blockSize ? Blake2s.hash(key) : key
        if normalizedKey.count < blockSize {
            normalizedKey.append(Data(repeating: 0, count: blockSize - normalizedKey.count))
        }
        var inner = Data(repeating: 0x36, count: blockSize)
        var outer = Data(repeating: 0x5c, count: blockSize)
        for index in 0..<blockSize {
            inner[index] ^= normalizedKey[index]
            outer[index] ^= normalizedKey[index]
        }
        inner.append(message)
        outer.append(Blake2s.hash(inner))
        return Blake2s.hash(outer)
    }

    public static func derive1(chainingKey: Data, input: Data) -> [Data] {
        let pseudorandomKey = hmac(key: chainingKey, message: input)
        return [hmac(key: pseudorandomKey, message: Data([1]))]
    }

    public static func derive2(chainingKey: Data, input: Data) -> [Data] {
        expand(chainingKey: chainingKey, input: input, count: 2)
    }

    public static func derive3(chainingKey: Data, input: Data) -> [Data] {
        expand(chainingKey: chainingKey, input: input, count: 3)
    }

    private static func expand(chainingKey: Data, input: Data, count: Int) -> [Data] {
        let pseudorandomKey = hmac(key: chainingKey, message: input)
        var output: [Data] = []
        var previous = Data()
        for counter in 1...count {
            var message = previous
            message.append(UInt8(counter))
            previous = hmac(key: pseudorandomKey, message: message)
            output.append(previous)
        }
        return output
    }
}

private enum Blake2s {
    private static let initializationVector: [UInt32] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]

    private static let permutations: [[UInt8]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    static func hash(_ message: Data, outputLength: Int = 32, key: Data = Data()) -> Data {
        precondition((1...32).contains(outputLength) && key.count <= 32)
        var input = Data()
        if !key.isEmpty {
            input.append(key)
            input.append(Data(repeating: 0, count: 64 - key.count))
        }
        input.append(message)

        var state = initializationVector
        state[0] ^= 0x01010000 | (UInt32(key.count) << 8) | UInt32(outputLength)
        var offset = 0
        var count: UInt64 = 0

        while input.count - offset > 64 {
            let block = input.subdata(in: offset..<(offset + 64))
            count += 64
            compress(&state, block: block, byteCount: count, isLast: false)
            offset += 64
        }

        let finalLength = input.count - offset
        var finalBlock = input.subdata(in: offset..<input.count)
        if finalLength < 64 {
            finalBlock.append(Data(repeating: 0, count: 64 - finalLength))
        }
        count += UInt64(finalLength)
        compress(&state, block: finalBlock, byteCount: count, isLast: true)

        var digest = Data()
        digest.reserveCapacity(32)
        for word in state {
            var littleEndian = word.littleEndian
            withUnsafeBytes(of: &littleEndian) { digest.append(contentsOf: $0) }
        }
        return Data(digest.prefix(outputLength))
    }

    private static func compress(_ state: inout [UInt32], block: Data, byteCount: UInt64, isLast: Bool) {
        var message = [UInt32](repeating: 0, count: 16)
        for index in 0..<16 {
            let start = index * 4
            message[index] = UInt32(block[start]) | (UInt32(block[start + 1]) << 8) |
                (UInt32(block[start + 2]) << 16) | (UInt32(block[start + 3]) << 24)
        }

        var work = state + initializationVector
        work[12] ^= UInt32(truncatingIfNeeded: byteCount)
        work[13] ^= UInt32(truncatingIfNeeded: byteCount >> 32)
        if isLast { work[14] ^= .max }

        for round in 0..<10 {
            let s = permutations[round]
            mix(&work, 0, 4, 8, 12, message[Int(s[0])], message[Int(s[1])])
            mix(&work, 1, 5, 9, 13, message[Int(s[2])], message[Int(s[3])])
            mix(&work, 2, 6, 10, 14, message[Int(s[4])], message[Int(s[5])])
            mix(&work, 3, 7, 11, 15, message[Int(s[6])], message[Int(s[7])])
            mix(&work, 0, 5, 10, 15, message[Int(s[8])], message[Int(s[9])])
            mix(&work, 1, 6, 11, 12, message[Int(s[10])], message[Int(s[11])])
            mix(&work, 2, 7, 8, 13, message[Int(s[12])], message[Int(s[13])])
            mix(&work, 3, 4, 9, 14, message[Int(s[14])], message[Int(s[15])])
        }

        for index in 0..<8 { state[index] ^= work[index] ^ work[index + 8] }
    }

    private static func mix(_ v: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int,
                            _ x: UInt32, _ y: UInt32) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = rotateRight(v[d] ^ v[a], by: 16)
        v[c] = v[c] &+ v[d]
        v[b] = rotateRight(v[b] ^ v[c], by: 12)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = rotateRight(v[d] ^ v[a], by: 8)
        v[c] = v[c] &+ v[d]
        v[b] = rotateRight(v[b] ^ v[c], by: 7)
    }

    private static func rotateRight(_ value: UInt32, by amount: UInt32) -> UInt32 {
        (value >> amount) | (value << (32 - amount))
    }
}
