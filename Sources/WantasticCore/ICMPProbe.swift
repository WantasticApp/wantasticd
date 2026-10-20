import Darwin
import Foundation

public enum ICMPProbeError: Error, Equatable {
    case invalidAddress
    case invalidTimeout
    case socketFailure(Int32)
    case sendFailure(Int32)
    case timedOut
}

/// Sends one native ICMP echo request using an unprivileged datagram socket.
/// It does not launch `/sbin/ping` or any other subprocess.
public enum ICMPProbe {
    private static let queue = DispatchQueue(label: "app.wantastic.icmp-probe", attributes: .concurrent)
    private static let payloadPrefix = Array("wantastic".utf8)

    public static func ping(address: String, timeout: TimeInterval = 0.75) async throws -> Int64 {
        guard timeout.isFinite, (0.1...5).contains(timeout) else { throw ICMPProbeError.invalidTimeout }
        guard let family = addressFamily(address) else { throw ICMPProbeError.invalidAddress }
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    continuation.resume(returning: try pingSynchronously(address: address, family: family, timeout: timeout))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private static func addressFamily(_ value: String) -> Int32? {
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 { return AF_INET }
        var ipv6 = in6_addr()
        if value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 { return AF_INET6 }
        return nil
    }

    private static func pingSynchronously(address: String, family: Int32, timeout: TimeInterval) throws -> Int64 {
        let protocolNumber = family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6
        let descriptor = Darwin.socket(family, SOCK_DGRAM, protocolNumber)
        guard descriptor >= 0 else { throw ICMPProbeError.socketFailure(errno) }
        defer { Darwin.close(descriptor) }

        let identifier = UInt16(truncatingIfNeeded: getpid())
        let sequence = UInt16(truncatingIfNeeded: arc4random())
        var nonce = UInt64.random(in: .min ... .max).bigEndian
        let nonceBytes = withUnsafeBytes(of: &nonce) { Array($0) }
        let payload = payloadPrefix + nonceBytes
        var packet = [UInt8](repeating: 0, count: 8)
        packet[0] = family == AF_INET ? 8 : 128
        packet[4] = UInt8(identifier >> 8)
        packet[5] = UInt8(identifier & 0xff)
        packet[6] = UInt8(sequence >> 8)
        packet[7] = UInt8(sequence & 0xff)
        packet.append(contentsOf: payload)
        if family == AF_INET {
            let checksum = internetChecksum(packet)
            packet[2] = UInt8(checksum >> 8)
            packet[3] = UInt8(checksum & 0xff)
        }

        let started = DispatchTime.now().uptimeNanoseconds
        let sent: Int
        if family == AF_INET {
            var destination = sockaddr_in()
            destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            destination.sin_family = sa_family_t(AF_INET)
            guard address.withCString({ inet_pton(AF_INET, $0, &destination.sin_addr) }) == 1 else {
                throw ICMPProbeError.invalidAddress
            }
            sent = packet.withUnsafeBytes { bytes in
                withUnsafePointer(to: &destination) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.sendto(descriptor, bytes.baseAddress, packet.count, 0, $0,
                                      socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
        } else {
            var destination = sockaddr_in6()
            destination.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            destination.sin6_family = sa_family_t(AF_INET6)
            guard address.withCString({ inet_pton(AF_INET6, $0, &destination.sin6_addr) }) == 1 else {
                throw ICMPProbeError.invalidAddress
            }
            sent = packet.withUnsafeBytes { bytes in
                withUnsafePointer(to: &destination) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.sendto(descriptor, bytes.baseAddress, packet.count, 0, $0,
                                      socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
            }
        }
        guard sent == packet.count else { throw ICMPProbeError.sendFailure(errno) }

        let deadline = started &+ UInt64(timeout * 1_000_000_000)
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw ICMPProbeError.timedOut }
            let remainingMS = Int32(max(1, min(Int64(Int32.max), Int64((deadline - now) / 1_000_000))))
            var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&pollDescriptor, 1, remainingMS)
            if ready == 0 { throw ICMPProbeError.timedOut }
            if ready < 0 {
                if errno == EINTR { continue }
                throw ICMPProbeError.socketFailure(errno)
            }
            var response = [UInt8](repeating: 0, count: 2048)
            let received = response.withUnsafeMutableBytes {
                Darwin.recvfrom(descriptor, $0.baseAddress, $0.count, 0, nil, nil)
            }
            if received < 8 { continue }
            let bytes = Array(response.prefix(received))
            let headerOffset = icmpHeaderOffset(bytes, family: family)
            guard bytes.count >= headerOffset + 8 else { continue }
            let expectedType: UInt8 = family == AF_INET ? 0 : 129
            let responsePayload = Array(bytes.dropFirst(headerOffset + 8))
            guard bytes[headerOffset] == expectedType, bytes[headerOffset + 1] == 0,
                  responsePayload == payload else { continue }
            let elapsed = DispatchTime.now().uptimeNanoseconds - started
            return max(1, Int64(elapsed / 1_000_000))
        }
    }

    private static func icmpHeaderOffset(_ packet: [UInt8], family: Int32) -> Int {
        guard family == AF_INET, !packet.isEmpty, packet[0] >> 4 == 4, packet.count >= 20 else { return 0 }
        return Int(packet[0] & 0x0f) * 4
    }

    private static func internetChecksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < bytes.count {
            sum += (UInt32(bytes[index]) << 8) | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count { sum += UInt32(bytes[index]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum & 0xffff)
    }
}

public struct PingSample: Equatable, Sendable {
    public let latencyMS: Int64
    public let reachable: Bool

    public init(latencyMS: Int64 = 0, reachable: Bool) {
        self.latencyMS = latencyMS
        self.reachable = reachable
    }
}

public struct PingResult: Equatable, Sendable {
    public let target: String
    public let address: String
    public let reachable: Bool
    public let averageMS: Int64
    public let packetLoss: Int
    public let samples: [PingSample]

    public init(target: String, address: String, reachable: Bool, averageMS: Int64,
                packetLoss: Int, samples: [PingSample]) {
        self.target = target
        self.address = address
        self.reachable = reachable
        self.averageMS = averageMS
        self.packetLoss = packetLoss
        self.samples = samples
    }
}

public enum NativePingService {
    public static func ping(target: String, address: String, sampleCount: Int = 6,
                            timeout: TimeInterval = 0.75, interval: Duration = .milliseconds(75)) async throws -> PingResult {
        guard (1...10).contains(sampleCount) else { throw NativePingError.invalidSampleCount }
        var samples: [PingSample] = []
        samples.reserveCapacity(sampleCount)
        var totalMS: Int64 = 0
        var received = 0

        for index in 0..<sampleCount {
            do {
                let latency = try await ICMPProbe.ping(address: address, timeout: timeout)
                samples.append(PingSample(latencyMS: latency, reachable: true))
                totalMS += latency
                received += 1
            } catch ICMPProbeError.timedOut {
                samples.append(PingSample(reachable: false))
            }
            if index + 1 < sampleCount { try await Task.sleep(for: interval) }
        }
        let average = received > 0 ? max(1, totalMS / Int64(received)) : 0
        return PingResult(target: target, address: address, reachable: received > 0,
                          averageMS: average, packetLoss: (sampleCount - received) * 100 / sampleCount,
                          samples: samples)
    }
}

public enum NativePingError: Error, Equatable {
    case invalidSampleCount
}
