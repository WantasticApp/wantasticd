import Darwin
import Foundation

/// Enforces the IPv4 AllowedIPs identity for packets arriving over a direct
/// peer session before they enter the host packet flow.
public enum TunnelPeerPacketPolicy {
    public static func acceptsIPv4(_ packet: Data, sourceAddress: String) -> Bool {
        guard packet.count >= 20, packet[0] >> 4 == 4 else { return false }
        let headerLength = Int(packet[0] & 0x0f) * 4
        let totalLength = Int(packet[2]) << 8 | Int(packet[3])
        guard headerLength >= 20, headerLength <= packet.count,
              totalLength >= headerLength, totalLength <= packet.count else {
            return false
        }

        var expectedSource = in_addr()
        guard sourceAddress.withCString({ inet_pton(AF_INET, $0, &expectedSource) }) == 1 else {
            return false
        }
        let expectedBytes = withUnsafeBytes(of: expectedSource) { Data($0) }
        return packet.subdata(in: 12..<16) == expectedBytes
    }
}
