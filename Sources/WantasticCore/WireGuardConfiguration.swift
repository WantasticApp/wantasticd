import Foundation
import Darwin

public struct WireGuardConfiguration: Codable, Equatable, Sendable {
    public let privateKey: String
    public let addresses: [String]
    public let dnsServers: [String]
    public let peerPublicKey: String
    public let peerPresharedKey: String?
    public let endpointHost: String
    public let endpointPort: UInt16
    public let allowedIPs: [String]
    public let persistentKeepalive: UInt16
    public let listenPort: UInt16
    public let mtu: Int

    /// Builds a peer-only configuration for direct P2P validation while
    /// retaining the local interface identity and assigned addresses.
    public func directPeer(publicKey: Data, endpoint: P2PEndpoint,
                           assignedIPv4: String) throws -> WireGuardConfiguration {
        guard publicKey.count == 32, endpoint.port > 0,
              Self.isIPv4Address(assignedIPv4), Self.isIPv4Prefix("\(assignedIPv4)/32"),
              let endpointHost = Self.endpointHost(endpoint) else {
            throw WireGuardConfigError.invalidAddress
        }
        return WireGuardConfiguration(
            privateKey: privateKey,
            addresses: addresses,
            dnsServers: dnsServers,
            peerPublicKey: publicKey.base64EncodedString(),
            peerPresharedKey: nil,
            endpointHost: endpointHost,
            endpointPort: endpoint.port,
            allowedIPs: ["\(assignedIPv4)/32"],
            persistentKeepalive: 25,
            listenPort: listenPort,
            mtu: mtu
        )
    }

    public static func parse(_ text: String) throws -> WireGuardConfiguration {
        guard text.utf8.count <= 64 * 1024 else { throw WireGuardConfigError.tooLarge }
        var sections: [[String: String]] = []
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.split(whereSeparator: { $0 == "#" || $0 == ";" }).first.map(String.init)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if line.isEmpty { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                let name = String(line.dropFirst().dropLast()).lowercased()
                guard name == "interface" || name == "peer" else { throw WireGuardConfigError.malformedLine }
                sections.append(["__section": name])
                continue
            }
            guard !sections.isEmpty, let separator = line.firstIndex(of: "=") else {
                throw WireGuardConfigError.malformedLine
            }
            let key = line[..<separator].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !key.isEmpty, !value.isEmpty, let index = sections.indices.last else {
                throw WireGuardConfigError.duplicateOrEmptyField
            }
            let section = sections[index]["__section"] ?? ""
            let supported: Set<String> = section == "interface"
                ? ["privatekey", "address", "dns", "listenport", "mtu"]
                : ["publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"]
            guard supported.contains(key), sections[index][key] == nil else {
                throw supported.contains(key) ? WireGuardConfigError.duplicateOrEmptyField : WireGuardConfigError.unsupportedField
            }
            sections[index][key] = value
        }

        guard let interface = sections.first(where: { $0["__section"] == "interface" }),
              let peer = sections.first(where: { $0["__section"] == "peer" }),
              sections.filter({ $0["__section"] == "interface" }).count == 1,
              sections.filter({ $0["__section"] == "peer" }).count == 1,
              let privateKey = interface["privatekey"],
              let address = interface["address"],
              let publicKey = peer["publickey"],
              let endpoint = peer["endpoint"],
              let allowedIPs = peer["allowedips"] else {
            throw WireGuardConfigError.missingRequiredField
        }
        guard validKey(privateKey), validKey(publicKey) else { throw WireGuardConfigError.invalidKey }
        let presharedKey = peer["presharedkey"]
        if let presharedKey, !validKey(presharedKey) { throw WireGuardConfigError.invalidKey }
        let addresses = address.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let routes = allowedIPs.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard !addresses.isEmpty, addresses.allSatisfy(validPrefix),
              !routes.isEmpty, routes.allSatisfy(validPrefix) else { throw WireGuardConfigError.invalidAddress }
        let endpointParts = try parseEndpoint(endpoint)
        let keepalive = UInt16(peer["persistentkeepalive"] ?? "0")
        guard let keepalive else { throw WireGuardConfigError.invalidValue }
        let listenPort = UInt16(interface["listenport"] ?? "0")
        let mtu = Int(interface["mtu"] ?? "1420")
        guard let listenPort, let mtu, (mtu == 0 || (576...9000).contains(mtu)) else {
            throw WireGuardConfigError.invalidValue
        }
        return WireGuardConfiguration(
            privateKey: privateKey,
            addresses: addresses,
            dnsServers: (interface["dns"] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) },
            peerPublicKey: publicKey,
            peerPresharedKey: presharedKey,
            endpointHost: endpointParts.host,
            endpointPort: endpointParts.port,
            allowedIPs: routes,
            persistentKeepalive: keepalive,
            listenPort: listenPort,
            mtu: mtu == 0 ? 1420 : mtu
        )
    }

    private static func validKey(_ key: String) -> Bool {
        guard let data = Data(base64Encoded: key) else { return false }
        return data.count == 32
    }

    private static func validPrefix(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = UInt8(parts[1]) else { return false }
        let address = String(parts[0])
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 { return prefix <= 32 }
        var ipv6 = in6_addr()
        return address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 && prefix <= 128
    }

    private static func isIPv4Address(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
    }

    private static func isIPv4Prefix(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[1] == "32" else { return false }
        return isIPv4Address(String(parts[0]))
    }

    private static func endpointHost(_ endpoint: P2PEndpoint) -> String? {
        let family: Int32
        switch endpoint.address.count {
        case MemoryLayout<in_addr>.size: family = AF_INET
        case MemoryLayout<in6_addr>.size: family = AF_INET6
        default: return nil
        }
        var host = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = endpoint.address.withUnsafeBytes { bytes in
            inet_ntop(family, bytes.baseAddress, &host, socklen_t(host.count))
        }
        guard result != nil else { return nil }
        let value = String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                           as: UTF8.self)
        return family == AF_INET6 ? "[\(value)]" : value
    }

    private static func parseEndpoint(_ endpoint: String) throws -> (host: String, port: UInt16) {
        guard let components = URLComponents(string: "wg://\(endpoint)"),
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.path.isEmpty, components.query == nil, components.fragment == nil,
              let port = components.port, (1...65535).contains(port) else {
            throw WireGuardConfigError.invalidEndpoint
        }
        return (host, UInt16(port))
    }
}

public enum WireGuardConfigError: Error, Equatable {
    case tooLarge
    case malformedLine
    case duplicateOrEmptyField
    case unsupportedField
    case missingRequiredField
    case invalidKey
    case invalidAddress
    case invalidEndpoint
    case invalidValue
}
