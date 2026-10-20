import Darwin
import Foundation
import NetworkExtension
import WantasticCore

enum TunnelNetworkSettingsError: Error, Equatable {
    case invalidCIDR
    case invalidDNSAddress
    case endpointResolutionFailed
    case noTunnelAddresses
    case routeFamilyMissingAddress
    case localRouteOverlapsTunnel
}

/// Builds a split-tunnel configuration from validated WireGuard prefixes and
/// installs endpoint host routes as exclusions so the UDP socket stays outside
/// its own tunnel.
enum TunnelNetworkSettingsBuilder {
    private static let magicDNSDomain = "wantastic"

    private struct Prefix {
        let address: String
        let family: Int32
        let length: UInt8
    }

    static func build(_ configuration: WireGuardConfiguration,
                      localAccessRoutes: [TunnelIPv4Prefix] = [],
                      exitNodeRoutes: [String] = []) throws -> NEPacketTunnelNetworkSettings {
        let assigned = try configuration.addresses.map(parsePrefix)
        let configuredRoutes = try configuration.allowedIPs.map(parsePrefix)
        let requestedLocalRoutes = try localAccessRoutes.map { try parsePrefix($0.description) }
        _ = try exitNodeRoutes.map(parsePrefix)
        for localRoute in requestedLocalRoutes where configuredRoutes.contains(where: {
            $0.family == AF_INET && overlapsIPv4(localRoute, $0) &&
                !($0.address == localRoute.address && $0.length == localRoute.length)
        }) {
            throw TunnelNetworkSettingsError.localRouteOverlapsTunnel
        }
        var routeStrings = configuration.allowedIPs
        for route in exitNodeRoutes where !routeStrings.contains(route) {
            routeStrings.append(route)
        }
        for route in localAccessRoutes.map(\.description) where !routeStrings.contains(route) {
            routeStrings.append(route)
        }
        let routes = try routeStrings.map(parsePrefix)
        guard !assigned.isEmpty else { throw TunnelNetworkSettingsError.noTunnelAddresses }
        let endpoints = try resolve(configuration.endpointHost)
        guard let remote = endpoints.first else { throw TunnelNetworkSettingsError.endpointResolutionFailed }

        let ipv4Addresses = assigned.filter { $0.family == AF_INET }
        let ipv6Addresses = assigned.filter { $0.family == AF_INET6 }
        let ipv4Routes = routes.filter { $0.family == AF_INET }
        let ipv6Routes = routes.filter { $0.family == AF_INET6 }
        guard ipv4Routes.isEmpty || !ipv4Addresses.isEmpty,
              ipv6Routes.isEmpty || !ipv6Addresses.isEmpty else {
            throw TunnelNetworkSettingsError.routeFamilyMissingAddress
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote.address)
        if !ipv4Addresses.isEmpty {
            let ipv4 = NEIPv4Settings(
                addresses: ipv4Addresses.map(\.address),
                subnetMasks: ipv4Addresses.map { ipv4Mask($0.length) }
            )
            ipv4.includedRoutes = ipv4Routes.map {
                NEIPv4Route(destinationAddress: $0.address, subnetMask: ipv4Mask($0.length))
            }
            ipv4.excludedRoutes = endpoints.filter { $0.family == AF_INET }.map {
                NEIPv4Route(destinationAddress: $0.address, subnetMask: "255.255.255.255")
            }
            settings.ipv4Settings = ipv4
        }
        if !ipv6Addresses.isEmpty {
            let ipv6 = NEIPv6Settings(
                addresses: ipv6Addresses.map(\.address),
                networkPrefixLengths: ipv6Addresses.map { NSNumber(value: $0.length) }
            )
            ipv6.includedRoutes = ipv6Routes.map {
                NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.length))
            }
            ipv6.excludedRoutes = endpoints.filter { $0.family == AF_INET6 }.map {
                NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: 128)
            }
            settings.ipv6Settings = ipv6
        }

        var seenDNSServers = Set<String>()
        let dnsServers = configuration.dnsServers.filter { seenDNSServers.insert($0).inserted }
        if !dnsServers.isEmpty {
            guard dnsServers.allSatisfy(isIPAddress) else {
                throw TunnelNetworkSettingsError.invalidDNSAddress
            }
            let dns = NEDNSSettings(servers: dnsServers)
            dns.matchDomains = [Self.magicDNSDomain]
            dns.searchDomains = [Self.magicDNSDomain]
            dns.matchDomainsNoSearch = true
            settings.dnsSettings = dns
        }
        settings.mtu = NSNumber(value: configuration.mtu)
        return settings
    }

    private static func parsePrefix(_ value: String) throws -> Prefix {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let length = UInt8(parts[1]) else {
            throw TunnelNetworkSettingsError.invalidCIDR
        }
        let address = String(parts[0])
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1, length <= 32 {
            return Prefix(address: address, family: AF_INET, length: length)
        }
        var ipv6 = in6_addr()
        if address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1, length <= 128 {
            return Prefix(address: address, family: AF_INET6, length: length)
        }
        throw TunnelNetworkSettingsError.invalidCIDR
    }

    private static func isIPAddress(_ value: String) -> Bool {
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 { return true }
        var ipv6 = in6_addr()
        return value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1
    }

    private static func overlapsIPv4(_ lhs: Prefix, _ rhs: Prefix) -> Bool {
        guard lhs.family == AF_INET, rhs.family == AF_INET else { return false }
        var left = in_addr()
        var right = in_addr()
        guard lhs.address.withCString({ inet_pton(AF_INET, $0, &left) }) == 1,
              rhs.address.withCString({ inet_pton(AF_INET, $0, &right) }) == 1 else { return false }
        let leftValue = UInt32(bigEndian: left.s_addr)
        let rightValue = UInt32(bigEndian: right.s_addr)
        let commonLength = min(lhs.length, rhs.length)
        let mask = commonLength == 0 ? UInt32(0) : UInt32.max << (32 - commonLength)
        return (leftValue & mask) == (rightValue & mask)
    }

    private static func ipv4Mask(_ length: UInt8) -> String {
        (0..<4).map { index in
            let bits = min(max(Int(length) - index * 8, 0), 8)
            return bits == 0 ? 0 : (0xff << (8 - bits)) & 0xff
        }.map(String.init).joined(separator: ".")
    }

    private static func resolve(_ host: String) throws -> [Prefix] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var head: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &head) == 0, let head else {
            throw TunnelNetworkSettingsError.endpointResolutionFailed
        }
        defer { freeaddrinfo(head) }

        var results: [Prefix] = []
        var current: UnsafeMutablePointer<addrinfo>? = head
        while let item = current?.pointee {
            if item.ai_family == AF_INET, let address = item.ai_addr {
                let value = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
                let bytes = withUnsafeBytes(of: value) { Array($0) }
                results.append(Prefix(address: bytes.map(String.init).joined(separator: "."),
                                      family: AF_INET, length: 32))
            } else if item.ai_family == AF_INET6, let address = item.ai_addr {
                let value = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in6.self).pointee.sin6_addr
                let bytes = withUnsafeBytes(of: value) { Array($0) }
                let rendered = stride(from: 0, to: 16, by: 2).map { index in
                    String(format: "%x", UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1]))
                }.joined(separator: ":")
                results.append(Prefix(address: rendered, family: AF_INET6, length: 128))
            }
            current = item.ai_next
        }
        return results
    }
}
