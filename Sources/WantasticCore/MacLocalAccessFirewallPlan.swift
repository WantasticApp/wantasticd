import Foundation

public struct MacLocalAccessRoute: Equatable, Sendable {
    public let prefix: TunnelIPv4Prefix
    public let interfaceName: String

    public init(prefix: String, interfaceName: String) throws {
        try self.init(prefix: TunnelIPv4Prefix(prefix), interfaceName: interfaceName)
    }

    public init(prefix: TunnelIPv4Prefix, interfaceName: String) throws {
        guard Self.isValidInterfaceName(interfaceName) else {
            throw MacLocalAccessFirewallError.invalidInterface
        }
        self.prefix = prefix
        self.interfaceName = interfaceName
    }

    fileprivate static func isValidInterfaceName(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 32 else { return false }
        return value.utf8.allSatisfy { byte in
            (65...90).contains(byte) || (97...122).contains(byte) ||
                (48...57).contains(byte) || byte == 46 || byte == 95 || byte == 45
        }
    }
}

public enum MacLocalAccessFirewallError: Error, Equatable {
    case invalidInterface
    case noRoutes
    case tooManyRoutes
    case overlappingOverlayRoute
    case conflictingEgressInterfaces
}

/// Produces rules for the Wantastic-owned PF anchor. This type is pure: it
/// never enables PF, changes forwarding state, launches a process, or writes
/// system configuration. A privileged service must validate and apply the
/// plan separately.
public struct MacLocalAccessFirewallPlan: Equatable, Sendable {
    public static let pfAnchor = "com.apple/wantastic"
    public static let maximumRoutes = TunnelControlCodec.maxRoutesPerOwner

    public let tunnelInterfaceName: String
    public let routes: [MacLocalAccessRoute]
    public let overlaySources: [TunnelIPv4Prefix]

    public init(tunnelInterfaceName: String, routes: [MacLocalAccessRoute],
                overlaySources: [String]) throws {
        guard MacLocalAccessRoute.isValidInterfaceName(tunnelInterfaceName) else {
            throw MacLocalAccessFirewallError.invalidInterface
        }
        guard !routes.isEmpty, !overlaySources.isEmpty else {
            throw MacLocalAccessFirewallError.noRoutes
        }
        guard routes.count <= Self.maximumRoutes,
              overlaySources.count <= Self.maximumRoutes else {
            throw MacLocalAccessFirewallError.tooManyRoutes
        }

        let sources = try Array(Set(overlaySources.map(TunnelIPv4Prefix.init)))
            .sorted { $0.description < $1.description }
        let routesByPrefix = Dictionary(grouping: routes, by: \.prefix)
        guard routesByPrefix.values.allSatisfy({ Set($0.map(\.interfaceName)).count == 1 }) else {
            throw MacLocalAccessFirewallError.conflictingEgressInterfaces
        }
        let normalizedRoutes = try routesByPrefix.keys.sorted { $0.description < $1.description }.map { prefix in
            try MacLocalAccessRoute(prefix: prefix, interfaceName: routesByPrefix[prefix]![0].interfaceName)
        }

        for route in normalizedRoutes {
            guard route.interfaceName != tunnelInterfaceName else {
                throw MacLocalAccessFirewallError.invalidInterface
            }
            for source in sources where Self.overlaps(route.prefix, source) {
                throw MacLocalAccessFirewallError.overlappingOverlayRoute
            }
        }
        self.tunnelInterfaceName = tunnelInterfaceName
        self.routes = normalizedRoutes
        self.overlaySources = sources
    }

    /// Matches the deployed Darwin agent's rule layout and Wantastic anchor
    /// semantics. Prefixes are canonicalized and output order is deterministic.
    public var rules: String {
        var result = ""
        for route in routes {
            for source in overlaySources {
                result += "nat on \(route.interfaceName) inet from \(source.description) to \(route.prefix.description) -> (\(route.interfaceName))\n"
                result += "pass in quick on \(tunnelInterfaceName) inet from \(source.description) to \(route.prefix.description) keep state\n"
            }
        }
        return result
    }

    private static func overlaps(_ lhs: TunnelIPv4Prefix, _ rhs: TunnelIPv4Prefix) -> Bool {
        let commonLength = min(lhs.prefixLength, rhs.prefixLength)
        let mask = commonLength == 0 ? UInt32(0) : UInt32.max << (32 - commonLength)
        return lhs.address & mask == rhs.address & mask
    }
}

/// Serializable request body for a privileged firewall helper. Decoding never
/// trusts a caller-supplied PF rule string; the helper must reconstruct the
/// plan through the validating initializer before applying it.
public struct MacLocalAccessFirewallPlanRequest: Codable, Equatable, Sendable {
    public struct Route: Codable, Equatable, Sendable {
        public let prefix: String
        public let interfaceName: String

        public init(prefix: String, interfaceName: String) {
            self.prefix = prefix
            self.interfaceName = interfaceName
        }
    }

    public let tunnelInterfaceName: String
    public let routes: [Route]
    public let overlaySources: [String]

    public init(plan: MacLocalAccessFirewallPlan) {
        tunnelInterfaceName = plan.tunnelInterfaceName
        routes = plan.routes.map { Route(prefix: $0.prefix.description, interfaceName: $0.interfaceName) }
        overlaySources = plan.overlaySources.map(\.description)
    }

    public init(tunnelInterfaceName: String, routes: [Route], overlaySources: [String]) {
        self.tunnelInterfaceName = tunnelInterfaceName
        self.routes = routes
        self.overlaySources = overlaySources
    }

    public func validatedPlan() throws -> MacLocalAccessFirewallPlan {
        try MacLocalAccessFirewallPlan(
            tunnelInterfaceName: tunnelInterfaceName,
            routes: routes.map { try MacLocalAccessRoute(prefix: $0.prefix, interfaceName: $0.interfaceName) },
            overlaySources: overlaySources)
    }
}
