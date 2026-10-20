import Darwin
import Foundation
import WantasticCore

public enum MacLocalAccessProviderError: Error, Equatable {
    case invalidRouteSelection
    case tunnelInterfaceNotFound
    case noPrivateOverlayAddresses
    case alreadyEnabled
}

/// Runs the local-access lifecycle inside the authenticated packet provider.
/// Client route strings are only selectors: interface and PF data are always
/// reconstructed from the provider's live configuration and host interfaces.
public actor MacLocalAccessProviderManager: TunnelProviderLocalAccessManaging {
    private let configuration: WireGuardConfiguration
    private let coordinator: MacLocalAccessRouteCoordinator
    private let routeDiscovery: @Sendable () throws -> [MacLocalAccessRoute]
    private let interfaceResolver: @Sendable (String) throws -> String?

    public init(configuration: WireGuardConfiguration,
                sender: any TunnelControlPayloadSender,
                firewall: MacLocalAccessFirewallController = MacLocalAccessFirewallController(
                    system: XPCMacLocalAccessFirewallSystem()),
                routeDiscovery: @escaping @Sendable () throws -> [MacLocalAccessRoute] = {
                    try MacDeviceCollector.privateLANRouteCandidates()
                },
                interfaceResolver: @escaping @Sendable (String) throws -> String? = {
                    try MacDeviceCollector.interfaceName(owningIPv4Address: $0)
                }) {
        self.configuration = configuration
        coordinator = MacLocalAccessRouteCoordinator(firewall: firewall, sender: sender)
        self.routeDiscovery = routeDiscovery
        self.interfaceResolver = interfaceResolver
    }

    public func enable(routes requestedRoutes: [String]) async throws {
        guard !requestedRoutes.isEmpty,
              requestedRoutes.count <= TunnelControlCodec.maxRoutesPerOwner else {
            throw MacLocalAccessProviderError.invalidRouteSelection
        }
        let normalized = try requestedRoutes.map(TunnelIPv4Prefix.init)
        guard Set(normalized).count == normalized.count else {
            throw MacLocalAccessProviderError.invalidRouteSelection
        }
        let candidates = try routeDiscovery()
        let candidateByPrefix = Dictionary(uniqueKeysWithValues: candidates.map { ($0.prefix, $0) })
        let selected = try normalized.map { prefix -> MacLocalAccessRoute in
            guard let candidate = candidateByPrefix[prefix] else {
                throw MacLocalAccessProviderError.invalidRouteSelection
            }
            return candidate
        }
        guard !(await coordinator.isActive) else {
            throw MacLocalAccessProviderError.alreadyEnabled
        }

        let overlaySources = configuration.addresses.compactMap { value -> String? in
            let host = String(value.split(separator: "/", maxSplits: 1).first ?? "")
            var address = in_addr()
            guard host.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return nil }
            return "\(host)/32"
        }
        guard !overlaySources.isEmpty else {
            throw MacLocalAccessProviderError.noPrivateOverlayAddresses
        }
        guard let tunnelAddress = overlaySources.first?.split(separator: "/").first,
              let tunnelInterface = try interfaceResolver(String(tunnelAddress)) else {
            throw MacLocalAccessProviderError.tunnelInterfaceNotFound
        }
        let plan = try MacLocalAccessFirewallPlan(tunnelInterfaceName: tunnelInterface,
                                                  routes: selected,
                                                  overlaySources: overlaySources)
        try await coordinator.activate(plan)
    }

    public func disable() async throws {
        guard await coordinator.isActive else { return }
        try await coordinator.deactivate()
    }

    public func isEnabled() async -> Bool {
        await coordinator.isActive
    }
}
