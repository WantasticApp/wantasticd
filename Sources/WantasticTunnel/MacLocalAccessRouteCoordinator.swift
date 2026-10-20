import Foundation
import WantasticCore

public enum MacLocalAccessRouteCoordinatorError: Error, Equatable {
    case alreadyActive
    case notActive
    case activationFailed(String)
    case withdrawalFailed(String)
}

/// Couples the authenticated route advertisement to the local forwarding
/// lifecycle. A subnet is never published before its firewall plan activates;
/// on shutdown it is withdrawn before forwarding rules are removed.
public actor MacLocalAccessRouteCoordinator {
    private let firewall: MacLocalAccessFirewallController
    private let sender: any TunnelControlPayloadSender
    private var activeRoutes: [String]?

    public var isActive: Bool { activeRoutes != nil }

    public init(firewall: MacLocalAccessFirewallController,
                sender: any TunnelControlPayloadSender) {
        self.firewall = firewall
        self.sender = sender
    }

    public func activate(_ plan: MacLocalAccessFirewallPlan) async throws {
        guard activeRoutes == nil else {
            throw MacLocalAccessRouteCoordinatorError.alreadyActive
        }
        let routes = plan.routes.map { $0.prefix.description }
        let advertisement = try TunnelControlCodec.encodeLocalAccessAdvertisement(routes)
        do {
            try await firewall.activate(plan)
            try await sender.sendTUNControlPayload(advertisement)
            activeRoutes = routes
        } catch {
            let activationError = error.localizedDescription
            var rollbackErrors: [String] = []
            // A transport error can occur after the remote side received the
            // advertisement, so revoke it before dropping local forwarding.
            // If withdrawal is uncertain, preserve forwarding and retain the
            // routes so the owner can retry cleanup; otherwise a remote route
            // could still point at a destination this host no longer serves.
            let withdrawalConfirmed: Bool
            do {
                try await sender.sendTUNControlPayload(
                    TunnelControlCodec.encodeLocalAccessAdvertisement([]))
                withdrawalConfirmed = true
            } catch {
                withdrawalConfirmed = false
                rollbackErrors.append("route withdrawal could not be confirmed")
            }
            guard withdrawalConfirmed else {
                activeRoutes = routes
                let suffix = "; " + rollbackErrors.joined(separator: "; ")
                throw MacLocalAccessRouteCoordinatorError.activationFailed(activationError + suffix)
            }
            do { try await firewall.deactivate() }
            catch {
                activeRoutes = routes
                rollbackErrors.append("firewall rollback failed: \(error.localizedDescription)")
            }
            let suffix = rollbackErrors.isEmpty ? "" : "; " + rollbackErrors.joined(separator: "; ")
            throw MacLocalAccessRouteCoordinatorError.activationFailed(activationError + suffix)
        }
    }

    public func deactivate() async throws {
        guard activeRoutes != nil else { throw MacLocalAccessRouteCoordinatorError.notActive }
        let withdrawal = try TunnelControlCodec.encodeLocalAccessAdvertisement([])
        do { try await sender.sendTUNControlPayload(withdrawal) }
        catch {
            // Keep forwarding installed while a remote route may still point
            // at this device; removing it would turn a stale route into a drop.
            throw MacLocalAccessRouteCoordinatorError.withdrawalFailed(error.localizedDescription)
        }
        do { try await firewall.deactivate() }
        catch {
            throw MacLocalAccessRouteCoordinatorError.withdrawalFailed(
                "route withdrawn but firewall cleanup failed: \(error.localizedDescription)")
        }
        activeRoutes = nil
    }
}
