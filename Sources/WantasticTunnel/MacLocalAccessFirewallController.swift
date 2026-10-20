import Foundation
import WantasticCore

public protocol MacLocalAccessFirewallSystem: Sendable {
    func ipv4ForwardingEnabled() async throws -> Bool
    func setIPv4Forwarding(_ enabled: Bool) async throws
    func packetFilterEnabled() async throws -> Bool
    func enablePacketFilter() async throws -> String
    func apply(_ plan: MacLocalAccessFirewallPlan) async throws
    func flushOwnedAnchor() async throws
    func releasePacketFilter(token: String) async throws
    func restoreWantasticOwnedState() async throws
}

public enum MacLocalAccessFirewallControllerError: Error, Equatable {
    case activationFailed(String)
    case updateFailed(String)
    case cleanupFailed(String)
}

/// Applies only Wantastic-owned PF anchor rules. Existing PF state and IPv4
/// forwarding are preserved, and a failed activation rolls back before it can
/// be followed by a route advertisement.
public actor MacLocalAccessFirewallController {
    private let system: any MacLocalAccessFirewallSystem
    private var activePlan: MacLocalAccessFirewallPlan?

    public init(system: any MacLocalAccessFirewallSystem) {
        self.system = system
    }

    public func activate(_ plan: MacLocalAccessFirewallPlan) async throws {
        if let activePlan {
            guard activePlan != plan else { return }
            do {
                try await system.apply(plan)
                self.activePlan = plan
            } catch {
                let updateError = error.localizedDescription
                do {
                    try await system.apply(activePlan)
                } catch {
                    throw MacLocalAccessFirewallControllerError.updateFailed(
                        "update failed (\(updateError)) and previous rules could not be restored: \(error.localizedDescription)")
                }
                throw MacLocalAccessFirewallControllerError.updateFailed(updateError)
            }
            return
        }

        let wasForwardingEnabled: Bool
        let wasPacketFilterEnabled: Bool
        do {
            wasForwardingEnabled = try await system.ipv4ForwardingEnabled()
            wasPacketFilterEnabled = try await system.packetFilterEnabled()
        } catch {
            throw MacLocalAccessFirewallControllerError.activationFailed(error.localizedDescription)
        }

        do {
            if !wasPacketFilterEnabled { _ = try await system.enablePacketFilter() }
            try await system.apply(plan)
            if !wasForwardingEnabled {
                try await system.setIPv4Forwarding(true)
            }
        } catch {
            var rollbackErrors: [String] = []
            do { try await system.restoreWantasticOwnedState() }
            catch { rollbackErrors.append("restore Wantastic firewall state: \(error.localizedDescription)") }
            let rollback = rollbackErrors.isEmpty ? "" : "; rollback: " + rollbackErrors.joined(separator: "; ")
            throw MacLocalAccessFirewallControllerError.activationFailed(error.localizedDescription + rollback)
        }

        activePlan = plan
    }

    public func deactivate() async throws {
        guard activePlan != nil else {
            // Removes an orphaned Wantastic anchor without changing global PF
            // or forwarding state owned by another process.
            do { try await system.flushOwnedAnchor() }
            catch { throw MacLocalAccessFirewallControllerError.cleanupFailed(error.localizedDescription) }
            return
        }

        do { try await system.restoreWantasticOwnedState() }
        catch {
            throw MacLocalAccessFirewallControllerError.cleanupFailed(error.localizedDescription)
        }
        activePlan = nil
    }
}
