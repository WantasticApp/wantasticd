import Foundation
import ServiceManagement

/// Registers the privileged helper from the signed app bundle. macOS owns the
/// approval UI and may leave the service in `requiresApproval` until the user
/// enables it in System Settings.
public final class MacLocalAccessHelperRegistration {
    private let service: SMAppService

    public enum State: Equatable, Sendable {
        case notRegistered
        case enabled
        case requiresApproval
        case unavailable
    }

    public init(plistName: String = MacLocalAccessHelperService.launchDaemonPlistName) {
        service = SMAppService.daemon(plistName: plistName)
    }

    public var state: State {
        switch service.status {
        case .notRegistered: .notRegistered
        case .enabled: .enabled
        case .requiresApproval: .requiresApproval
        case .notFound: .unavailable
        @unknown default: .unavailable
        }
    }

    public func register() throws {
        try service.register()
    }

    public func unregister() throws {
        try service.unregister()
    }

    public func openApprovalSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }
}
