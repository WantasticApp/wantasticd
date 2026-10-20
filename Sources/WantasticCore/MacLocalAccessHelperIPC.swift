import Foundation

/// XPC surface exported only by the separately authorized local-access
/// LaunchDaemon. It deliberately accepts a validated-plan payload rather than
/// shell commands or raw PF rules.
@objc public protocol MacLocalAccessHelperXPCProtocol {
    func readIPv4Forwarding(_ reply: @escaping (NSNumber?, NSError?) -> Void)
    func writeIPv4Forwarding(_ enabled: Bool, reply: @escaping (NSError?) -> Void)
    func readPacketFilterEnabled(_ reply: @escaping (NSNumber?, NSError?) -> Void)
    func enablePacketFilter(_ reply: @escaping (NSString?, NSError?) -> Void)
    func applyFirewallPlan(_ request: NSData, reply: @escaping (NSError?) -> Void)
    func flushWantasticAnchor(_ reply: @escaping (NSError?) -> Void)
    func releasePacketFilterToken(_ token: NSString, reply: @escaping (NSError?) -> Void)
    func restoreWantasticOwnedState(_ reply: @escaping (NSError?) -> Void)
    func scheduleSystemReboot(_ reply: @escaping (NSError?) -> Void)
}

public enum MacLocalAccessHelperService {
    public static let machServiceName = "app.wantastic.desktop.local-access-helper"
    public static let launchDaemonPlistName = "app.wantastic.desktop.local-access-helper.plist"
    public static let helperBundleIdentifier = "app.wantastic.desktop.local-access-helper"
    public static let appBundleIdentifier = "app.wantastic.desktop"
    public static let networkExtensionBundleIdentifier = "app.wantastic.desktop.network-extension"
}
