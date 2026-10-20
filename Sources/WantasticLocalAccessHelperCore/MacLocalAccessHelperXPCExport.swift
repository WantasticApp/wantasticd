import Foundation
import WantasticCore

public final class MacLocalAccessHelperXPCExport: NSObject, MacLocalAccessHelperXPCProtocol {
    private let operations: MacLocalAccessPrivilegedOperations

    public init(operations: MacLocalAccessPrivilegedOperations = MacLocalAccessPrivilegedOperations()) {
        self.operations = operations
    }

    public func recoverOwnedStateBeforeServing() throws {
        try operations.recoverOwnedState()
    }

    public func readIPv4Forwarding(_ reply: @escaping (NSNumber?, NSError?) -> Void) {
        do { reply(NSNumber(value: try operations.ipv4ForwardingEnabled()), nil) }
        catch { reply(nil, Self.asNSError(error)) }
    }

    public func writeIPv4Forwarding(_ enabled: Bool, reply: @escaping (NSError?) -> Void) {
        do { try operations.setIPv4Forwarding(enabled); reply(nil) }
        catch { reply(Self.asNSError(error)) }
    }

    public func readPacketFilterEnabled(_ reply: @escaping (NSNumber?, NSError?) -> Void) {
        do { reply(NSNumber(value: try operations.packetFilterEnabled()), nil) }
        catch { reply(nil, Self.asNSError(error)) }
    }

    public func enablePacketFilter(_ reply: @escaping (NSString?, NSError?) -> Void) {
        do { reply(try operations.enablePacketFilter() as NSString, nil) }
        catch { reply(nil, Self.asNSError(error)) }
    }

    public func applyFirewallPlan(_ request: NSData, reply: @escaping (NSError?) -> Void) {
        do { try operations.applyFirewallPlan(request as Data); reply(nil) }
        catch { reply(Self.asNSError(error)) }
    }

    public func flushWantasticAnchor(_ reply: @escaping (NSError?) -> Void) {
        do { try operations.flushWantasticAnchor(); reply(nil) }
        catch { reply(Self.asNSError(error)) }
    }

    public func releasePacketFilterToken(_ token: NSString, reply: @escaping (NSError?) -> Void) {
        do { try operations.releasePacketFilterToken(token as String); reply(nil) }
        catch { reply(Self.asNSError(error)) }
    }

    public func restoreWantasticOwnedState(_ reply: @escaping (NSError?) -> Void) {
        do { try operations.recoverOwnedState(); reply(nil) }
        catch { reply(Self.asNSError(error)) }
    }

    public func scheduleSystemReboot(_ reply: @escaping (NSError?) -> Void) {
        operations.scheduleSystemReboot()
        reply(nil)
    }

    private static func asNSError(_ error: Error) -> NSError {
        NSError(domain: "app.wantastic.local-access-helper", code: 3,
                userInfo: [NSLocalizedDescriptionKey: error.localizedDescription])
    }
}
