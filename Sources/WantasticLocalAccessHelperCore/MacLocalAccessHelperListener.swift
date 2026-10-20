import Foundation
import Darwin
import WantasticCore

public final class MacLocalAccessHelperListener: NSObject, NSXPCListenerDelegate {
    private let listener: NSXPCListener
    private let exportedObject: MacLocalAccessHelperXPCExport

    public init(exportedObject: MacLocalAccessHelperXPCExport = MacLocalAccessHelperXPCExport()) {
        self.exportedObject = exportedObject
        listener = NSXPCListener(machServiceName: MacLocalAccessHelperService.machServiceName)
        super.init()
        listener.delegate = self
    }

    public func runForever() -> Never {
        do { try exportedObject.recoverOwnedStateBeforeServing() }
        catch {
            fputs("Wantastic local-access helper recovery failed: \(error.localizedDescription)\n", stderr)
            exit(EXIT_FAILURE)
        }
        do {
            _ = try CodeSignatureRequirement.pinnedPeer(
                identifier: MacLocalAccessHelperService.helperBundleIdentifier)
        } catch {
            fputs("Wantastic local-access helper has no usable code signature\n", stderr)
            exit(EXIT_FAILURE)
        }
        listener.resume()
        dispatchMain()
    }

    public func listener(_ listener: NSXPCListener,
                         shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let requirement = try? CodeSignatureRequirement.pinnedPeer(
            identifiers: [MacLocalAccessHelperService.appBundleIdentifier,
                          MacLocalAccessHelperService.networkExtensionBundleIdentifier]) else { return false }
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: MacLocalAccessHelperXPCProtocol.self)
        connection.exportedObject = exportedObject
        connection.resume()
        return true
    }
}
