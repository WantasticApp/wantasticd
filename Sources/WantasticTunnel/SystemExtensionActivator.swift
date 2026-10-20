import Foundation
@preconcurrency import SystemExtensions
import WantasticCore

public enum SystemExtensionActivationResult: Equatable, Sendable {
    case active
    case requiresRestart

    public static func from(requiresRestart: Bool) -> Self {
        requiresRestart ? .requiresRestart : .active
    }
}

/// Requests activation through macOS's supported system-extension approval
/// flow. The app must be Developer ID signed with Apple's granted entitlements.
@MainActor
public final class SystemExtensionActivator {
    public static let shared = SystemExtensionActivator()

    private var pendingDelegate: ActivationRequestDelegate?

    private init() {}

    public func activate(onApprovalRequired: @escaping @MainActor () -> Void = {}) async throws -> SystemExtensionActivationResult {
        try await withCheckedThrowingContinuation { continuation in
            let delegate = ActivationRequestDelegate(
                onApprovalRequired: { Task { @MainActor in onApprovalRequired() } },
                completion: { [weak self] result in
                    Task { @MainActor in
                        self?.pendingDelegate = nil
                        continuation.resume(with: result)
                    }
                }
            )
            pendingDelegate = delegate
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: TunnelProfilePolicy.providerBundleIdentifier,
                queue: .main
            )
            request.delegate = delegate
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }
}

private final class ActivationRequestDelegate: NSObject, OSSystemExtensionRequestDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private let onApprovalRequired: @Sendable () -> Void
    private let completion: @Sendable (Result<SystemExtensionActivationResult, Error>) -> Void
    private var completed = false

    init(onApprovalRequired: @escaping @Sendable () -> Void,
         completion: @escaping @Sendable (Result<SystemExtensionActivationResult, Error>) -> Void) {
        self.onApprovalRequired = onApprovalRequired
        self.completion = completion
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        onApprovalRequired()
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        guard existing.bundleIdentifier == TunnelProfilePolicy.providerBundleIdentifier,
              ext.bundleIdentifier == TunnelProfilePolicy.providerBundleIdentifier else { return .cancel }
        return .replace
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        finish(.success(.from(requiresRestart: result == .willCompleteAfterReboot)))
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        finish(.failure(error))
    }

    private func finish(_ result: Result<SystemExtensionActivationResult, Error>) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        lock.unlock()
        completion(result)
    }
}
