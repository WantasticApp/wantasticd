import Foundation

/// Deduplicates retryable WUSP mutations for one authenticated peer transport.
/// A repeated request identity receives the exact original response, while
/// reusing that identity with different request data is rejected.
public actor WUSPControlReplayCache {
    private struct Key: Hashable {
        let requestID: UInt64
        let sequence: UInt64
    }

    private struct Entry {
        let fingerprint: Data
        var response: Data?
        var task: Task<Data?, Never>?
        var expiresAt: Date
    }

    private enum Capacity {
        static let maximumEntries = 256
        static let lifetime: TimeInterval = 120
    }

    private var entries: [Key: Entry] = [:]

    public init() {}

    public func execute(request: WUSPWireRequest,
                        operation: @escaping @Sendable () async -> Data?) async -> Data? {
        guard Self.isReplayable(request.method) else { return await operation() }

        var semanticRequest = request
        semanticRequest.metadata.removeValue(forKey: "wusp.response_max_control_payload")
        guard let fingerprint = try? WUSPTransportCodec.encode(semanticRequest) else {
            return await operation()
        }
        let sequence = UInt64(request.metadata["wusp.request_sequence"] ?? "") ?? 0
        let key = Key(requestID: request.id, sequence: sequence)
        let now = Date()
        entries = entries.filter { $0.value.expiresAt > now }

        if let entry = entries[key] {
            guard entry.fingerprint == fingerprint else {
                return Self.errorResponse(for: request,
                                          error: "request identity \(request.id)/\(sequence) was reused with different action data",
                                          code: "WUSP_AGENT_ERROR")
            }
            if let response = entry.response { return response }
            if let task = entry.task { return await task.value }
        }

        if entries.count >= Capacity.maximumEntries {
            if let oldest = entries
                .filter({ $0.value.task == nil })
                .min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key {
                entries.removeValue(forKey: oldest)
            } else {
                return Self.errorResponse(for: request, error: "reliable control queue is full",
                                          code: "WUSP_AGENT_ERROR")
            }
        }

        let task = Task { await operation() }
        entries[key] = Entry(fingerprint: fingerprint, response: nil, task: task,
                             expiresAt: now.addingTimeInterval(Capacity.lifetime))
        let response = await task.value
        if var completed = entries[key], completed.fingerprint == fingerprint {
            completed.response = response
            completed.task = nil
            completed.expiresAt = Date().addingTimeInterval(Capacity.lifetime)
            if response == nil { entries.removeValue(forKey: key) }
            else { entries[key] = completed }
        }
        return response
    }

    private static func isReplayable(_ method: WUSPMethod) -> Bool {
        switch method {
        case .set, .add, .delete, .operate, .notify: true
        default: false
        }
    }

    private static func errorResponse(for request: WUSPWireRequest, error: String,
                                      code: String) -> Data? {
        var metadata: [String: String] = [
            "wusp.result.state": "error",
            "wusp.result.code": code,
            "wusp.result.message": error,
            "wusp.result.request_id": String(request.id),
            "wusp.result.retryable": "false",
        ]
        if let sequence = UInt64(request.metadata["wusp.request_sequence"] ?? ""), sequence > 0 {
            metadata["wusp.response_sequence"] = String(sequence)
        }
        return try? WUSPTransportCodec.encode(WUSPWireResponse(
            id: request.id, method: request.method, error: error, metadata: metadata))
    }
}
