import Foundation

struct MacWUSPEventDelivery: Sendable {
    let requestID: UInt64
    let subscriptionID: String?
}

/// Thread-safe in-memory subscriptions for the native WUSP agent. Subscription
/// state is session-scoped, matching the Go agent's behavior after reconnect.
final class MacWUSPSubscriptionRegistry: @unchecked Sendable {
    private static let maximumIDBytes = 128
    private static let maximumFilters = 128
    private static let maximumFilterBytes = 512

    private struct Entry: Sendable {
        let id: String
        let eventTypes: Set<Int>
        let pathPrefixes: [String]
        let eventNames: [String]
    }

    private let lock = NSLock()
    private var entries: [String: Entry] = [:]
    private var nextRequestID: UInt64 = 0

    func update(action: String, metadata: [String: String]) -> (id: String, error: String?) {
        let id = metadata["wusp_sub_id"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !id.isEmpty else { return (id, "subscription id required") }
        guard id.utf8.count <= Self.maximumIDBytes else {
            return (id, "subscription id exceeds limit")
        }

        lock.lock()
        defer { lock.unlock() }
        switch action {
        case "subscribe":
            let pathPrefixes = csv(metadata["wusp_sub_paths"])
            let eventNames = csv(metadata["wusp_sub_events"])
            guard pathPrefixes.count <= Self.maximumFilters,
                  eventNames.count <= Self.maximumFilters,
                  (pathPrefixes + eventNames).allSatisfy({ $0.utf8.count <= Self.maximumFilterBytes }) else {
                return (id, "subscription filters exceed limits")
            }
            entries[id] = Entry(
                id: id,
                eventTypes: Set(csv(metadata["wusp_sub_types"]).compactMap { value in
                    guard let type = Int(value), (1...6).contains(type) else { return nil }
                    return type
                }),
                pathPrefixes: pathPrefixes,
                eventNames: eventNames)
            return (id, nil)
        case "unsubscribe":
            entries.removeValue(forKey: id)
            return (id, nil)
        default:
            return (id, "unknown wusp subscription action")
        }
    }

    /// Matches Go's subscription filters and sends an untagged notification
    /// when there are no matches so the controller can still update its cache.
    func deliveries(eventType: Int, path: String, eventName: String = "") -> [MacWUSPEventDelivery] {
        lock.lock()
        defer { lock.unlock() }
        let matching = entries.values.filter { entry in
            (entry.eventTypes.isEmpty || entry.eventTypes.contains(eventType)) &&
                (entry.pathPrefixes.isEmpty || entry.pathPrefixes.contains(where: path.hasPrefix)) &&
                (eventType != 1 || entry.eventNames.isEmpty || entry.eventNames.contains(eventName))
        }.sorted { $0.id < $1.id }
        let subscriptionIDs: [String?] = matching.isEmpty ? [nil] : matching.map { Optional($0.id) }
        return subscriptionIDs.map { id in
            nextRequestID = nextRequestID == UInt64.max ? 1 : nextRequestID + 1
            return MacWUSPEventDelivery(requestID: nextRequestID, subscriptionID: id)
        }
    }

    private func csv(_ value: String?) -> [String] {
        (value ?? "").split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty }
    }
}
