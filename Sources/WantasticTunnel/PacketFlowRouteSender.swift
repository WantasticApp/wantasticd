import Foundation

/// Keeps a failed direct route from taking the otherwise healthy hub path down.
enum PacketFlowRouteSender {
    typealias Send = @Sendable (Data) async throws -> Void

    static func send(_ packet: Data, directly: Send?, relay: @escaping Send,
                     onDirectFailure: @escaping @Sendable () async -> Void) async throws {
        if let directly {
            do {
                try await directly(packet)
                return
            } catch {
                await onDirectFailure()
            }
        }
        try await relay(packet)
    }
}
