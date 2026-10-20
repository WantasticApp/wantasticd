import Foundation

public enum WUSPRequestTransportError: Error, Equatable {
    case wrongDevice
    case duplicateRequestID
    case timedOut
    case channelClosed
    case malformedResponse
}

/// Authenticated type-8 payload path exposed by the native WireGuard peer.
public protocol WUSPControlChannel: Sendable {
    var wuspControlPayloads: AsyncStream<Data> { get }
    func sendWUSPControlPayload(_ payload: Data) async throws
}

/// Authenticated raw type-8 stream frames used by Go's reliable file-transfer
/// sessions. Unlike control requests, transfer frames are not fragment-wrapped.
/// Peer transports bound this stream and may drop its oldest buffered item if
/// its consumer falls behind; reliable sessions recover through sequence ACKs.
public protocol WUSPTransferStreamChannel: Sendable {
    var wuspTransferStreamPayloads: AsyncStream<Data> { get }
    func sendWUSPTransferStreamFrame(_ frame: WUSPTransferStreamFrame) async throws
}

/// Correlates Go-compatible WUSP requests and responses over one authenticated
/// peer. A separate instance is used per peer so response IDs cannot cross
/// device boundaries.
public actor WUSPRequestTransport: WUSPTransport {
    private struct PendingRequest {
        let method: WUSPMethod
        let continuation: CheckedContinuation<WUSPResponse, Error>
        var timeoutTask: Task<Void, Never>?
    }

    private let channel: any WUSPControlChannel
    private let deviceID: String
    private let timeout: Duration
    private var pending: [UInt64: PendingRequest] = [:]
    private var responseTask: Task<Void, Never>?
    private var closed = false

    public init(channel: any WUSPControlChannel, deviceID: String,
                timeout: Duration = .seconds(20)) {
        self.channel = channel
        self.deviceID = deviceID
        self.timeout = timeout
    }

    public func send(_ request: WUSPRequest, to deviceID: String) async throws -> WUSPResponse {
        guard !closed else { throw WUSPRequestTransportError.channelClosed }
        guard deviceID == self.deviceID else { throw WUSPRequestTransportError.wrongDevice }
        guard pending[request.id] == nil else { throw WUSPRequestTransportError.duplicateRequestID }
        startResponsePumpIfNeeded()

        let messageFrame: Data?
        if request.values.isEmpty {
            messageFrame = nil
        } else {
            let fields = request.values.keys.sorted().map { path in
                WUSPMessageField(path: path, value: .string(request.values[path] ?? ""))
            }
            messageFrame = try WUSPMessageCodec.encode(WUSPMessage(fields: fields))
        }
        let wireRequest = WUSPWireRequest(id: request.id, method: request.method,
                                          paths: request.paths, messageFrame: messageFrame)
        let encoded = try WUSPTransportCodec.encode(wireRequest)

        return try await withCheckedThrowingContinuation { continuation in
            var item = PendingRequest(method: request.method, continuation: continuation)
            item.timeoutTask = Task { [weak self, timeout] in
                do { try await Task.sleep(for: timeout) }
                catch { return }
                await self?.expire(request.id)
            }
            pending[request.id] = item
            Task { [weak self, channel] in
                do {
                    try await channel.sendWUSPControlPayload(encoded)
                } catch {
                    await self?.fail(request.id, error: error)
                }
            }
        }
    }

    public func close() {
        guard !closed else { return }
        closed = true
        responseTask?.cancel()
        responseTask = nil
        let outstanding = Array(pending.values)
        pending.removeAll()
        for item in outstanding {
            item.timeoutTask?.cancel()
            item.continuation.resume(throwing: WUSPRequestTransportError.channelClosed)
        }
    }

    private func startResponsePumpIfNeeded() {
        guard responseTask == nil else { return }
        let payloads = channel.wuspControlPayloads
        responseTask = Task { [weak self] in
            for await payload in payloads {
                guard !Task.isCancelled else { return }
                await self?.receive(payload)
            }
            await self?.close()
        }
    }

    private func receive(_ payload: Data) {
        guard !closed, let response = try? WUSPTransportCodec.decodeResponse(payload),
              let item = pending.removeValue(forKey: response.id) else { return }
        item.timeoutTask?.cancel()
        guard response.method == item.method else {
            item.continuation.resume(throwing: WUSPRequestTransportError.malformedResponse)
            return
        }
        let values: [String: String]
        if let frame = response.messageFrame,
           let message = try? WUSPMessageCodec.decode(frame) {
            values = Dictionary(message.fields.map { ($0.path, Self.stringValue($0.value)) },
                                uniquingKeysWith: { _, newest in newest })
        } else {
            values = [:]
        }
        item.continuation.resume(returning: WUSPResponse(
            id: response.id, values: values,
            error: response.error.isEmpty ? nil : response.error
        ))
    }

    private func expire(_ id: UInt64) {
        guard let item = pending.removeValue(forKey: id) else { return }
        item.continuation.resume(throwing: WUSPRequestTransportError.timedOut)
    }

    private func fail(_ id: UInt64, error: Error) {
        guard let item = pending.removeValue(forKey: id) else { return }
        item.timeoutTask?.cancel()
        item.continuation.resume(throwing: error)
    }

    private static func stringValue(_ value: WUSPValue) -> String {
        switch value {
        case .null: ""
        case let .bool(value): value ? "true" : "false"
        case let .unsigned(value): String(value)
        case let .signed(value), let .timeNanoseconds(value): String(value)
        case let .decimal(value): String(value)
        case let .string(value): value
        case let .bytes(value), let .ipv4(value), let .ipv6(value), let .mac(value):
            value.map { String(format: "%02x", $0) }.joined()
        case let .ipv4Prefix(address, prefix), let .ipv6Prefix(address, prefix):
            address.map { String(format: "%02x", $0) }.joined() + "/\(prefix)"
        case let .list(values): values.map(Self.stringValue).joined(separator: ",")
        }
    }
}
