import Foundation

public enum TunnelProviderRPCError: Error, Equatable {
    case tooLarge
    case malformed
    case unsupportedVersion
}

public enum TunnelProviderRPCOperation: Codable, Equatable, Sendable {
    case wusp(WUSPRequest)
    case p2pSnapshot
    case p2pPunch(peerID: UInt32)
    case exitNodeSelection(peerID: UInt32?)
    case localAccessEnable(routes: [String])
    case localAccessDisable
    case localAccessStatus
}

public protocol TunnelProviderLocalAccessManaging: Sendable {
    func enable(routes: [String]) async throws
    func disable() async throws
    func isEnabled() async -> Bool
}

public protocol TunnelControlPayloadSender: Sendable {
    func sendTUNControlPayload(_ payload: Data) async throws
}

public struct TunnelProviderRPCRequest: Codable, Equatable, Sendable {
    public let version: UInt8
    public let operation: TunnelProviderRPCOperation

    public init(request: WUSPRequest, version: UInt8 = 1) {
        self.version = version
        operation = .wusp(request)
    }

    public init(operation: TunnelProviderRPCOperation, version: UInt8 = 1) {
        self.version = version
        self.operation = operation
    }
}

public struct TunnelProviderRPCResponse: Codable, Equatable, Sendable {
    public let version: UInt8
    public let response: WUSPResponse?
    public let p2pPeers: [P2PPeerRecord]?
    public let accepted: Bool?
    public let errorCode: String?

    public init(response: WUSPResponse? = nil, p2pPeers: [P2PPeerRecord]? = nil,
                accepted: Bool? = nil, errorCode: String? = nil, version: UInt8 = 1) {
        self.version = version
        self.response = response
        self.p2pPeers = p2pPeers
        self.accepted = accepted
        self.errorCode = errorCode
    }
}

/// Small bounded JSON envelope for the app-extension message channel. WUSP
/// payload framing remains binary and Go-compatible inside WireGuard; this
/// outer envelope is private to the local app/provider boundary.
public enum TunnelProviderRPCCodec {
    public static let maximumMessageBytes = 1_048_576

    public static func encode(_ request: TunnelProviderRPCRequest) throws -> Data {
        guard request.version == 1, valid(request.operation) else {
            throw TunnelProviderRPCError.malformed
        }
        return try boundedEncode(request)
    }

    public static func decodeRequest(_ data: Data) throws -> TunnelProviderRPCRequest {
        let request: TunnelProviderRPCRequest = try boundedDecode(data)
        guard request.version == 1 else { throw TunnelProviderRPCError.unsupportedVersion }
        guard valid(request.operation) else { throw TunnelProviderRPCError.malformed }
        return request
    }

    public static func encode(_ response: TunnelProviderRPCResponse) throws -> Data {
        guard response.version == 1,
              [response.response != nil, response.p2pPeers != nil,
               response.accepted != nil, response.errorCode != nil].filter({ $0 }).count == 1 else {
            throw TunnelProviderRPCError.malformed
        }
        return try boundedEncode(response)
    }

    public static func decodeResponse(_ data: Data) throws -> TunnelProviderRPCResponse {
        let response: TunnelProviderRPCResponse = try boundedDecode(data)
        guard response.version == 1 else { throw TunnelProviderRPCError.unsupportedVersion }
        guard [response.response != nil, response.p2pPeers != nil,
               response.accepted != nil, response.errorCode != nil].filter({ $0 }).count == 1 else {
            throw TunnelProviderRPCError.malformed
        }
        return response
    }

    private static func boundedEncode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
        guard data.count <= maximumMessageBytes else { throw TunnelProviderRPCError.tooLarge }
        return data
    }

    private static func boundedDecode<T: Decodable>(_ data: Data) throws -> T {
        guard !data.isEmpty else { throw TunnelProviderRPCError.malformed }
        guard data.count <= maximumMessageBytes else { throw TunnelProviderRPCError.tooLarge }
        do { return try JSONDecoder().decode(T.self, from: data) }
        catch { throw TunnelProviderRPCError.malformed }
    }

    private static func valid(_ operation: TunnelProviderRPCOperation) -> Bool {
        if case let .wusp(request) = operation { return request.id > 0 }
        if case let .p2pPunch(peerID) = operation { return peerID > 0 }
        if case let .exitNodeSelection(peerID) = operation, let peerID { return peerID > 0 }
        if case let .localAccessEnable(routes) = operation {
            return !routes.isEmpty && routes.count <= TunnelControlCodec.maxRoutesPerOwner &&
                (try? TunnelControlCodec.encodeLocalAccessAdvertisement(routes)) != nil
        }
        return true
    }
}

/// Testable dispatch layer shared by the packet provider and its app-message
/// boundary. Provider failures are intentionally reduced to stable codes.
public struct TunnelProviderRPCDispatcher: Sendable {
    private let transport: any WUSPTransport
    private let deviceID: String
    private let p2pCoordinator: P2PCoordinator?
    private let tunnelControlSender: (any TunnelControlPayloadSender)?
    private let localAccessManager: (any TunnelProviderLocalAccessManaging)?

    public init(transport: any WUSPTransport, deviceID: String,
                p2pCoordinator: P2PCoordinator? = nil,
                tunnelControlSender: (any TunnelControlPayloadSender)? = nil,
                localAccessManager: (any TunnelProviderLocalAccessManaging)? = nil) {
        self.transport = transport
        self.deviceID = deviceID
        self.p2pCoordinator = p2pCoordinator
        self.tunnelControlSender = tunnelControlSender
        self.localAccessManager = localAccessManager
    }

    public func dispatch(_ data: Data) async -> Data? {
        guard let request = try? TunnelProviderRPCCodec.decodeRequest(data) else {
            return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(errorCode: "invalid_request"))
        }
        do {
            switch request.operation {
            case let .wusp(wuspRequest):
                let response = try await transport.send(wuspRequest, to: deviceID)
                return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(response: response))
            case .p2pSnapshot:
                guard let p2pCoordinator else { throw TunnelProviderRPCDispatchFailure.unavailable }
                let snapshot = await p2pCoordinator.snapshot
                let peers = snapshot.peers.map {
                    $0.withNetworkStatus(
                        udpReachable: snapshot.authenticatedReachablePeerIDs.contains($0.id),
                        direct: snapshot.directPeerIDs.contains($0.id))
                }
                return try? TunnelProviderRPCCodec.encode(
                    TunnelProviderRPCResponse(p2pPeers: peers))
            case let .p2pPunch(peerID):
                guard let p2pCoordinator else { throw TunnelProviderRPCDispatchFailure.unavailable }
                try await p2pCoordinator.requestDirectConnection(to: peerID)
                return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(accepted: true))
            case let .exitNodeSelection(peerID):
                guard let tunnelControlSender else { throw TunnelProviderRPCDispatchFailure.unavailable }
                var publicKeyHex: String?
                if let peerID {
                    guard let p2pCoordinator else { throw TunnelProviderRPCDispatchFailure.unavailable }
                    let snapshot = await p2pCoordinator.snapshot
                    guard let peer = snapshot.peers.first(where: { $0.id == peerID }),
                          peer.offersExitNode, peer.publicKey.count == 32 else {
                        throw TunnelProviderRPCDispatchFailure.peerDoesNotOfferExitNode
                    }
                    publicKeyHex = peer.publicKey.map { String(format: "%02x", $0) }.joined()
                }
                let payload = try TunnelControlCodec.encodeExitNodeSelection(publicKeyHex: publicKeyHex)
                try await tunnelControlSender.sendTUNControlPayload(payload)
                return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(accepted: true))
            case let .localAccessEnable(routes):
                guard let localAccessManager else {
                    throw TunnelProviderRPCDispatchFailure.localAccessUnavailable
                }
                do { try await localAccessManager.enable(routes: routes) }
                catch { throw TunnelProviderRPCDispatchFailure.localAccessOperationFailed }
                return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(accepted: true))
            case .localAccessDisable:
                guard let localAccessManager else {
                    throw TunnelProviderRPCDispatchFailure.localAccessUnavailable
                }
                do { try await localAccessManager.disable() }
                catch { throw TunnelProviderRPCDispatchFailure.localAccessOperationFailed }
                return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(accepted: true))
            case .localAccessStatus:
                guard let localAccessManager else {
                    throw TunnelProviderRPCDispatchFailure.localAccessUnavailable
                }
                return try? TunnelProviderRPCCodec.encode(
                    TunnelProviderRPCResponse(accepted: await localAccessManager.isEnabled()))
            }
        } catch P2PCoordinatorError.peerUnavailable {
            return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(errorCode: "peer_unavailable"))
        } catch TunnelProviderRPCDispatchFailure.unavailable {
            return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(errorCode: "p2p_unavailable"))
        } catch TunnelProviderRPCDispatchFailure.peerDoesNotOfferExitNode {
            return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(errorCode: "peer_not_exit_node"))
        } catch TunnelProviderRPCDispatchFailure.localAccessUnavailable {
            return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(errorCode: "local_access_unavailable"))
        } catch TunnelProviderRPCDispatchFailure.localAccessOperationFailed {
            return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(errorCode: "local_access_failed"))
        } catch {
            return try? TunnelProviderRPCCodec.encode(TunnelProviderRPCResponse(errorCode: "request_failed"))
        }
    }
}

private enum TunnelProviderRPCDispatchFailure: Error {
    case unavailable
    case peerDoesNotOfferExitNode
    case localAccessUnavailable
    case localAccessOperationFailed
}
