import Foundation

public typealias MacWUSPOperationHandler = @Sendable (
    _ commandPath: String, _ input: WUSPMessage?, _ metadata: [String: String]
) throws -> WUSPMessage?
public typealias MacWUSPAsyncOperationHandler = @Sendable (
    _ commandPath: String, _ input: WUSPMessage?, _ metadata: [String: String]
) async throws -> WUSPMessage?

public enum MacWUSPOperationError: Error, Equatable {
    case unsupported
}

/// Native macOS WUSP request handler exposed to the controller over the
/// authenticated WireGuard control channel. Only collected parameters and the
/// explicitly writable FriendlyName and ProvisioningCode settings are accepted.
public struct MacWUSPAgentDispatcher: Sendable {
    private static let operationCommandPathKey = "wusp.operation_command_path"
    private static let friendlyNamePath = "Device.DeviceInfo.FriendlyName"
    private static let provisioningCodePath = "Device.DeviceInfo.ProvisioningCode"
    private static let maximumFriendlyNameBytes = 64
    private static let selectorPaths: [UInt64: String] = [
        5_326_957_525_806_991_164: "Device.RootDataModelVersion",
        13_350_179_363_487_105_404: "Device.DeviceInfo.Manufacturer",
        10_267_099_029_593_665_213: "Device.DeviceInfo.ModelName",
        6_912_254_594_259_689_904: "Device.DeviceInfo.ProductClass",
        13_527_754_238_055_825_072: "Device.DeviceInfo.SoftwareVersion",
        17_617_958_749_237_003_661: "Device.DeviceInfo.UpTime",
        5_441_735_910_175_514_088: "Device.DeviceInfo.MemoryStatus.Total",
        13_753_903_917_177_893_348: "Device.DeviceInfo.MemoryStatus.Free",
        16_573_842_583_776_841_923: "Device.DeviceInfo.NetworkProperties.TCPImplementation",
        8_582_781_017_805_368_456: "Device.DeviceInfo.HostName",
        2_286_188_729_812_078_817: "Device.DeviceInfo.FriendlyName",
        8_620_908_333_006_359_769: "Device.DeviceInfo.ProvisioningCode",
        8_240_030_075_286_677_841: "Device.IP.InterfaceNumberOfEntries",
        7_278_240_583_950_947_699: "Device.IP.Interface.{i}.Name",
        5_384_303_982_053_908_687: "Device.IP.Interface.{i}.Enable",
        11_794_585_636_747_160_018: "Device.IP.Interface.{i}.Status",
        691_476_654_774_448_317: "Device.IP.Interface.{i}.IPv4Address.{i}.IPAddress",
        2_107_622_221_238_863_027: "Device.IP.Interface.{i}.IPv4Address.{i}.SubnetMask",
        5_709_957_747_384_362_739: "Device.IP.Interface.{i}.IPv6Address.{i}.IPAddress",
        6_389_498_419_104_937_915: "Device.Ethernet.InterfaceNumberOfEntries",
        3_112_834_130_646_020_669: "Device.Ethernet.Interface.{i}.Name",
        2_599_662_795_404_241_949: "Device.Ethernet.Interface.{i}.Enable",
        15_436_398_138_094_388_640: "Device.Ethernet.Interface.{i}.Status",
        14_020_725_306_093_811_551: "Device.Ethernet.Interface.{i}.MACAddress",
        12_120_280_007_176_993_584: "Device.IP.Interface.{i}.",
        13_919_312_572_810_635_550: "Device.IP.Interface.{i}.IPv4Address.{i}.",
        10_428_290_883_066_364_612: "Device.IP.Interface.{i}.IPv6Address.{i}.",
        7_101_167_601_985_494_302: "Device.Ethernet.Interface.{i}.",
        7_470_374_252_734_745_033: "Device.Time.CurrentLocalTime",
        18_096_091_504_730_752_484: "Device.Time.LocalTimeZone",
        13_545_392_493_760_057_785: "Device.IP.IPv4Capable",
        16_312_803_732_236_064_188: "Device.IP.IPv4Enable",
        13_501_531_255_845_275_141: "Device.IP.IPv4Status",
        12_197_594_044_343_824_307: "Device.IP.IPv6Capable",
        11_270_614_977_237_238_594: "Device.IP.IPv6Enable",
        14_870_596_540_097_983_643: "Device.IP.IPv6Status",
    ]
    private static let multiInstanceObjects = [
        "Device.IP.Interface.{i}.",
        "Device.IP.Interface.{i}.IPv4Address.{i}.",
        "Device.IP.Interface.{i}.IPv6Address.{i}.",
        "Device.Ethernet.Interface.{i}.",
    ]
    private static let supportedDataModel = WUSPSupportedDataModel(
        rootDataModelVersion: "2.20",
        models: [WUSPBroadbandDataModel(
            id: "device", name: "TR-181 Device (USP Full Import)", modelVersion: "2.20.1",
            firstVersion: "2.0", latestVersion: "2.20",
            source: "BroadbandForum/usp-data-models tr-181-2-20-1-usp-full.xml",
            sourceURL: "https://github.com/BroadbandForum/usp-data-models/blob/master/tr-181-2-20-1-usp-full.xml",
            objectCount: 875, paramCount: 7_075)],
        objects: [
            WUSPSupportedObject(path: "Device.DeviceInfo.", multiInstance: false, sinceVersion: "2.12"),
            WUSPSupportedObject(path: "Device.IP.", multiInstance: false, sinceVersion: "2.12"),
            WUSPSupportedObject(path: "Device.Time.", multiInstance: false, sinceVersion: "2.12"),
            WUSPSupportedObject(path: "Device.Ethernet.Interface.{i}.", multiInstance: true, sinceVersion: "2.12"),
            WUSPSupportedObject(path: "Device.IP.Interface.{i}.", multiInstance: true, sinceVersion: "2.12"),
            WUSPSupportedObject(path: "Device.IP.Interface.{i}.IPv4Address.{i}.", multiInstance: true, sinceVersion: "2.12"),
            WUSPSupportedObject(path: "Device.IP.Interface.{i}.IPv6Address.{i}.", multiInstance: true, sinceVersion: "2.12"),
        ],
        params: [
            WUSPSupportedParam(path: "Device.RootDataModelVersion", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.DeviceInfo.FriendlyName", type: "string", access: "readWrite", sinceVersion: "2.0"),
            WUSPSupportedParam(path: "Device.DeviceInfo.ProvisioningCode", type: "string", access: "readWrite", sinceVersion: "2.0"),
            WUSPSupportedParam(path: "Device.DeviceInfo.HostName", type: "string", access: "readOnly", sinceVersion: "2.16"),
            WUSPSupportedParam(path: "Device.DeviceInfo.Manufacturer", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.DeviceInfo.ModelName", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.DeviceInfo.ProductClass", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.DeviceInfo.SoftwareVersion", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.DeviceInfo.UpTime", type: "unsignedInt", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.DeviceInfo.MemoryStatus.Total", type: "unsignedInt", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.DeviceInfo.MemoryStatus.Free", type: "unsignedInt", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.DeviceInfo.NetworkProperties.TCPImplementation", type: "list", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.IPv4Capable", type: "boolean", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.IPv4Enable", type: "boolean", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.IPv4Status", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.IPv6Capable", type: "boolean", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.IPv6Enable", type: "boolean", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.IPv6Status", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.Time.CurrentLocalTime", type: "dateTime", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.Time.LocalTimeZone", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.Ethernet.InterfaceNumberOfEntries", type: "unsignedInt", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.Ethernet.Interface.{i}.Enable", type: "boolean", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.Ethernet.Interface.{i}.MACAddress", type: "MACAddress", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.Ethernet.Interface.{i}.Name", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.Ethernet.Interface.{i}.Status", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.InterfaceNumberOfEntries", type: "unsignedInt", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.Interface.{i}.Enable", type: "boolean", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.Interface.{i}.Name", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.Interface.{i}.Status", type: "string", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.Interface.{i}.IPv4Address.{i}.IPAddress", type: "IPv4Address", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.Interface.{i}.IPv4Address.{i}.SubnetMask", type: "IPv4Address", access: "readOnly", sinceVersion: "2.12"),
            WUSPSupportedParam(path: "Device.IP.Interface.{i}.IPv6Address.{i}.IPAddress", type: "IPv6Address", access: "readOnly", sinceVersion: "2.12"),
        ])

    private let friendlyNameAccount: String
    private let provisioningCodeAccount: String
    private let consoleHost: String
    private let credentials: any CredentialPersistence
    private let collector: @Sendable () throws -> WUSPMessage
    private let eventSender: (@Sendable (Data) -> Void)?
    private let operationHandler: MacWUSPOperationHandler?
    private let asyncOperationHandler: MacWUSPAsyncOperationHandler?
    private let transferManager: WUSPTransferSessionManager?
    private let replayCache: WUSPControlReplayCache
    private let subscriptions = MacWUSPSubscriptionRegistry()

    public init(consoleHost: String, credentials: any CredentialPersistence = CredentialVault(),
                eventSender: (@Sendable (Data) -> Void)? = nil,
                operationHandler: MacWUSPOperationHandler? = nil,
                asyncOperationHandler: MacWUSPAsyncOperationHandler? = nil,
                transferManager: WUSPTransferSessionManager? = nil,
                collector: @escaping @Sendable () throws -> WUSPMessage = {
                    try MacDeviceCollector.collect()
                }) throws {
        let host = consoleHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !host.isEmpty, !host.contains("/"), !host.contains("@"),
              !host.contains(":"), !host.contains("\\") else {
            throw RegisteredDeviceStoreError.invalidConsoleHost
        }
        self.friendlyNameAccount = "wusp-settings:\(host):friendly-name"
        self.provisioningCodeAccount = "wusp-settings:\(host):provisioning-code"
        self.consoleHost = host
        self.credentials = credentials
        self.eventSender = eventSender
        self.operationHandler = operationHandler
        self.asyncOperationHandler = asyncOperationHandler
        self.transferManager = transferManager
        self.replayCache = WUSPControlReplayCache()
        self.collector = collector
    }

    /// Returns a Go-compatible WUSP response, or nil if the incoming bytes
    /// are not a valid WUSP request envelope.
    public func handle(_ payload: Data) -> Data? {
        guard let request = try? WUSPTransportCodec.decodeRequest(payload) else { return nil }
        let response: WUSPWireResponse
        do {
            response = try process(request)
        } catch AgentRequestError.unsupported {
            response = makeResponse(request, error: "unsupported WUSP method or parameter",
                                    code: "WUSP_UNSUPPORTED")
        } catch AgentRequestError.invalid(let message) {
            response = makeResponse(request, error: message, code: "WUSP_INVALID_REQUEST")
        } catch {
            response = makeResponse(request, error: "macOS data collection or storage failed",
                                    code: "WUSP_AGENT_ERROR")
        }
        return try? WUSPTransportCodec.encode(response)
    }

    /// Asynchronous entry point used by the authenticated tunnel so file
    /// transfers can create and retire stream sessions without blocking the
    /// packet receive loop. Other methods retain the synchronous dispatcher.
    public func handleAsync(_ payload: Data) async -> Data? {
        guard let request = try? WUSPTransportCodec.decodeRequest(payload) else { return nil }
        if request.method != .upload && request.method != .download {
            return await replayCache.execute(request: request) { [self] in
                await handleAsync(request, payload: payload)
            }
        }
        guard let transferManager else { return handle(payload) }
        do {
            let response = try await transferManager.begin(request)
            return try WUSPTransportCodec.encode(response)
        } catch {
            return try? WUSPTransportCodec.encode(WUSPWireResponse(
                id: request.id, method: request.method,
                error: String(describing: error),
                metadata: ["error_code": "WUSP_TRANSFER_FAILED"]))
        }
    }

    private func handleAsync(_ request: WUSPWireRequest, payload: Data) async -> Data? {
        guard request.method == .operate, let asyncOperationHandler else {
            return handle(payload)
        }
        do {
            guard let objectPath = request.objectPath?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !objectPath.isEmpty else {
                throw AgentRequestError.invalid("operate request is missing an object path")
            }
            let commandPath = try Self.operationCommandPath(
                objectPath: objectPath, metadata: request.metadata)
            let input = try request.messageFrame.map { try WUSPMessageCodec.decode($0) }
            let output = try await asyncOperationHandler(commandPath, input, request.metadata)
            if commandPath == "Device.FactoryReset()" {
                try clearConfiguration()
            }
            let outputFrame = try output.map { try WUSPMessageCodec.encode($0) }
            return try WUSPTransportCodec.encode(makeResponse(
                request, messageFrame: outputFrame, objectPath: objectPath))
        } catch AgentRequestError.unsupported, MacWUSPOperationError.unsupported {
            return try? WUSPTransportCodec.encode(makeResponse(
                request, error: "unsupported WUSP operation", code: "WUSP_UNSUPPORTED"))
        } catch AgentRequestError.invalid(let message) {
            return try? WUSPTransportCodec.encode(makeResponse(
                request, error: message, code: "WUSP_INVALID_REQUEST"))
        } catch {
            return try? WUSPTransportCodec.encode(makeResponse(
                request, error: "macOS operation failed", code: "WUSP_AGENT_ERROR"))
        }
    }

    private func clearConfiguration() throws {
        let accounts = [
            "registered-device:\(consoleHost)",
            "manual-wireguard:\(consoleHost)",
            friendlyNameAccount,
            provisioningCodeAccount,
        ]
        var firstError: Error?
        for account in accounts {
            do { try credentials.delete(account: account) }
            catch { if firstError == nil { firstError = error } }
        }
        if let firstError { throw firstError }
    }

    public func handleTransferFrame(_ payload: Data) async {
        guard let transferManager,
              let frame = try? WUSPTransferStreamCodec.decode(payload) else { return }
        await transferManager.receive(frame)
    }

    private func process(_ request: WUSPWireRequest) throws -> WUSPWireResponse {
        guard request.id > 0 else { throw AgentRequestError.invalid("request id is required") }
        switch request.method {
        case .get:
            let message = try currentMessage()
            let selectors = Self.resolveSelectors(request)
            let selected = message.fields.filter { field in
                request.paths.contains(where: { Self.matches(field.path, selector: $0) }) ||
                    selectors.contains(where: { Self.matches(field.path, selector: $0) }) ||
                    (request.paths.isEmpty && request.pathCodes.isEmpty &&
                     request.objectCode == WUSPAgentEventCodec.deviceRootObjectCode)
            }
            guard !selected.isEmpty else {
                let path = request.paths.first ?? selectors.first ?? "Device."
                throw AgentRequestError.invalid("path not found: \(path)")
            }
            let frame = try WUSPMessageCodec.encode(WUSPMessage(
                deviceID: message.deviceID,
                timestampNanoseconds: message.timestampNanoseconds,
                fields: selected
            ))
            return makeResponse(request, messageFrame: frame)
        case .set:
            let fields = try applySet(request)
            emitValueChanges(fields)
            return makeResponse(request)
        case .delete:
            try applyDelete(request)
            return makeResponse(request)
        case .getInstances:
            let message = try currentMessage()
            let requestedPaths = request.paths + Self.resolveSelectors(request)
            let objectPatterns = requestedPaths.isEmpty
                ? Self.multiInstanceObjects
                : requestedPaths.compactMap(Self.canonicalObjectPattern)
            guard !objectPatterns.isEmpty else {
                throw AgentRequestError.invalid("get-instances requires a supported object path")
            }
            var instances = Set<String>()
            for objectPattern in objectPatterns {
                for field in message.fields {
                    if let instance = Self.instanceObjectPath(fieldPath: field.path,
                                                              objectPattern: objectPattern) {
                        instances.insert(instance)
                    }
                }
            }
            guard !instances.isEmpty else {
                throw AgentRequestError.invalid("path not found: \(requestedPaths.first ?? "Device.")")
            }
            return makeResponse(request, paths: instances.sorted())
        case .operate:
            guard let objectPath = request.objectPath?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !objectPath.isEmpty else {
                throw AgentRequestError.invalid("operate request is missing an object path")
            }
            let commandPath = try Self.operationCommandPath(
                objectPath: objectPath, metadata: request.metadata)
            guard let operationHandler else { throw AgentRequestError.unsupported }
            let input = try request.messageFrame.map { try WUSPMessageCodec.decode($0) }
            let output = try operationHandler(commandPath, input, request.metadata)
            let outputFrame = try output.map { try WUSPMessageCodec.encode($0) }
            return makeResponse(request, messageFrame: outputFrame, objectPath: objectPath)
        case .getSupportedProtocol:
            var methods = ["Get", "Set", "Delete", "GetInstances"]
            if eventSender != nil { methods.append("Notify") }
            if operationHandler != nil || asyncOperationHandler != nil { methods.append("Operate") }
            if transferManager != nil { methods += ["Upload", "Download"] }
            methods += ["GetSupportedDM", "GetSupportedProtocol"]
            return makeResponse(request, protocolInfo: WUSPProtocolInfo(
                name: "wantastic-wusp-over-wireguard", version: 1,
                methods: methods,
                compression: ["nested-message-lz4"],
                controlTransport: "wireguard-noise-fragmented-datagram+request-replay-v1",
                transferTransport: transferManager == nil ? "" : "wireguard-noise-type-8-stream",
                maxControlPayload: 1_200,
                recommendedChunkSize: 1_120, tunnelOnly: true,
                reliableTransfer: transferManager != nil))
        case .notify:
            guard eventSender != nil else { throw AgentRequestError.unsupported }
            let result = subscriptions.update(
                action: request.metadata["wusp_action"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "",
                metadata: request.metadata)
            if let error = result.error {
                throw AgentRequestError.invalid(error)
            }
            return makeResponse(request, additionalMetadata: [
                "wusp_sub_id": result.id,
                "wusp_sub_status": "ok",
            ])
        case .getSupportedDM:
            let requestedPaths = request.paths + Self.resolveSelectors(request)
            let objects = Self.supportedDataModel.objects.filter { object in
                requestedPaths.isEmpty || requestedPaths.contains(where: {
                    Self.supportedDMMatches(candidate: object.path, selector: $0)
                })
            }
            let params = Self.supportedDataModel.params.filter { param in
                requestedPaths.isEmpty || requestedPaths.contains(where: {
                    Self.matches(param.path, selector: $0)
                })
            }
            return makeResponse(request, supportedDataModel: WUSPSupportedDataModel(
                rootDataModelVersion: Self.supportedDataModel.rootDataModelVersion,
                models: Self.supportedDataModel.models, objects: objects, params: params))
        default:
            throw AgentRequestError.unsupported
        }
    }

    private func currentMessage() throws -> WUSPMessage {
        let snapshot = try collector()
        let defaultName = snapshot.fields.first(where: {
            $0.path == "Device.DeviceInfo.HostName"
        }).flatMap { field -> String? in
            guard case let .string(value) = field.value else { return nil }
            return value
        } ?? "Mac"
        let friendlyName = try credentials.read(account: friendlyNameAccount)
            .flatMap { String(data: $0, encoding: .utf8) }
            .flatMap(Self.validFriendlyName) ?? defaultName
        var fields = snapshot.fields.filter {
            $0.path != Self.friendlyNamePath && $0.path != Self.provisioningCodePath
        }
        fields.append(WUSPMessageField(path: Self.friendlyNamePath, value: .string(friendlyName)))
        if let provisioningCode = try credentials.read(account: provisioningCodeAccount),
           let value = String(data: provisioningCode, encoding: .utf8), !value.isEmpty {
            fields.append(WUSPMessageField(path: Self.provisioningCodePath, value: .string(value)))
        }
        return WUSPMessage(deviceID: snapshot.deviceID,
                           timestampNanoseconds: snapshot.timestampNanoseconds,
                           fields: fields)
    }

    private static func operationCommandPath(objectPath: String,
                                             metadata: [String: String]) throws -> String {
        guard let rawCommandPath = metadata[operationCommandPathKey] else { return objectPath }
        let commandPath = rawCommandPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard commandPath.hasSuffix("()") else {
            throw AgentRequestError.invalid("operate command path must end with '()'")
        }
        let commandName = String(commandPath.dropLast(2))
        guard let separator = commandName.lastIndex(of: "."),
              separator != commandName.startIndex,
              separator < commandName.index(before: commandName.endIndex) else {
            throw AgentRequestError.invalid("operate command path must include an object path")
        }
        let expectedObjectPath = String(commandName[...separator])
        guard expectedObjectPath == objectPath else {
            throw AgentRequestError.invalid("operate command path does not belong to request object path")
        }
        return commandPath
    }

    private func applySet(_ request: WUSPWireRequest) throws -> [WUSPMessageField] {
        guard let frame = request.messageFrame else {
            throw AgentRequestError.invalid("set request is missing parameter values")
        }
        let message = try WUSPMessageCodec.decode(frame)
        guard !message.fields.isEmpty else {
            throw AgentRequestError.invalid("set request is missing parameter values")
        }
        // Validate the whole batch before persisting any field, so malformed
        // or unsupported values cannot cause a partial update.
        var writes: [(account: String, value: Data)] = []
        var deletes: [String] = []
        for field in message.fields {
            guard case let .string(value) = field.value else {
                throw AgentRequestError.invalid("device information values must be strings")
            }
            switch field.path {
            case Self.friendlyNamePath:
                if value.isEmpty {
                    deletes.append(friendlyNameAccount)
                } else {
                    guard let name = Self.validFriendlyName(value) else {
                        throw AgentRequestError.invalid("friendly name must contain 1 to 64 printable characters")
                    }
                    writes.append((friendlyNameAccount, Data(name.utf8)))
                }
            case Self.provisioningCodePath:
                guard Self.validProvisioningCode(value) else {
                    throw AgentRequestError.invalid("provisioning code must contain at most 64 printable characters")
                }
                if value.isEmpty {
                    deletes.append(provisioningCodeAccount)
                } else {
                    writes.append((provisioningCodeAccount, Data(value.utf8)))
                }
            default:
                throw AgentRequestError.unsupported
            }
        }
        for write in writes {
            try credentials.write(write.value, account: write.account)
        }
        for account in deletes {
            try credentials.delete(account: account)
        }
        return message.fields
    }

    private func emitValueChanges(_ fields: [WUSPMessageField]) {
        guard let eventSender else { return }
        for field in fields {
            guard case let .string(value) = field.value else { continue }
            for delivery in subscriptions.deliveries(eventType: 2, path: field.path) {
                guard let payload = try? WUSPAgentEventCodec.encodeValueChange(
                    id: delivery.requestID, subscriptionID: delivery.subscriptionID,
                    parameterPath: field.path, value: value) else { continue }
                eventSender(payload)
            }
        }
    }

    private func applyDelete(_ request: WUSPWireRequest) throws {
        let paths = request.paths + Self.resolveSelectors(request)
        guard !paths.isEmpty else {
            throw AgentRequestError.invalid("delete request is missing paths")
        }
        for path in paths {
            switch path {
            case Self.friendlyNamePath:
                try credentials.delete(account: friendlyNameAccount)
            case Self.provisioningCodePath:
                try credentials.delete(account: provisioningCodeAccount)
            default:
                throw AgentRequestError.unsupported
            }
        }
    }

    private static func validProvisioningCode(_ value: String) -> Bool {
        value.utf8.count <= 64 && value.unicodeScalars.allSatisfy {
            !CharacterSet.controlCharacters.contains($0)
        }
    }

    private func makeResponse(_ request: WUSPWireRequest, error: String = "",
                              code: String = "WUSP_OK",
                              messageFrame: Data? = nil,
                              objectPath: String? = nil,
                              paths: [String] = [],
                              protocolInfo: WUSPProtocolInfo? = nil,
                              supportedDataModel: WUSPSupportedDataModel? = nil,
                              additionalMetadata: [String: String] = [:]) -> WUSPWireResponse {
        var metadata = [
            "wusp.result.state": error.isEmpty ? "success" : "error",
            "wusp.result.code": code,
            "wusp.result.message": error,
            "wusp.result.request_id": String(request.id),
            "wusp.result.retryable": "false",
        ]
        if let sequence = UInt64(request.metadata["wusp.request_sequence"] ?? ""), sequence > 0 {
            metadata["wusp.response_sequence"] = String(sequence)
        }
        metadata.merge(additionalMetadata) { _, newest in newest }
        return WUSPWireResponse(id: request.id, method: request.method, error: error,
                                paths: paths, objectPath: objectPath,
                                messageFrame: messageFrame, metadata: metadata,
                                supportedDataModel: supportedDataModel,
                                protocolInfo: protocolInfo)
    }

    private static func matches(_ fieldPath: String, selector: String) -> Bool {
        guard !selector.isEmpty else { return false }
        if selector == fieldPath { return true }
        if selector.hasSuffix(".") { return fieldPath.hasPrefix(selector) }
        let pattern = NSRegularExpression.escapedPattern(for: selector)
            .replacingOccurrences(of: #"\{i\}"#, with: #"[0-9]+"#)
        guard let regex = try? NSRegularExpression(pattern: "^\(pattern)$") else { return false }
        let range = NSRange(fieldPath.startIndex..., in: fieldPath)
        return regex.firstMatch(in: fieldPath, range: range) != nil
    }

    private static func supportedDMMatches(candidate: String, selector: String) -> Bool {
        matches(candidate, selector: selector) || matches(selector, selector: candidate) ||
            instanceObjectPath(fieldPath: selector, objectPattern: candidate) != nil
    }

    private static func resolveSelectors(_ request: WUSPWireRequest) -> [String] {
        request.pathCodes.enumerated().compactMap { index, code in
            guard var path = selectorPaths[code] else { return nil }
            let instances = request.pathInstances.indices.contains(index)
                ? request.pathInstances[index] : []
            for instance in instances where instance > 0 {
                guard let range = path.range(of: "{i}") else { break }
                path.replaceSubrange(range, with: String(instance))
            }
            return path
        }
    }

    private static func canonicalObjectPattern(_ path: String) -> String? {
        let normalized = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return nil }
        let object = normalized.hasSuffix(".") ? normalized : normalized + "."
        return multiInstanceObjects.first { pattern in
            if object == pattern || object == pattern.replacingOccurrences(of: ".{i}", with: "") {
                return true
            }
            guard let regex = try? NSRegularExpression(
                pattern: "^" + NSRegularExpression.escapedPattern(for: pattern)
                    .replacingOccurrences(of: #"\{i\}"#, with: #"[0-9]+"#) + "$"
            ) else { return false }
            return regex.firstMatch(in: object, range: NSRange(object.startIndex..., in: object)) != nil
        }
    }

    private static func instanceObjectPath(fieldPath: String,
                                           objectPattern: String) -> String? {
        let objectSegments = objectPattern.split(separator: ".").map(String.init)
        let fieldSegments = fieldPath.split(separator: ".").map(String.init)
        guard fieldSegments.count > objectSegments.count else { return nil }
        var concrete: [String] = []
        for (patternSegment, fieldSegment) in zip(objectSegments, fieldSegments) {
            if patternSegment == "{i}" {
                guard UInt64(fieldSegment) != nil else { return nil }
                concrete.append(fieldSegment)
            } else {
                guard patternSegment == fieldSegment else { return nil }
                concrete.append(fieldSegment)
            }
        }
        return concrete.joined(separator: ".") + "."
    }

    private static func validFriendlyName(_ value: String) -> String? {
        let name = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.utf8.count <= maximumFriendlyNameBytes,
              name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return nil
        }
        return name
    }

    private enum AgentRequestError: Error {
        case unsupported
        case invalid(String)
    }
}
