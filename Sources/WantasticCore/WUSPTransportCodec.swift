import Foundation

public struct WUSPWireRequest: Equatable, Sendable {
    public var id: UInt64
    public var method: WUSPMethod
    public var paths: [String]
    public var pathCodes: [UInt64]
    public var pathInstances: [[UInt64]]
    public var objectPath: String?
    public var objectCode: UInt64
    public var objectInstances: [UInt64]
    public var messageFrame: Data?
    public var transfer: WUSPTransferRequest?
    public var metadata: [String: String]

    public init(id: UInt64, method: WUSPMethod, paths: [String] = [], objectPath: String? = nil,
                messageFrame: Data? = nil, transfer: WUSPTransferRequest? = nil,
                metadata: [String: String] = [:], pathCodes: [UInt64] = [],
                pathInstances: [[UInt64]] = [], objectCode: UInt64 = 0, objectInstances: [UInt64] = []) {
        self.id = id
        self.method = method
        self.paths = paths
        self.pathCodes = pathCodes
        self.pathInstances = pathInstances
        self.objectPath = objectPath
        self.objectCode = objectCode
        self.objectInstances = objectInstances
        self.messageFrame = messageFrame
        self.transfer = transfer
        self.metadata = metadata
    }
}

public struct WUSPWireResponse: Equatable, Sendable {
    public var id: UInt64
    public var method: WUSPMethod
    public var error: String
    public var paths: [String]
    public var pathCodes: [UInt64]
    public var pathInstances: [[UInt64]]
    public var objectPath: String?
    public var objectCode: UInt64
    public var objectInstances: [UInt64]
    public var supportedDataModel: WUSPSupportedDataModel?
    public var protocolInfo: WUSPProtocolInfo?
    public var messageFrame: Data?
    public var transfer: WUSPTransferResult?
    public var metadata: [String: String]

    public init(id: UInt64, method: WUSPMethod, error: String = "", paths: [String] = [],
                objectPath: String? = nil, messageFrame: Data? = nil,
                transfer: WUSPTransferResult? = nil, metadata: [String: String] = [:],
                pathCodes: [UInt64] = [], pathInstances: [[UInt64]] = [], objectCode: UInt64 = 0,
                objectInstances: [UInt64] = [], supportedDataModel: WUSPSupportedDataModel? = nil,
                protocolInfo: WUSPProtocolInfo? = nil) {
        self.id = id
        self.method = method
        self.error = error
        self.paths = paths
        self.pathCodes = pathCodes
        self.pathInstances = pathInstances
        self.objectPath = objectPath
        self.objectCode = objectCode
        self.objectInstances = objectInstances
        self.supportedDataModel = supportedDataModel
        self.protocolInfo = protocolInfo
        self.messageFrame = messageFrame
        self.transfer = transfer
        self.metadata = metadata
    }
}

public struct WUSPProtocolInfo: Equatable, Sendable {
    public var name: String
    public var version: UInt64
    public var methods: [String]
    public var compression: [String]
    public var controlTransport: String
    public var transferTransport: String
    public var maxControlPayload: UInt64
    public var recommendedChunkSize: UInt64
    public var tunnelOnly: Bool
    public var reliableTransfer: Bool

    public init(name: String, version: UInt64, methods: [String], compression: [String],
                controlTransport: String, transferTransport: String,
                maxControlPayload: UInt64, recommendedChunkSize: UInt64,
                tunnelOnly: Bool, reliableTransfer: Bool) {
        self.name = name
        self.version = version
        self.methods = methods
        self.compression = compression
        self.controlTransport = controlTransport
        self.transferTransport = transferTransport
        self.maxControlPayload = maxControlPayload
        self.recommendedChunkSize = recommendedChunkSize
        self.tunnelOnly = tunnelOnly
        self.reliableTransfer = reliableTransfer
    }
}

public struct WUSPBroadbandDataModel: Equatable, Sendable {
    public var id: String
    public var name: String
    public var modelVersion: String
    public var firstVersion: String
    public var latestVersion: String
    public var source: String
    public var sourceURL: String
    public var objectCount: UInt64
    public var paramCount: UInt64

    public init(id: String, name: String, modelVersion: String, firstVersion: String,
                latestVersion: String, source: String, sourceURL: String,
                objectCount: UInt64, paramCount: UInt64) {
        self.id = id
        self.name = name
        self.modelVersion = modelVersion
        self.firstVersion = firstVersion
        self.latestVersion = latestVersion
        self.source = source
        self.sourceURL = sourceURL
        self.objectCount = objectCount
        self.paramCount = paramCount
    }
}

public struct WUSPSupportedObject: Equatable, Sendable {
    public var path: String
    public var multiInstance: Bool
    public var sinceVersion: String

    public init(path: String, multiInstance: Bool, sinceVersion: String) {
        self.path = path
        self.multiInstance = multiInstance
        self.sinceVersion = sinceVersion
    }
}

public struct WUSPSupportedParam: Equatable, Sendable {
    public var path: String
    public var type: String
    public var access: String
    public var sinceVersion: String

    public init(path: String, type: String, access: String, sinceVersion: String) {
        self.path = path
        self.type = type
        self.access = access
        self.sinceVersion = sinceVersion
    }
}

public struct WUSPSupportedDataModel: Equatable, Sendable {
    public var rootDataModelVersion: String
    public var models: [WUSPBroadbandDataModel]
    public var objects: [WUSPSupportedObject]
    public var params: [WUSPSupportedParam]

    public init(rootDataModelVersion: String, models: [WUSPBroadbandDataModel],
                objects: [WUSPSupportedObject], params: [WUSPSupportedParam]) {
        self.rootDataModelVersion = rootDataModelVersion
        self.models = models
        self.objects = objects
        self.params = params
    }
}

public struct WUSPTransferRequest: Equatable, Sendable {
    public var path: String
    public var uri: String
    public var filename: String
    public var contentType: String
    public var payload: Data
    public var metadata: [String: String]

    public init(path: String, uri: String, filename: String = "", contentType: String = "",
                payload: Data = Data(), metadata: [String: String] = [:]) {
        self.path = path
        self.uri = uri
        self.filename = filename
        self.contentType = contentType
        self.payload = payload
        self.metadata = metadata
    }
}

public struct WUSPTransferResult: Equatable, Sendable {
    public var path: String
    public var uri: String
    public var bytes: UInt64
    public var metadata: [String: String]

    public init(path: String, uri: String, bytes: UInt64, metadata: [String: String] = [:]) {
        self.path = path
        self.uri = uri
        self.bytes = bytes
        self.metadata = metadata
    }
}

public enum WUSPTransportError: Error, Equatable {
    case malformed
    case unsupported
    case tooLarge
}

/// Encoder/decoder for the Go agent's WUSP transport envelope version 1.
/// Message-frame bytes are preserved verbatim so this codec never alters the
/// inner WU binary frame or depends on a locally generated TR-181 registry.
public enum WUSPTransportCodec {
    private static let maxBytes = 1_048_576
    private static let maxItems = 16_384

    public static func encode(_ request: WUSPWireRequest) throws -> Data {
        if let objectPath = request.objectPath, objectPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw WUSPTransportError.malformed
        }
        try validateSelectors(codes: request.pathCodes, objectCode: request.objectCode,
                              objectInstances: request.objectInstances)
        if let message = request.messageFrame { try validateMessageFrame(message) }
        var flags: UInt8 = 0
        if request.messageFrame != nil { flags |= 1 << 0 }
        if request.transfer != nil { flags |= 1 << 1 }
        if request.objectPath != nil { flags |= 1 << 2 }
        if !request.metadata.isEmpty { flags |= 1 << 3 }
        if !request.pathCodes.isEmpty { flags |= 1 << 4 }
        if request.objectCode != 0 { flags |= 1 << 5 }
        var writer = Writer()
        writer.header(kind: 1, method: request.method.wireID, flags: flags, id: request.id)
        try writer.stringList(request.paths)
        if let path = request.objectPath { try writer.string(path) }
        if !request.pathCodes.isEmpty { try writer.pathSelectors(request.pathCodes, instances: request.pathInstances) }
        if request.objectCode != 0 { try writer.pathSelector(request.objectCode, instances: request.objectInstances) }
        if let message = request.messageFrame { try writer.bytes(message) }
        if let transfer = request.transfer {
            try writer.string(transfer.path)
            try writer.string(transfer.uri)
            try writer.string(transfer.filename)
            try writer.string(transfer.contentType)
            try writer.bytes(transfer.payload)
            try writer.metadata(transfer.metadata)
        }
        if !request.metadata.isEmpty { try writer.metadata(request.metadata) }
        return try writer.finish()
    }

    public static func decodeRequest(_ data: Data) throws -> WUSPWireRequest {
        var reader = try Reader(data, expectedKind: 1)
        let paths = try reader.stringList()
        let objectPath = reader.flags & (1 << 2) != 0 ? try reader.string() : nil
        let selectors = reader.flags & (1 << 4) != 0 ? try reader.pathSelectors() : ([], [])
        let objectSelector = reader.flags & (1 << 5) != 0 ? try reader.pathSelector() : (UInt64(0), [])
        try validateSelectors(codes: selectors.0, objectCode: objectSelector.0,
                              objectInstances: objectSelector.1)
        let message = reader.flags & (1 << 0) != 0 ? try reader.bytes() : nil
        if let message { try validateMessageFrame(message) }
        var transfer: WUSPTransferRequest?
        if reader.flags & (1 << 1) != 0 {
            transfer = WUSPTransferRequest(
                path: try reader.string(), uri: try reader.string(), filename: try reader.string(),
                contentType: try reader.string(), payload: try reader.bytes(), metadata: try reader.metadata()
            )
        }
        let metadata = reader.flags & (1 << 3) != 0 ? try reader.metadata() : [:]
        try reader.finish()
        return WUSPWireRequest(id: reader.id, method: reader.method, paths: paths, objectPath: objectPath,
                               messageFrame: message, transfer: transfer, metadata: metadata,
                               pathCodes: selectors.0, pathInstances: selectors.1,
                               objectCode: objectSelector.0, objectInstances: objectSelector.1)
    }

    public static func encode(_ response: WUSPWireResponse) throws -> Data {
        if let objectPath = response.objectPath, objectPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw WUSPTransportError.malformed
        }
        try validateSelectors(codes: response.pathCodes, objectCode: response.objectCode,
                              objectInstances: response.objectInstances)
        if let message = response.messageFrame { try validateMessageFrame(message) }
        var flags: UInt8 = 0
        if response.messageFrame != nil { flags |= 1 << 0 }
        if response.transfer != nil { flags |= 1 << 1 }
        if !response.paths.isEmpty { flags |= 1 << 2 }
        if response.objectPath != nil { flags |= 1 << 3 }
        if !response.metadata.isEmpty { flags |= 1 << 4 }
        if response.supportedDataModel != nil { flags |= 1 << 5 }
        if response.protocolInfo != nil { flags |= 1 << 6 }
        if !response.pathCodes.isEmpty || response.objectCode != 0 || !response.objectInstances.isEmpty {
            flags |= 1 << 7
        }
        var writer = Writer()
        writer.header(kind: 2, method: response.method.wireID, flags: flags, id: response.id)
        try writer.string(response.error)
        if flags & (1 << 2) != 0 { try writer.stringList(response.paths) }
        if let path = response.objectPath { try writer.string(path) }
        if let message = response.messageFrame { try writer.bytes(message) }
        if let transfer = response.transfer {
            try writer.string(transfer.path)
            try writer.string(transfer.uri)
            writer.varint(transfer.bytes)
            try writer.metadata(transfer.metadata)
        }
        if !response.metadata.isEmpty { try writer.metadata(response.metadata) }
        if flags & (1 << 7) != 0 {
            try writer.pathSelectors(response.pathCodes, instances: response.pathInstances)
            try writer.pathSelector(response.objectCode, instances: response.objectInstances)
        }
        if let supportedDataModel = response.supportedDataModel {
            try writer.supportedDataModel(supportedDataModel)
        }
        if let protocolInfo = response.protocolInfo {
            try writer.protocolInfo(protocolInfo)
        }
        return try writer.finish()
    }

    public static func decodeResponse(_ data: Data) throws -> WUSPWireResponse {
        var reader = try Reader(data, expectedKind: 2)
        let error = try reader.string()
        let paths = reader.flags & (1 << 2) != 0 ? try reader.stringList() : []
        let objectPath = reader.flags & (1 << 3) != 0 ? try reader.string() : nil
        let message = reader.flags & (1 << 0) != 0 ? try reader.bytes() : nil
        if let message { try validateMessageFrame(message) }
        var transfer: WUSPTransferResult?
        if reader.flags & (1 << 1) != 0 {
            transfer = WUSPTransferResult(path: try reader.string(), uri: try reader.string(),
                                          bytes: try reader.varint(), metadata: try reader.metadata())
        }
        let metadata = reader.flags & (1 << 4) != 0 ? try reader.metadata() : [:]
        let selectors = reader.flags & (1 << 7) != 0 ? try reader.pathSelectors() : ([], [])
        let objectSelector = reader.flags & (1 << 7) != 0 ? try reader.pathSelector() : (UInt64(0), [])
        try validateSelectors(codes: selectors.0, objectCode: objectSelector.0,
                              objectInstances: objectSelector.1)
        let supportedDataModel = reader.flags & (1 << 5) != 0
            ? try reader.supportedDataModel() : nil
        let protocolInfo = reader.flags & (1 << 6) != 0 ? try reader.protocolInfo() : nil
        try reader.finish()
        return WUSPWireResponse(id: reader.id, method: reader.method, error: error, paths: paths,
                                 objectPath: objectPath, messageFrame: message, transfer: transfer, metadata: metadata,
                                 pathCodes: selectors.0, pathInstances: selectors.1,
                                 objectCode: objectSelector.0, objectInstances: objectSelector.1,
                                 supportedDataModel: supportedDataModel,
                                 protocolInfo: protocolInfo)
    }

    private static func validateMessageFrame(_ data: Data) throws {
        guard data.count >= 8, data[0] == 0x57, data[1] == 0x55, data[2] == 1 else {
            throw WUSPTransportError.malformed
        }
    }

    private static func validateSelectors(codes: [UInt64], objectCode: UInt64,
                                          objectInstances: [UInt64]) throws {
        guard codes.allSatisfy({ $0 != 0 }), (objectCode != 0 || objectInstances.isEmpty),
              codes.count <= maxItems,
              objectInstances.count <= maxItems else { throw WUSPTransportError.malformed }
    }

    private struct Writer {
        var data = Data()
        mutating func header(kind: UInt8, method: UInt8, flags: UInt8, id: UInt64) {
            data.append(contentsOf: [1, kind, method, flags])
            var little = id.littleEndian
            withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
        }
        mutating func varint(_ value: UInt64) {
            var number = value
            while number >= 0x80 { data.append(UInt8(number & 0x7f) | 0x80); number >>= 7 }
            data.append(UInt8(number))
        }
        mutating func string(_ value: String) throws { try bytes(Data(value.utf8)) }
        mutating func bytes(_ value: Data) throws {
            guard value.count <= maxBytes else { throw WUSPTransportError.tooLarge }
            varint(UInt64(value.count)); data.append(value)
        }
        mutating func stringList(_ values: [String]) throws {
            guard values.count <= maxItems else { throw WUSPTransportError.tooLarge }
            varint(UInt64(values.count)); for item in values { try string(item) }
        }
        mutating func pathSelectors(_ codes: [UInt64], instances: [[UInt64]]) throws {
            guard codes.count <= maxItems else { throw WUSPTransportError.tooLarge }
            varint(UInt64(codes.count))
            for (index, code) in codes.enumerated() {
                varint(code)
                try uint64List(instances.indices.contains(index) ? instances[index] : [])
            }
        }
        mutating func pathSelector(_ code: UInt64, instances: [UInt64]) throws {
            varint(code)
            try uint64List(instances)
        }
        mutating func uint64List(_ values: [UInt64]) throws {
            guard values.count <= maxItems else { throw WUSPTransportError.tooLarge }
            varint(UInt64(values.count))
            for value in values { varint(value) }
        }
        mutating func metadata(_ values: [String: String]) throws {
            guard values.count <= maxItems else { throw WUSPTransportError.tooLarge }
            let keys = values.keys.sorted()
            varint(UInt64(keys.count))
            for key in keys { try string(key); try string(values[key] ?? "") }
        }
        mutating func protocolInfo(_ info: WUSPProtocolInfo) throws {
            try string(info.name)
            varint(info.version)
            try stringList(info.methods)
            try stringList(info.compression)
            try string(info.controlTransport)
            try string(info.transferTransport)
            varint(info.maxControlPayload)
            varint(info.recommendedChunkSize)
            varint(info.tunnelOnly ? 1 : 0)
            varint(info.reliableTransfer ? 1 : 0)
        }
        mutating func supportedDataModel(_ model: WUSPSupportedDataModel) throws {
            try string(model.rootDataModelVersion)
            guard model.models.count <= maxItems, model.objects.count <= maxItems,
                  model.params.count <= maxItems else { throw WUSPTransportError.tooLarge }
            varint(UInt64(model.models.count))
            for item in model.models {
                try string(item.id)
                try string(item.name)
                try string(item.modelVersion)
                try string(item.firstVersion)
                try string(item.latestVersion)
                try string(item.source)
                try string(item.sourceURL)
                varint(item.objectCount)
                varint(item.paramCount)
            }
            varint(UInt64(model.objects.count))
            for object in model.objects {
                try string(object.path)
                varint(object.multiInstance ? 1 : 0)
                try string(object.sinceVersion)
            }
            varint(UInt64(model.params.count))
            for param in model.params {
                try string(param.path)
                try string(param.type)
                try string(param.access)
                try string(param.sinceVersion)
            }
        }
        func finish() throws -> Data {
            guard data.count <= maxBytes else { throw WUSPTransportError.tooLarge }
            return data
        }
    }

    private struct Reader {
        let data: Data
        var offset = 12
        let flags: UInt8
        let id: UInt64
        let method: WUSPMethod

        init(_ data: Data, expectedKind: UInt8) throws {
            guard data.count >= 12, data.count <= maxBytes, data[0] == 1, data[1] == expectedKind else {
                throw WUSPTransportError.malformed
            }
            guard let method = WUSPMethod.allCases.first(where: { $0.wireID == data[2] }) else {
                throw WUSPTransportError.unsupported
            }
            self.data = data
            self.flags = data[3]
            self.method = method
            self.id = data[4..<12].enumerated().reduce(UInt64(0)) { $0 | (UInt64($1.element) << (8 * $1.offset)) }
            let supportedFlags: UInt8 = expectedKind == 1 ? 0b0011_1111 : 0b1111_1111
            guard flags & ~supportedFlags == 0 else { throw WUSPTransportError.unsupported }
        }

        mutating func varint() throws -> UInt64 {
            var value: UInt64 = 0
            var shift: UInt64 = 0
            for _ in 0..<10 {
                guard offset < data.count else { throw WUSPTransportError.malformed }
                let byte = data[offset]; offset += 1
                guard shift < 64, !(shift == 63 && byte > 1) else { throw WUSPTransportError.malformed }
                value |= UInt64(byte & 0x7f) << shift
                if byte & 0x80 == 0 { return value }
                shift += 7
            }
            throw WUSPTransportError.malformed
        }
        mutating func bytes() throws -> Data {
            let size = try varint()
            guard size <= UInt64(maxBytes), size <= UInt64(data.count - offset) else { throw WUSPTransportError.malformed }
            defer { offset += Int(size) }
            return data.subdata(in: offset..<(offset + Int(size)))
        }
        mutating func string() throws -> String {
            guard let value = String(data: try bytes(), encoding: .utf8) else { throw WUSPTransportError.malformed }
            return value
        }
        mutating func stringList() throws -> [String] {
            let count = try varint()
            guard count <= UInt64(maxItems) else { throw WUSPTransportError.tooLarge }
            return try (0..<count).map { _ in try string() }
        }
        mutating func pathSelectors() throws -> ([UInt64], [[UInt64]]) {
            let count = try varint()
            guard count <= UInt64(maxItems) else { throw WUSPTransportError.tooLarge }
            var codes: [UInt64] = []
            var instances: [[UInt64]] = []
            codes.reserveCapacity(Int(count))
            instances.reserveCapacity(Int(count))
            for _ in 0..<count {
                codes.append(try varint())
                instances.append(try uint64List())
            }
            return (codes, instances)
        }
        mutating func pathSelector() throws -> (UInt64, [UInt64]) {
            (try varint(), try uint64List())
        }
        mutating func uint64List() throws -> [UInt64] {
            let count = try varint()
            guard count <= UInt64(maxItems) else { throw WUSPTransportError.tooLarge }
            return try (0..<count).map { _ in try varint() }
        }
        mutating func metadata() throws -> [String: String] {
            let count = try varint()
            guard count <= UInt64(maxItems) else { throw WUSPTransportError.tooLarge }
            var result: [String: String] = [:]
            for _ in 0..<count {
                let key = try string()
                guard result[key] == nil else { throw WUSPTransportError.malformed }
                result[key] = try string()
            }
            return result
        }
        mutating func protocolInfo() throws -> WUSPProtocolInfo {
            let name = try string()
            let version = try varint()
            let methods = try stringList()
            let compression = try stringList()
            let controlTransport = try string()
            let transferTransport = try string()
            let maxControlPayload = try varint()
            let recommendedChunkSize = try varint()
            let tunnelOnly = try bool()
            let reliableTransfer = try bool()
            return WUSPProtocolInfo(name: name, version: version, methods: methods,
                                    compression: compression, controlTransport: controlTransport,
                                    transferTransport: transferTransport,
                                    maxControlPayload: maxControlPayload,
                                    recommendedChunkSize: recommendedChunkSize,
                                    tunnelOnly: tunnelOnly, reliableTransfer: reliableTransfer)
        }
        mutating func supportedDataModel() throws -> WUSPSupportedDataModel {
            let rootVersion = try string()
            let modelCount = try itemCount()
            var models: [WUSPBroadbandDataModel] = []
            models.reserveCapacity(modelCount)
            for _ in 0..<modelCount {
                models.append(WUSPBroadbandDataModel(
                    id: try string(), name: try string(), modelVersion: try string(),
                    firstVersion: try string(), latestVersion: try string(),
                    source: try string(), sourceURL: try string(),
                    objectCount: try varint(), paramCount: try varint()))
            }
            let objectCount = try itemCount()
            var objects: [WUSPSupportedObject] = []
            objects.reserveCapacity(objectCount)
            for _ in 0..<objectCount {
                objects.append(WUSPSupportedObject(path: try string(), multiInstance: try bool(),
                                                  sinceVersion: try string()))
            }
            let paramCount = try itemCount()
            var params: [WUSPSupportedParam] = []
            params.reserveCapacity(paramCount)
            for _ in 0..<paramCount {
                params.append(WUSPSupportedParam(path: try string(), type: try string(),
                                                 access: try string(), sinceVersion: try string()))
            }
            return WUSPSupportedDataModel(rootDataModelVersion: rootVersion, models: models,
                                          objects: objects, params: params)
        }
        mutating func itemCount() throws -> Int {
            let count = try varint()
            guard count <= UInt64(maxItems) else { throw WUSPTransportError.tooLarge }
            return Int(count)
        }
        mutating func bool() throws -> Bool {
            let value = try varint()
            guard value <= 1 else { throw WUSPTransportError.malformed }
            return value == 1
        }
        mutating func finish() throws {
            guard data[offset...].allSatisfy({ $0 == 0 }) else { throw WUSPTransportError.malformed }
            offset = data.count
        }
    }
}
