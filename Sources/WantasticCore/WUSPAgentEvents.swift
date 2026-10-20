import Foundation

/// Go-compatible encoders for agent-originated WUSP notifications. These are
/// sent fire-and-forget to the controller, unlike WUSP requests issued by the
/// desktop UI and correlated by `WUSPRequestTransport`.
public enum WUSPAgentEventCodec {
    public static let protocolVersion = "1.0.0"
    // Frozen from Wantastic's Go WUSP model for Device. Go compacts known
    // object paths to selectors before encoding a request.
    public static let deviceRootObjectCode: UInt64 = 12_276_583_236_878_442_247
    public static let deviceInfoObjectCode: UInt64 = 574_954_365_742_359_977
    private static let valueChangePathCodes: [String: UInt64] = [
        "Device.DeviceInfo.FriendlyName": 2_286_188_729_812_078_817,
        "Device.DeviceInfo.ProvisioningCode": 8_620_908_333_006_359_769,
    ]

    public static func encodeOnBoardRequest(id: UInt64, serialNumber: String,
                                            manufacturer: String, productClass: String,
                                            softwareVersion: String) throws -> Data {
        let values = [serialNumber, manufacturer, productClass, softwareVersion]
        guard id > 0, values.allSatisfy({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }),
              values.allSatisfy({ $0.utf8.count <= 256 }) else {
            throw WUSPTransportError.malformed
        }
        let request = WUSPWireRequest(
            id: id,
            method: .notify,
            metadata: [
                "event_type": "6",
                "manufacturer": manufacturer,
                "product_class": productClass,
                "protocol_versions": protocolVersion,
                "serial_number": serialNumber,
                "software_version": softwareVersion,
            ],
            objectCode: deviceRootObjectCode
        )
        return try WUSPTransportCodec.encode(request)
    }

    public static func encodeValueChange(id: UInt64, subscriptionID: String?,
                                         parameterPath: String, value: String) throws -> Data {
        guard id > 0, let separator = parameterPath.lastIndex(of: "."),
              separator > parameterPath.startIndex,
              !parameterPath.hasSuffix("."), parameterPath.utf8.count <= 512,
              value.utf8.count <= 4_096 else {
            throw WUSPTransportError.malformed
        }
        var metadata = ["event_type": "2", "param_value": value]
        if let subscriptionID, !subscriptionID.isEmpty {
            metadata["subscription_id"] = subscriptionID
        }
        let objectPath = String(parameterPath[...separator])
        let request: WUSPWireRequest
        if let pathCode = valueChangePathCodes[parameterPath],
           objectPath == "Device.DeviceInfo." {
            request = WUSPWireRequest(id: id, method: .notify, metadata: metadata,
                                      pathCodes: [pathCode], pathInstances: [[]],
                                      objectCode: deviceInfoObjectCode)
        } else {
            request = WUSPWireRequest(id: id, method: .notify, paths: [parameterPath],
                                      objectPath: objectPath, metadata: metadata)
        }
        return try WUSPTransportCodec.encode(request)
    }
}
