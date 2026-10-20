import Darwin
import Foundation

public struct MacIPAddressSnapshot: Equatable, Sendable {
    public let address: Data
    public let subnetMask: Data?
    public let family: Int32

    public init(address: Data, subnetMask: Data?, family: Int32) {
        self.address = address
        self.subnetMask = subnetMask
        self.family = family
    }
}

public struct MacInterfaceSnapshot: Equatable, Sendable {
    public let name: String
    public let isUp: Bool
    public let isLoopback: Bool
    public let isPointToPoint: Bool
    public let hardwareAddress: Data?
    public let addresses: [MacIPAddressSnapshot]

    public init(name: String, isUp: Bool, addresses: [MacIPAddressSnapshot],
                isLoopback: Bool = false, isPointToPoint: Bool = false,
                hardwareAddress: Data? = nil) {
        self.name = name
        self.isUp = isUp
        self.isLoopback = isLoopback
        self.isPointToPoint = isPointToPoint
        self.hardwareAddress = hardwareAddress
        self.addresses = addresses
    }
}

/// Read-only macOS system collector. It uses Darwin APIs directly and never
/// invokes a shell, AppleScript, or an external command.
public enum MacDeviceCollector {
    /// Returns usable host-interface addresses for the P2P coordinator. The
    /// connected WireGuard socket's bound port is supplied by its Network
    /// framework path so peers probe the mapping that actually exists.
    public static func p2pCandidates(udpPort: UInt16) throws -> [P2PEndpoint] {
        guard udpPort > 0 else { return [] }
        return p2pCandidates(from: try networkInterfaces(), udpPort: udpPort)
    }

    static func p2pCandidates(from interfaces: [MacInterfaceSnapshot],
                              udpPort: UInt16) -> [P2PEndpoint] {
        guard udpPort > 0 else { return [] }
        var seen = Set<P2PEndpoint>()
        var result: [P2PEndpoint] = []
        for interface in interfaces where interface.isUp && !interface.isLoopback &&
            interface.hardwareAddress?.count == 6 {
            for address in interface.addresses {
                guard isUsableP2PAddress(address.address, family: address.family) else { continue }
                let candidate = P2PEndpoint(address: address.address, port: udpPort)
                if seen.insert(candidate).inserted { result.append(candidate) }
            }
        }
        return result
    }

    /// Finds bounded, directly attached private IPv4 networks suitable for an
    /// explicit local-access advertisement. This only discovers routes; it
    /// does not change system routing, firewall, or tunnel state.
    public static func privateLANRoutes() throws -> [String] {
        try privateLANRoutes(from: networkInterfaces())
    }

    public static func privateLANRouteCandidates() throws -> [MacLocalAccessRoute] {
        try privateLANRouteCandidates(from: networkInterfaces())
    }

    /// Finds the active interface that owns a configured IPv4 tunnel address.
    /// This deliberately does not guess from interface numbering or route order.
    public static func interfaceName(owningIPv4Address address: String) throws -> String? {
        try interfaceName(owningIPv4Address: address, from: networkInterfaces())
    }

    static func interfaceName(owningIPv4Address address: String,
                              from interfaces: [MacInterfaceSnapshot]) -> String? {
        var parsed = in_addr()
        guard address.withCString({ inet_pton(AF_INET, $0, &parsed) }) == 1 else { return nil }
        let target = data(parsed)
        return interfaces
            .filter(\.isUp)
            .sorted { lhs, rhs in
                let lhsTunnel = lhs.name.hasPrefix("utun")
                let rhsTunnel = rhs.name.hasPrefix("utun")
                return lhsTunnel && !rhsTunnel
            }
            .first { interface in
                interface.addresses.contains { $0.family == AF_INET && $0.address == target }
            }?.name
    }

    public static func privateLANRoutes(from interfaces: [MacInterfaceSnapshot],
                                        tunnelInterfaceName: String? = nil) throws -> [String] {
        try privateLANRouteCandidates(from: interfaces,
                                      tunnelInterfaceName: tunnelInterfaceName).map { $0.prefix.description }
    }

    public static func privateLANRouteCandidates(from interfaces: [MacInterfaceSnapshot],
                                                 tunnelInterfaceName: String? = nil) throws -> [MacLocalAccessRoute] {
        var routeInterfaces: [String: String] = [:]
        for interface in interfaces where interface.isUp && !interface.isLoopback &&
            !interface.isPointToPoint && interface.hardwareAddress?.count == 6 &&
            interface.name != tunnelInterfaceName && !interface.name.hasPrefix("utun") {
            for address in interface.addresses where address.family == AF_INET {
                guard let route = privateIPv4Network(address: address.address,
                                                     subnetMask: address.subnetMask) else { continue }
                if let previous = routeInterfaces[route], previous != interface.name {
                    throw MacCollectorError.ambiguousLocalRoute
                }
                routeInterfaces[route] = interface.name
            }
        }
        guard routeInterfaces.count <= TunnelControlCodec.maxRoutesPerOwner else {
            throw TunnelControlError.tooManyRoutes
        }
        return try routeInterfaces.keys.sorted().map { route in
            guard let interface = routeInterfaces[route] else { throw MacCollectorError.ambiguousLocalRoute }
            return try MacLocalAccessRoute(prefix: route, interfaceName: interface)
        }
    }

    public static func collect() throws -> WUSPMessage {
        let interfaces = try networkInterfaces()
        let hostname = systemHostname()
        let model = sysctlString("hw.model") ?? "Mac"
        let process = ProcessInfo.processInfo
        let version = process.operatingSystemVersion
        return message(hostname: hostname, model: model,
                       softwareVersion: productVersion(version),
                       interfaces: interfaces,
                       systemUptimeSeconds: UInt64(max(0, process.systemUptime)),
                       totalMemoryKilobytes: process.physicalMemory / 1024,
                       freeMemoryKilobytes: freeMemoryKilobytes() ?? 0,
                       localTimeZone: TimeZone.current.identifier)
    }

    static func productVersion(_ version: OperatingSystemVersion) -> String {
        let components = [version.majorVersion, version.minorVersion]
        let versionComponents = version.patchVersion == 0
            ? components
            : components + [version.patchVersion]
        return versionComponents.map(String.init).joined(separator: ".")
    }

    public static func message(hostname: String, model: String, softwareVersion: String,
                               interfaces: [MacInterfaceSnapshot], timestamp: Date = Date(),
                               systemUptimeSeconds: UInt64 = 0,
                               totalMemoryKilobytes: UInt64 = 0,
                               freeMemoryKilobytes: UInt64 = 0,
                               localTimeZone: String = "") -> WUSPMessage {
        var fields = [
            WUSPMessageField(path: "Device.RootDataModelVersion", value: .string("2.20")),
            WUSPMessageField(path: "Device.DeviceInfo.Manufacturer", value: .string("Apple")),
            WUSPMessageField(path: "Device.DeviceInfo.ModelName", value: .string(model)),
            WUSPMessageField(path: "Device.DeviceInfo.ProductClass", value: .string("Mac")),
            WUSPMessageField(path: "Device.DeviceInfo.SoftwareVersion", value: .string(softwareVersion)),
            WUSPMessageField(path: "Device.DeviceInfo.HostName", value: .string(hostname)),
            WUSPMessageField(path: "Device.DeviceInfo.NetworkProperties.TCPImplementation",
                             value: .list([.string("CUBIC")])),
            WUSPMessageField(path: "Device.Time.CurrentLocalTime",
                             value: .timeNanoseconds(Int64(timestamp.timeIntervalSince1970 * 1_000_000_000))),
            WUSPMessageField(path: "Device.IP.IPv4Capable", value: .bool(true)),
            WUSPMessageField(path: "Device.IP.IPv4Enable", value: .bool(true)),
            WUSPMessageField(path: "Device.IP.IPv4Status", value: .string("Enabled")),
            WUSPMessageField(path: "Device.IP.IPv6Capable", value: .bool(true)),
            WUSPMessageField(path: "Device.IP.IPv6Enable", value: .bool(true)),
            WUSPMessageField(path: "Device.IP.IPv6Status", value: .string("Enabled")),
        ]
        if systemUptimeSeconds > 0 {
            fields.append(WUSPMessageField(path: "Device.DeviceInfo.UpTime",
                                           value: .unsigned(systemUptimeSeconds)))
        }
        if totalMemoryKilobytes > 0 {
            fields.append(WUSPMessageField(path: "Device.DeviceInfo.MemoryStatus.Total",
                                           value: .unsigned(totalMemoryKilobytes)))
        }
        if freeMemoryKilobytes > 0 {
            fields.append(WUSPMessageField(path: "Device.DeviceInfo.MemoryStatus.Free",
                                           value: .unsigned(freeMemoryKilobytes)))
        }
        if !localTimeZone.isEmpty {
            fields.append(WUSPMessageField(path: "Device.Time.LocalTimeZone",
                                           value: .string(localTimeZone)))
        }

        let advertised = interfaces.filter { !$0.isLoopback && $0.hardwareAddress?.count == 6 }
            .sorted(by: { $0.name < $1.name })
        fields.append(WUSPMessageField(path: "Device.Ethernet.InterfaceNumberOfEntries",
                                       value: .unsigned(UInt64(advertised.count))))
        fields.append(WUSPMessageField(path: "Device.IP.InterfaceNumberOfEntries", value: .unsigned(UInt64(advertised.count))))
        for (position, interface) in advertised.enumerated() {
            let interfaceID = position + 1
            let root = "Device.IP.Interface.\(interfaceID)."
            let ethernetRoot = "Device.Ethernet.Interface.\(interfaceID)."
            fields.append(WUSPMessageField(path: ethernetRoot + "Name", value: .string(interface.name)))
            fields.append(WUSPMessageField(path: ethernetRoot + "Enable", value: .bool(interface.isUp)))
            fields.append(WUSPMessageField(path: ethernetRoot + "Status",
                                           value: .string(interface.isUp ? "Up" : "Down")))
            if let hardwareAddress = interface.hardwareAddress {
                fields.append(WUSPMessageField(path: ethernetRoot + "MACAddress",
                                               value: .mac(hardwareAddress)))
            }
            fields.append(WUSPMessageField(path: root + "Name", value: .string(interface.name)))
            fields.append(WUSPMessageField(path: root + "Enable", value: .bool(interface.isUp)))
            fields.append(WUSPMessageField(path: root + "Status", value: .string(interface.isUp ? "Up" : "Down")))
            var ipv4ID = 0
            var ipv6ID = 0
            for address in interface.addresses {
                if address.family == AF_INET, address.address.count == 4 {
                    ipv4ID += 1
                    let base = root + "IPv4Address.\(ipv4ID)."
                    fields.append(WUSPMessageField(path: base + "IPAddress", value: .ipv4(address.address)))
                    if let mask = address.subnetMask, mask.count == 4 {
                        fields.append(WUSPMessageField(path: base + "SubnetMask", value: .ipv4(mask)))
                    }
                } else if address.family == AF_INET6, address.address.count == 16 {
                    ipv6ID += 1
                    let base = root + "IPv6Address.\(ipv6ID)."
                    fields.append(WUSPMessageField(path: base + "IPAddress", value: .ipv6(address.address)))
                }
            }
        }
        return WUSPMessage(timestampNanoseconds: Int64(timestamp.timeIntervalSince1970 * 1_000_000_000), fields: fields)
    }

    private static func freeMemoryKilobytes() -> UInt64? {
        var statistics = vm_statistics64()
        var count = mach_msg_type_number_t(
            MemoryLayout<vm_statistics64_data_t>.stride / MemoryLayout<integer_t>.stride)
        let result = withUnsafeMutablePointer(to: &statistics) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        return UInt64(statistics.free_count) * UInt64(getpagesize()) / 1024
    }

    private static func networkInterfaces() throws -> [MacInterfaceSnapshot] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0, let first else { throw MacCollectorError.interfaceEnumerationFailed }
        defer { freeifaddrs(first) }

        struct MutableInterface {
            var isUp = false
            var isLoopback = false
            var isPointToPoint = false
            var hardwareAddress: Data?
            var addresses: [MacIPAddressSnapshot] = []
        }
        var byName: [String: MutableInterface] = [:]
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let item = cursor {
            defer { cursor = item.pointee.ifa_next }
            let record = item.pointee
            let name = String(cString: record.ifa_name)
            let isUp = record.ifa_flags & UInt32(IFF_UP) != 0
            var value = byName[name] ?? MutableInterface()
            value.isUp = value.isUp || isUp
            value.isLoopback = value.isLoopback || record.ifa_flags & UInt32(IFF_LOOPBACK) != 0
            value.isPointToPoint = value.isPointToPoint || record.ifa_flags & UInt32(IFF_POINTOPOINT) != 0
            guard let addressPointer = record.ifa_addr else { byName[name] = value; continue }
            let family = Int32(addressPointer.pointee.sa_family)

            if family == AF_LINK {
                value.hardwareAddress = hardwareAddress(from: addressPointer)
            } else if family == AF_INET {
                let address = addressPointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                let mask = record.ifa_netmask?.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                value.addresses.append(MacIPAddressSnapshot(address: data(address), subnetMask: mask.map(data), family: AF_INET))
            } else if family == AF_INET6 {
                let address = addressPointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                let mask = record.ifa_netmask?.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                value.addresses.append(MacIPAddressSnapshot(address: data(address), subnetMask: mask.map(data), family: AF_INET6))
            }
            byName[name] = value
        }
        return byName.map {
            MacInterfaceSnapshot(name: $0.key, isUp: $0.value.isUp,
                                 addresses: $0.value.addresses,
                                 isLoopback: $0.value.isLoopback,
                                 isPointToPoint: $0.value.isPointToPoint,
                                 hardwareAddress: $0.value.hardwareAddress)
        }
    }

    private static func data(_ address: in_addr) -> Data {
        var copy = address.s_addr
        return withUnsafeBytes(of: &copy) { Data($0) }
    }

    private static func hardwareAddress(from address: UnsafeMutablePointer<sockaddr>) -> Data? {
        address.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { link in
            let length = Int(link.pointee.sdl_alen)
            let nameLength = Int(link.pointee.sdl_nlen)
            guard length == 6,
                  let dataOffset = MemoryLayout<sockaddr_dl>.offset(of: \.sdl_data),
                  Int(link.pointee.sdl_len) >= dataOffset + nameLength + length else { return nil }
            return Data(bytes: UnsafeRawPointer(link).advanced(by: dataOffset + nameLength), count: length)
        }
    }

    private static func data(_ address: in6_addr) -> Data {
        var copy = address
        return withUnsafeBytes(of: &copy) { Data($0.prefix(16)) }
    }

    private static func isUsableP2PAddress(_ address: Data, family: Int32) -> Bool {
        if family == AF_INET, address.count == 4 {
            let bytes = Array(address)
            return bytes.contains(where: { $0 != 0 }) && bytes[0] != 127 && bytes[0] < 224 &&
                !(bytes[0] == 169 && bytes[1] == 254)
        }
        if family == AF_INET6, address.count == 16 {
            let bytes = Array(address)
            return bytes.contains(where: { $0 != 0 }) && bytes != Array(repeating: 0, count: 15) + [1] &&
                bytes[0] != 0xff && !(bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80)
        }
        return false
    }

    private static func privateIPv4Network(address: Data, subnetMask: Data?) -> String? {
        guard address.count == 4, let subnetMask, subnetMask.count == 4 else { return nil }
        let bytes = Array(address)
        let octets = bytes.map(UInt32.init)
        let ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        let maskBytes = Array(subnetMask).map(UInt32.init)
        let mask = (maskBytes[0] << 24) | (maskBytes[1] << 16) | (maskBytes[2] << 8) | maskBytes[3]
        let prefixLength = mask.nonzeroBitCount
        guard (8...32).contains(prefixLength),
              mask == (prefixLength == 0 ? 0 : UInt32.max << (32 - prefixLength)) else { return nil }

        let first = bytes[0]
        let second = bytes[1]
        let isPrivate = first == 10 || (first == 172 && (16...31).contains(second)) ||
            (first == 192 && second == 168)
        guard isPrivate else { return nil }

        let network = ip & mask
        let networkText = [24, 16, 8, 0].map { String((network >> $0) & 255) }.joined(separator: ".")
        return "\(networkText)/\(prefixLength)"
    }

    private static func systemHostname() -> String {
        var buffer = [CChar](repeating: 0, count: Int(MAXHOSTNAMELEN))
        guard gethostname(&buffer, buffer.count) == 0 else { return Host.current().name ?? "Mac" }
        return decodedCString(buffer)
    }

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 1 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
        return decodedCString(buffer)
    }

    private static func decodedCString(_ buffer: [CChar]) -> String {
        String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}

public enum MacCollectorError: Error, Equatable {
    case interfaceEnumerationFailed
    case ambiguousLocalRoute
}
