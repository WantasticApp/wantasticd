import Darwin
import Foundation
import Network

public enum TCPServiceScannerError: Error, Equatable {
    case invalidAddress
    case invalidPorts
    case tooManyPorts
    case invalidTimeout
}

/// Performs a bounded TCP connect scan against one explicitly selected IP
/// address. It never scans a subnet or resolves arbitrary hostnames.
public enum TCPServiceScanner {
    public static let commonPorts: [UInt16] = [22, 80, 443, 3389, 5900, 8000, 8080, 8443]
    public static let maximumPorts = 128
    private static let maximumConcurrentConnections = 16
    private static let queue = DispatchQueue(label: "app.wantastic.tcp-service-scan")

    public static func scan(address: String, ports: [UInt16] = commonPorts,
                            timeout: TimeInterval = 1.2) async throws -> [NetworkService] {
        guard isIPAddress(address) else { throw TCPServiceScannerError.invalidAddress }
        guard !ports.isEmpty, ports.allSatisfy({ $0 != 0 }), Set(ports).count == ports.count else {
            throw TCPServiceScannerError.invalidPorts
        }
        guard ports.count <= maximumPorts else { throw TCPServiceScannerError.tooManyPorts }
        guard timeout.isFinite, (0.1...10).contains(timeout) else { throw TCPServiceScannerError.invalidTimeout }

        var services: [NetworkService] = []
        for start in stride(from: 0, to: ports.count, by: maximumConcurrentConnections) {
            let end = min(start + maximumConcurrentConnections, ports.count)
            let batch = Array(ports[start..<end])
            let results = await withTaskGroup(of: (UInt16, Bool).self, returning: [(UInt16, Bool)].self) { group in
                for port in batch {
                    group.addTask {
                        (port, await probe(address: address, port: port, timeout: timeout))
                    }
                }
                var values: [(UInt16, Bool)] = []
                for await value in group { values.append(value) }
                return values
            }
            services.append(contentsOf: results.compactMap { port, isOpen in
                isOpen ? NetworkService(port: Int(port), kind: ServiceClassifier.kind(for: Int(port)), isOpen: true) : nil
            })
        }
        return services.sorted { $0.port < $1.port }
    }

    private static func isIPAddress(_ value: String) -> Bool {
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 { return true }
        var ipv6 = in6_addr()
        return value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1
    }

    private static func probe(address: String, port: UInt16, timeout: TimeInterval) async -> Bool {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else { return false }
        let connection = NWConnection(host: NWEndpoint.Host(address), port: endpointPort, using: .tcp)
        let completion = ProbeCompletion()
        let opened = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            completion.install(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    completion.finish(true)
                case .failed, .cancelled:
                    completion.finish(false)
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                completion.finish(false)
                connection.cancel()
            }
        }
        connection.cancel()
        return opened
    }
}

private final class ProbeCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Bool, Never>?
    private var finished = false

    func install(_ continuation: CheckedContinuation<Bool, Never>) {
        lock.lock()
        self.continuation = continuation
        lock.unlock()
    }

    func finish(_ result: Bool) {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(returning: result)
    }
}
