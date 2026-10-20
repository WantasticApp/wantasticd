import Darwin
import Foundation
import WantasticCore

public protocol PFCommandExecuting: Sendable {
    func run(arguments: [String], input: String?) throws -> String
}

public protocol IPv4ForwardingAccess: Sendable {
    func isEnabled() throws -> Bool
    func setEnabled(_ enabled: Bool) throws
}

public protocol SystemRebootRequesting: Sendable {
    func schedule(after delay: TimeInterval)
}

public struct DarwinSystemRebootRequestor: SystemRebootRequesting {
    public init() {}

    public func schedule(after delay: TimeInterval) {
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + delay) {
            guard reboot(RB_AUTOBOOT) != 0 else { return }
            fputs("Wantastic helper could not reboot macOS: \(String(cString: strerror(errno)))\n", stderr)
        }
    }
}

public struct SystemIPv4ForwardingAccess: IPv4ForwardingAccess {
    public init() {}

    public func isEnabled() throws -> Bool {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctlbyname("net.inet.ip.forwarding", &value, &size, nil, 0) == 0,
              size == MemoryLayout<Int32>.size,
              value == 0 || value == 1 else {
            throw MacLocalAccessPrivilegedOperationError.forwardingReadFailed(
                String(cString: strerror(errno)))
        }
        return value == 1
    }

    public func setEnabled(_ enabled: Bool) throws {
        var value: Int32 = enabled ? 1 : 0
        guard sysctlbyname("net.inet.ip.forwarding", nil, nil, &value,
                           MemoryLayout<Int32>.size) == 0 else {
            throw MacLocalAccessPrivilegedOperationError.forwardingWriteFailed(
                String(cString: strerror(errno)))
        }
    }
}

public enum MacLocalAccessPrivilegedOperationError: Error, Equatable {
    case invalidPlan
    case invalidToken
    case pfCommandFailed(String)
    case forwardingReadFailed(String)
    case forwardingWriteFailed(String)
}

/// Root-side operation set. The caller cannot choose an executable, PF anchor,
/// PF command, or raw rule string; plans are decoded and validated again here.
public final class MacLocalAccessPrivilegedOperations: @unchecked Sendable {
    private let commandRunner: any PFCommandExecuting
    private let forwarding: any IPv4ForwardingAccess
    private let rebootRequestor: any SystemRebootRequesting
    private let stateStore: any MacLocalAccessHelperStateStoring
    private let lock = NSRecursiveLock()

    public init(commandRunner: any PFCommandExecuting = SystemPFCommandRunner(),
                forwarding: any IPv4ForwardingAccess = SystemIPv4ForwardingAccess(),
                rebootRequestor: any SystemRebootRequesting = DarwinSystemRebootRequestor(),
                stateStore: any MacLocalAccessHelperStateStoring = FileMacLocalAccessHelperStateStore()) {
        self.commandRunner = commandRunner
        self.forwarding = forwarding
        self.rebootRequestor = rebootRequestor
        self.stateStore = stateStore
    }

    /// Schedules a fixed native reboot so the authenticated controller can
    /// receive the Operate response before the system starts shutting down.
    public func scheduleSystemReboot() {
        lock.withLock { rebootRequestor.schedule(after: 2) }
    }

    public func ipv4ForwardingEnabled() throws -> Bool {
        try lock.withLock { try forwarding.isEnabled() }
    }

    public func setIPv4Forwarding(_ enabled: Bool) throws {
        try lock.withLock {
            let current = try forwarding.isEnabled()
            guard current != enabled else { return }
            var state = try stateStore.load()
            if state.originalIPv4Forwarding == nil {
                state.originalIPv4Forwarding = current
            }
            state.forwardingValueBeforeMutation = current
            state.helperSetIPv4Forwarding = enabled
            try stateStore.save(state)
            try forwarding.setEnabled(enabled)
        }
    }

    public func packetFilterEnabled() throws -> Bool {
        try lock.withLock {
            let output = try pfctl(["-s", "info"])
            for line in output.split(separator: "\n") {
                let fields = line.split(whereSeparator: \.isWhitespace)
                if fields.count >= 2, fields[0] == "Status:" { return fields[1] == "Enabled" }
            }
            throw MacLocalAccessPrivilegedOperationError.pfCommandFailed("PF status was not reported")
        }
    }

    public func enablePacketFilter() throws -> String {
        try lock.withLock {
            let previous = try stateStore.load()
            if let token = previous.packetFilterToken { return token }
            let output = try pfctl(["-E"])
            for line in output.split(separator: "\n") {
                guard let separator = line.firstIndex(of: ":"),
                      line[..<separator].trimmingCharacters(in: .whitespaces) == "Token" else { continue }
                let token = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
                guard Self.isValidToken(token) else { break }
                var state = previous
                state.packetFilterToken = token
                do { try stateStore.save(state) }
                catch {
                    _ = try? pfctl(["-X", token])
                    throw error
                }
                return token
            }
            throw MacLocalAccessPrivilegedOperationError.pfCommandFailed("PF enable token was not reported")
        }
    }

    public func applyFirewallPlan(_ data: Data) throws {
        try lock.withLock {
            guard data.count <= 64 * 1024,
                  let request = try? JSONDecoder().decode(MacLocalAccessFirewallPlanRequest.self, from: data),
                  let plan = try? request.validatedPlan() else {
                throw MacLocalAccessPrivilegedOperationError.invalidPlan
            }
            var state = try stateStore.load()
            state.anchorCleanupRequired = true
            try stateStore.save(state)
            _ = try pfctl(["-a", MacLocalAccessFirewallPlan.pfAnchor, "-f", "-"], input: plan.rules)
        }
    }

    public func flushWantasticAnchor() throws {
        try lock.withLock {
            _ = try pfctl(["-a", MacLocalAccessFirewallPlan.pfAnchor, "-F", "all"])
            var state = try stateStore.load()
            state.anchorCleanupRequired = false
            try stateStore.save(state)
        }
    }

    public func releasePacketFilterToken(_ token: String) throws {
        try lock.withLock {
            guard Self.isValidToken(token) else {
                throw MacLocalAccessPrivilegedOperationError.invalidToken
            }
            guard try stateStore.load().packetFilterToken == token else {
                throw MacLocalAccessPrivilegedOperationError.invalidToken
            }
            _ = try pfctl(["-X", token])
            var state = try stateStore.load()
            if state.packetFilterToken == token {
                state.packetFilterToken = nil
                try stateStore.save(state)
            }
        }
    }

    /// Removes only resources recorded as owned by Wantastic. The state file
    /// remains until every cleanup action succeeds so launchd retries recovery.
    public func recoverOwnedState() throws {
        try lock.withLock {
            var state = try stateStore.load().validated()
            guard !state.isEmpty else { return }
            if state.anchorCleanupRequired {
                _ = try pfctl(["-a", MacLocalAccessFirewallPlan.pfAnchor, "-F", "all"])
                state.anchorCleanupRequired = false
                try stateStore.save(state)
            }
            if let token = state.packetFilterToken {
                _ = try pfctl(["-X", token])
                state.packetFilterToken = nil
                try stateStore.save(state)
            }
            if let original = state.originalIPv4Forwarding,
               let beforeMutation = state.forwardingValueBeforeMutation,
               let expected = state.helperSetIPv4Forwarding {
                let current = try forwarding.isEnabled()
                if current == expected || current == beforeMutation,
                   current != original {
                    try forwarding.setEnabled(original)
                }
            }
            try stateStore.clear()
        }
    }

    private func pfctl(_ arguments: [String], input: String? = nil) throws -> String {
        do { return try commandRunner.run(arguments: arguments, input: input) }
        catch {
            throw MacLocalAccessPrivilegedOperationError.pfCommandFailed(error.localizedDescription)
        }
    }

    private static func isValidToken(_ token: String) -> Bool {
        !token.isEmpty && token.utf8.count <= 128 && token.utf8.allSatisfy { (48...57).contains($0) }
    }
}

public struct SystemPFCommandRunner: PFCommandExecuting {
    public init() {}

    public func run(arguments: [String], input: String?) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        let inputPipe = input == nil ? nil : Pipe()
        process.standardInput = inputPipe
        try process.run()
        if let input, let inputPipe {
            do {
                try inputPipe.fileHandleForWriting.write(contentsOf: Data(input.utf8))
                try inputPipe.fileHandleForWriting.close()
            } catch {
                inputPipe.fileHandleForWriting.closeFile()
                process.terminate()
                process.waitUntilExit()
                throw error
            }
        }
        let result = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw MacLocalAccessPrivilegedOperationError.pfCommandFailed(
                "pfctl failed (\(process.terminationStatus)): \(result.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        return result
    }
}
