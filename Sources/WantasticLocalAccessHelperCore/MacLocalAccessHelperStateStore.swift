import Darwin
import Foundation

public struct MacLocalAccessHelperRecoveryState: Codable, Equatable, Sendable {
    public var anchorCleanupRequired = false
    public var packetFilterToken: String?
    public var originalIPv4Forwarding: Bool?
    public var forwardingValueBeforeMutation: Bool?
    public var helperSetIPv4Forwarding: Bool?

    public init(anchorCleanupRequired: Bool = false, packetFilterToken: String? = nil,
                originalIPv4Forwarding: Bool? = nil, forwardingValueBeforeMutation: Bool? = nil,
                helperSetIPv4Forwarding: Bool? = nil) {
        self.anchorCleanupRequired = anchorCleanupRequired
        self.packetFilterToken = packetFilterToken
        self.originalIPv4Forwarding = originalIPv4Forwarding
        self.forwardingValueBeforeMutation = forwardingValueBeforeMutation
        self.helperSetIPv4Forwarding = helperSetIPv4Forwarding
    }

    public var isEmpty: Bool {
        !anchorCleanupRequired && packetFilterToken == nil &&
            originalIPv4Forwarding == nil && forwardingValueBeforeMutation == nil &&
            helperSetIPv4Forwarding == nil
    }

    public func validated() throws -> Self {
        if let token = packetFilterToken,
           token.isEmpty || token.utf8.count > 128 ||
            !token.utf8.allSatisfy({ (48...57).contains($0) }) {
            throw MacLocalAccessHelperStateStoreError.invalidState
        }
        guard (originalIPv4Forwarding == nil) == (forwardingValueBeforeMutation == nil),
              (originalIPv4Forwarding == nil) == (helperSetIPv4Forwarding == nil) else {
            throw MacLocalAccessHelperStateStoreError.invalidState
        }
        return self
    }
}

public protocol MacLocalAccessHelperStateStoring: Sendable {
    func load() throws -> MacLocalAccessHelperRecoveryState
    func save(_ state: MacLocalAccessHelperRecoveryState) throws
    func clear() throws
}

public enum MacLocalAccessHelperStateStoreError: Error, Equatable {
    case invalidState
    case unsafePath
    case corruptState
    case ioFailure(String)
}

/// Root-only, bounded, atomic recovery record. The parent is required to be a
/// root-owned system directory and the data file must be a regular 0600 file.
public struct FileMacLocalAccessHelperStateStore: MacLocalAccessHelperStateStoring {
    public static let defaultURL = URL(fileURLWithPath: "/var/db/app.wantastic.local-access-helper.json")
    private static let maximumBytes = 4096
    private let fileURL: URL

    public init(fileURL: URL = defaultURL) {
        self.fileURL = fileURL
    }

    public func load() throws -> MacLocalAccessHelperRecoveryState {
        try requireRoot()
        try validateParent()
        let fd = fileURL.path.withCString { open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
        guard fd >= 0 else {
            if errno == ENOENT { return MacLocalAccessHelperRecoveryState() }
            throw ioFailure()
        }
        defer { _ = close(fd) }
        var metadata = stat()
        guard fstat(fd, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == 0,
              (metadata.st_mode & 0o077) == 0,
              metadata.st_size >= 0,
              metadata.st_size <= Self.maximumBytes else {
            throw MacLocalAccessHelperStateStoreError.unsafePath
        }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 1024)
        while true {
            let count = read(fd, &buffer, buffer.count)
            if count == 0 { break }
            guard count > 0, data.count + count <= Self.maximumBytes else {
                throw count < 0 ? ioFailure() : MacLocalAccessHelperStateStoreError.corruptState
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        guard let state = try? JSONDecoder().decode(MacLocalAccessHelperRecoveryState.self, from: data),
              let validated = try? state.validated() else {
            throw MacLocalAccessHelperStateStoreError.corruptState
        }
        return validated
    }

    public func save(_ state: MacLocalAccessHelperRecoveryState) throws {
        try requireRoot()
        try validateParent()
        let validated = try state.validated()
        if validated.isEmpty { return try clear() }
        let data = try JSONEncoder().encode(validated)
        guard data.count <= Self.maximumBytes else {
            throw MacLocalAccessHelperStateStoreError.invalidState
        }

        let parent = fileURL.deletingLastPathComponent().path
        var template = Array((parent + "/.wantastic-local-access.XXXXXX").utf8CString)
        let fd = mkstemp(&template)
        guard fd >= 0 else { throw ioFailure() }
        let temporaryPath = template.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        var shouldUnlink = true
        defer {
            _ = close(fd)
            if shouldUnlink { _ = temporaryPath.withCString { unlink($0) } }
        }
        guard fchmod(fd, mode_t(0o600)) == 0 else { throw ioFailure() }
        try writeAll(data, to: fd)
        guard fsync(fd) == 0 else { throw ioFailure() }
        guard temporaryPath.withCString({ temporary in
            fileURL.path.withCString { destination in rename(temporary, destination) }
        }) == 0 else { throw ioFailure() }
        shouldUnlink = false
        let directoryFD = parent.withCString { open($0, O_RDONLY | O_CLOEXEC) }
        if directoryFD >= 0 {
            defer { _ = close(directoryFD) }
            guard fsync(directoryFD) == 0 else { throw ioFailure() }
        }
    }

    public func clear() throws {
        try requireRoot()
        try validateParent()
        let result = fileURL.path.withCString { unlink($0) }
        if result != 0, errno != ENOENT { throw ioFailure() }
        let directoryFD = fileURL.deletingLastPathComponent().path.withCString {
            open($0, O_RDONLY | O_CLOEXEC)
        }
        if directoryFD >= 0 {
            defer { _ = close(directoryFD) }
            guard fsync(directoryFD) == 0 else { throw ioFailure() }
        }
    }

    private func requireRoot() throws {
        guard geteuid() == 0 else { throw MacLocalAccessHelperStateStoreError.unsafePath }
    }

    private func validateParent() throws {
        var metadata = stat()
        let result = fileURL.deletingLastPathComponent().path.withCString { lstat($0, &metadata) }
        guard result == 0,
              (metadata.st_mode & S_IFMT) == S_IFDIR,
              metadata.st_uid == 0,
              (metadata.st_mode & 0o022) == 0 else {
            throw MacLocalAccessHelperStateStoreError.unsafePath
        }
    }

    private func writeAll(_ data: Data, to fd: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < data.count {
                let written = Darwin.write(fd, base.advanced(by: offset), data.count - offset)
                guard written > 0 else { throw ioFailure() }
                offset += written
            }
        }
    }

    private func ioFailure() -> MacLocalAccessHelperStateStoreError {
        .ioFailure(String(cString: strerror(errno)))
    }
}
