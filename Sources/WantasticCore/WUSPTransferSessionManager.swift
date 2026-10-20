import Darwin
import Foundation

/// Implements the Go-compatible WUSP stream session on a private staging
/// directory. Remote requests can name files in that directory but cannot
/// use paths to read or overwrite arbitrary host files.
public actor WUSPTransferSessionManager {
    public static let chunkSize = 1_120
    public static let acknowledgementTimeout: Duration = .seconds(2)
    public static let maximumRetries = 3
    public static let maximumTransferBytes: UInt64 = 512 * 1_024 * 1_024
    private static let maximumConcurrentSessions = 8
    private static let sessionLifetime: Duration = .seconds(600)
    private static let transportKey = "transport"
    private static let sessionIDKey = "session_id"
    private static let chunkSizeKey = "chunk_size"
    private static let sourceKey = "source"
    private static let destinationKey = "destination"

    private struct Session {
        let id: UInt64
        let requestID: UInt64
        let method: WUSPMethod
        let filename: String
        let contentType: String
        let fileURL: URL
        let temporaryURL: URL?
        let totalSize: UInt64
        var reservedBytes: UInt64 = 0
        var transferred: UInt64 = 0
        var nextSequence: UInt32 = 1
        var highestAcknowledgement: UInt32 = 0
        var fileHandle: FileHandle?
        var acknowledgementWaiters: [UInt32: CheckedContinuation<Void, Error>] = [:]
    }

    private let channel: any WUSPTransferStreamChannel
    private let directory: URL
    private let fileManager: FileManager
    private let acknowledgementTimeout: Duration
    private let maximumRetries: Int
    private var sessions: [UInt64: Session] = [:]
    private var reservedTransferBytes: UInt64 = 0

    public init(channel: any WUSPTransferStreamChannel, directory: URL,
                fileManager: FileManager = .default,
                acknowledgementTimeout: Duration = WUSPTransferSessionManager.acknowledgementTimeout,
                maximumRetries: Int = WUSPTransferSessionManager.maximumRetries) {
        self.channel = channel
        self.directory = directory.standardizedFileURL
        self.fileManager = fileManager
        self.acknowledgementTimeout = acknowledgementTimeout
        self.maximumRetries = max(1, maximumRetries)
    }

    /// Starts a Go-compatible Upload or Download session and returns the
    /// control-channel result that carries the stream session ID.
    public func begin(_ request: WUSPWireRequest) async throws -> WUSPWireResponse {
        guard request.id > 0, let transfer = request.transfer,
              request.method == .upload || request.method == .download else {
            throw WUSPTransferSessionError.invalidRequest
        }
        guard sessions.count < Self.maximumConcurrentSessions else {
            throw WUSPTransferSessionError.tooManySessions
        }
        try prepareDirectory()

        let filename = try Self.filename(for: transfer, method: request.method)
        let fileURL = directory.appendingPathComponent(filename, isDirectory: false)
        let sessionID = Self.newSessionID(avoiding: Set(sessions.keys))
        var result: WUSPTransferResult

        switch request.method {
        case .upload:
            guard !fileManager.fileExists(atPath: fileURL.path) else {
                throw WUSPTransferSessionError.destinationExists
            }
            let size: UInt64
            if let encodedSize = transfer.metadata["size"] {
                guard let parsedSize = UInt64(encodedSize), parsedSize <= Self.maximumTransferBytes else {
                    throw WUSPTransferSessionError.transferTooLarge
                }
                size = parsedSize
            } else {
                size = 0
            }
            try reserve(size)
            let temporaryURL = directory.appendingPathComponent(".\(UUID().uuidString).uploading")
            let descriptor = open(temporaryURL.path,
                                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                                  mode_t(S_IRUSR | S_IWUSR))
            guard descriptor >= 0 else {
                release(size)
                throw WUSPTransferSessionError.fileOperationFailed
            }
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            sessions[sessionID] = Session(
                id: sessionID, requestID: request.id, method: request.method,
                filename: filename, contentType: transfer.contentType,
                fileURL: fileURL, temporaryURL: temporaryURL,
                totalSize: size, reservedBytes: size, fileHandle: handle)
            result = WUSPTransferResult(
                path: transfer.path, uri: fileURL.absoluteString, bytes: 0,
                metadata: [Self.transportKey: "wg-stream",
                           Self.sessionIDKey: String(sessionID),
                           Self.chunkSizeKey: String(Self.chunkSize),
                           Self.destinationKey: fileURL.path])
        case .download:
            guard Self.isRegularFile(fileURL, fileManager: fileManager) else {
                throw WUSPTransferSessionError.sourceUnavailable
            }
            let values = try fileURL.resourceValues(forKeys: [.fileSizeKey])
            guard let size = values.fileSize, size >= 0,
                  UInt64(size) <= Self.maximumTransferBytes else {
                throw WUSPTransferSessionError.transferTooLarge
            }
            try reserve(UInt64(size))
            sessions[sessionID] = Session(
                id: sessionID, requestID: request.id, method: request.method,
                filename: filename, contentType: transfer.contentType,
                fileURL: fileURL, temporaryURL: nil, totalSize: UInt64(size),
                reservedBytes: UInt64(size), nextSequence: 0)
            result = WUSPTransferResult(
                path: transfer.path, uri: fileURL.absoluteString, bytes: UInt64(size),
                metadata: [Self.transportKey: "wg-stream",
                           Self.sessionIDKey: String(sessionID),
                           Self.chunkSizeKey: String(Self.chunkSize),
                           Self.sourceKey: fileURL.path])
        default:
            throw WUSPTransferSessionError.invalidRequest
        }

        Task { [weak self] in
            try? await Task.sleep(for: Self.sessionLifetime)
            await self?.expire(sessionID: sessionID)
        }
        if request.method == .download {
            Task { [weak self] in
                do {
                    try await Task.sleep(for: .milliseconds(25))
                    try await self?.sendDownload(sessionID: sessionID, path: transfer.path)
                } catch {
                    await self?.abort(sessionID: sessionID, reason: error)
                }
            }
        }
        return WUSPWireResponse(id: request.id, method: request.method, transfer: result)
    }

    /// Accepts an authenticated type-8 stream frame. Unknown, expired, or
    /// method-mismatched session frames are ignored without touching files.
    public func receive(_ frame: WUSPTransferStreamFrame) async {
        guard var session = sessions[frame.sessionID],
              session.requestID == frame.requestID,
              session.method == frame.method else { return }

        do {
            switch session.method {
            case .upload:
                try await receiveUpload(frame, session: session)
            case .download:
                if frame.phase == .abort {
                    await abort(sessionID: session.id, reason: WUSPTransferSessionError.remoteAbort)
                    return
                }
                guard frame.phase == .acknowledgement else { return }
                guard frame.acknowledgementSequence <= session.nextSequence else { return }
                session.highestAcknowledgement = max(session.highestAcknowledgement,
                                                      frame.acknowledgementSequence)
                let ready = session.acknowledgementWaiters.keys
                    .filter { $0 <= session.highestAcknowledgement }
                for sequence in ready {
                    session.acknowledgementWaiters.removeValue(forKey: sequence)?
                        .resume(returning: ())
                }
                sessions[session.id] = session
            default:
                return
            }
        } catch {
            await abort(sessionID: frame.sessionID, reason: error)
        }
    }

    public func close() async {
        let active = Array(sessions.keys)
        for id in active { await abort(sessionID: id, reason: WUSPTransferSessionError.closed) }
    }

    private func receiveUpload(_ frame: WUSPTransferStreamFrame,
                               session: Session) async throws {
        var session = session
        switch frame.phase {
        case .open:
            try await sendAcknowledgement(for: session, sequence: 0)
        case .chunk:
            guard frame.data.count <= Self.chunkSize else {
                throw WUSPTransferSessionError.invalidChunk
            }
            guard frame.sequence == session.nextSequence,
                  frame.offset == session.transferred else {
                try await sendAcknowledgement(for: session, sequence: session.nextSequence - 1)
                return
            }
            let newSize = session.transferred.addingReportingOverflow(UInt64(frame.data.count))
            guard !newSize.overflow, newSize.partialValue <= Self.maximumTransferBytes,
                  session.totalSize == 0 || newSize.partialValue <= session.totalSize,
                  let handle = session.fileHandle else {
                throw WUSPTransferSessionError.transferTooLarge
            }
            if newSize.partialValue > session.reservedBytes {
                let additionalBytes = newSize.partialValue - session.reservedBytes
                try reserve(additionalBytes)
                session.reservedBytes += additionalBytes
                sessions[session.id] = session
            }
            try handle.write(contentsOf: frame.data)
            session.transferred = newSize.partialValue
            session.nextSequence &+= 1
            if frame.isFinal { try handle.synchronize() }
            sessions[session.id] = session
            try await sendAcknowledgement(for: session, sequence: frame.sequence,
                                          final: frame.isFinal)
        case .complete:
            guard frame.offset == session.transferred,
                  session.totalSize == 0 || session.transferred == session.totalSize,
                  let temporaryURL = session.temporaryURL else {
                throw WUSPTransferSessionError.incompleteTransfer
            }
            try session.fileHandle?.synchronize()
            try session.fileHandle?.close()
            session.fileHandle = nil
            sessions[session.id] = nil
            release(session.reservedBytes)
            do {
                try fileManager.moveItem(at: temporaryURL, to: session.fileURL)
            } catch {
                try? fileManager.removeItem(at: temporaryURL)
                throw WUSPTransferSessionError.destinationExists
            }
            try await channel.sendWUSPTransferStreamFrame(WUSPTransferStreamFrame(
                sessionID: session.id, requestID: session.requestID, method: session.method,
                phase: .complete, acknowledgementSequence: session.nextSequence - 1,
                offset: session.transferred, totalSize: session.transferred,
                metadata: [Self.destinationKey: session.fileURL.path], isFinal: true))
        case .abort:
            await abort(sessionID: session.id, reason: WUSPTransferSessionError.remoteAbort)
        case .acknowledgement:
            break
        }
    }

    private func sendAcknowledgement(for session: Session, sequence: UInt32,
                                     final: Bool = false) async throws {
        try await channel.sendWUSPTransferStreamFrame(WUSPTransferStreamFrame(
            sessionID: session.id, requestID: session.requestID, method: session.method,
            phase: .acknowledgement, acknowledgementSequence: sequence,
            offset: session.transferred, totalSize: session.totalSize, isFinal: final))
    }

    private func sendDownload(sessionID: UInt64, path: String) async throws {
        guard let session = sessions[sessionID], session.method == .download else { return }
        let descriptor = open(session.fileURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { throw WUSPTransferSessionError.sourceUnavailable }
        var fileStatus = stat()
        guard fstat(descriptor, &fileStatus) == 0,
              (fileStatus.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            _ = Darwin.close(descriptor)
            throw WUSPTransferSessionError.sourceUnavailable
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        try await channel.sendWUSPTransferStreamFrame(WUSPTransferStreamFrame(
            sessionID: session.id, requestID: session.requestID, method: session.method,
            phase: .open, totalSize: session.totalSize, path: path,
            filename: session.filename, contentType: session.contentType))

        var offset: UInt64 = 0
        var sequence: UInt32 = 1
        while offset < session.totalSize {
            guard let data = try handle.read(upToCount: Self.chunkSize), !data.isEmpty else {
                throw WUSPTransferSessionError.incompleteTransfer
            }
            let end = offset + UInt64(data.count)
            let frame = WUSPTransferStreamFrame(
                sessionID: session.id, requestID: session.requestID, method: session.method,
                phase: .chunk, sequence: sequence, offset: offset,
                totalSize: session.totalSize, data: data, isFinal: end == session.totalSize)
            guard var activeSession = sessions[session.id] else {
                throw WUSPTransferSessionError.closed
            }
            activeSession.nextSequence = sequence
            sessions[session.id] = activeSession
            var acknowledged = false
            for _ in 0..<maximumRetries {
                try await channel.sendWUSPTransferStreamFrame(frame)
                do {
                    try await waitForAcknowledgement(sessionID: session.id, sequence: sequence)
                    acknowledged = true
                    break
                } catch WUSPTransferSessionError.acknowledgementTimedOut {
                    continue
                }
            }
            guard acknowledged else { throw WUSPTransferSessionError.acknowledgementTimedOut }
            offset = end
            sequence &+= 1
        }
        try await channel.sendWUSPTransferStreamFrame(WUSPTransferStreamFrame(
            sessionID: session.id, requestID: session.requestID, method: session.method,
            phase: .complete, acknowledgementSequence: sequence - 1,
            offset: offset, totalSize: session.totalSize,
            metadata: [Self.sourceKey: session.fileURL.path], isFinal: true))
        sessions[session.id] = nil
        release(session.reservedBytes)
    }

    private func waitForAcknowledgement(sessionID: UInt64, sequence: UInt32) async throws {
        if let session = sessions[sessionID], session.highestAcknowledgement >= sequence { return }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            guard var session = sessions[sessionID] else {
                continuation.resume(throwing: WUSPTransferSessionError.closed)
                return
            }
            session.acknowledgementWaiters[sequence] = continuation
            sessions[sessionID] = session
            let timeout = acknowledgementTimeout
            Task { [weak self] in
                try? await Task.sleep(for: timeout)
                await self?.expireAcknowledgement(sessionID: sessionID, sequence: sequence)
            }
        }
    }

    private func expireAcknowledgement(sessionID: UInt64, sequence: UInt32) {
        guard var session = sessions[sessionID],
              let waiter = session.acknowledgementWaiters.removeValue(forKey: sequence) else { return }
        sessions[sessionID] = session
        waiter.resume(throwing: WUSPTransferSessionError.acknowledgementTimedOut)
    }

    private func expire(sessionID: UInt64) async {
        await abort(sessionID: sessionID, reason: WUSPTransferSessionError.expired)
    }

    private func abort(sessionID: UInt64, reason: Error) async {
        guard let session = sessions.removeValue(forKey: sessionID) else { return }
        release(session.reservedBytes)
        try? session.fileHandle?.close()
        if let temporaryURL = session.temporaryURL { try? fileManager.removeItem(at: temporaryURL) }
        for waiter in session.acknowledgementWaiters.values {
            waiter.resume(throwing: reason)
        }
        try? await channel.sendWUSPTransferStreamFrame(WUSPTransferStreamFrame(
            sessionID: session.id, requestID: session.requestID, method: session.method,
            phase: .abort, offset: session.transferred, totalSize: session.totalSize,
            metadata: ["error": String(describing: reason)]))
    }

    private func prepareDirectory() throws {
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true,
                                       attributes: [.posixPermissions: 0o700])
        let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw WUSPTransferSessionError.invalidDirectory
        }
        defer { _ = Darwin.close(descriptor) }
        guard fchmod(descriptor, mode_t(S_IRWXU)) == 0 else {
            throw WUSPTransferSessionError.invalidDirectory
        }
    }

    private func reserve(_ bytes: UInt64) throws {
        let total = reservedTransferBytes.addingReportingOverflow(bytes)
        guard !total.overflow, total.partialValue <= Self.maximumTransferBytes else {
            throw WUSPTransferSessionError.transferTooLarge
        }
        reservedTransferBytes = total.partialValue
    }

    private func release(_ bytes: UInt64) {
        reservedTransferBytes -= min(reservedTransferBytes, bytes)
    }

    private static func isRegularFile(_ url: URL, fileManager: FileManager) -> Bool {
        guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]) else {
            return false
        }
        return values.isRegularFile == true && values.isSymbolicLink != true
    }

    private static func filename(for transfer: WUSPTransferRequest,
                                 method: WUSPMethod) throws -> String {
        let key = method == .upload ? destinationKey : sourceKey
        let candidates = [transfer.filename, transfer.metadata[key],
                          transfer.metadata[method == .upload ? sourceKey : destinationKey],
                          transfer.uri, transfer.path]
        for candidate in candidates {
            guard let candidate, !candidate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                continue
            }
            let value = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
            let decoded = URL(string: value).flatMap { url -> String? in
                guard url.scheme != nil else { return nil }
                return url.lastPathComponent.removingPercentEncoding
            } ?? value
            let name = URL(fileURLWithPath: decoded).lastPathComponent
            guard name != ".", name != "..", !name.isEmpty,
                  name.utf8.count <= 180,
                  !name.contains("/") && !name.contains("\\"),
                  name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw WUSPTransferSessionError.invalidFilename
            }
            return name
        }
        throw WUSPTransferSessionError.invalidFilename
    }

    private static func newSessionID(avoiding existing: Set<UInt64>) -> UInt64 {
        var value: UInt64
        repeat { value = UInt64.random(in: 1...UInt64.max) }
        while existing.contains(value)
        return value
    }
}

public enum WUSPTransferSessionError: Error, Equatable {
    case invalidRequest
    case tooManySessions
    case invalidDirectory
    case invalidFilename
    case destinationExists
    case sourceUnavailable
    case fileOperationFailed
    case invalidChunk
    case transferTooLarge
    case incompleteTransfer
    case acknowledgementTimedOut
    case remoteAbort
    case expired
    case closed
}
