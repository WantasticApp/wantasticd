import Foundation

struct PortalHTTPResponse: @unchecked Sendable {
    let data: Data
    let response: HTTPURLResponse
}

enum PortalHTTPError: Error {
    case invalidResponse
    case responseTooLarge
    case rejectedRedirect
}

/// Same-origin HTTPS URLSession transport that caps response memory while the
/// body is arriving (not after URLSession has buffered the whole response).
final class PortalHTTPTransport: NSObject, URLSessionDataDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private struct Pending {
        let limit: Int
        let continuation: CheckedContinuation<PortalHTTPResponse, Error>
        var data = Data()
        var response: HTTPURLResponse?
        var error: Error?
    }

    private let origin: URL
    private let lock = NSLock()
    private var pending: [Int: Pending] = [:]
    private var session: URLSession!

    init(origin: URL, configuration: URLSessionConfiguration = .ephemeral) {
        self.origin = origin
        super.init()
        configuration.httpMaximumConnectionsPerHost = 4
        session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }

    func execute(_ request: URLRequest, maxBytes: Int) async throws -> PortalHTTPResponse {
        try await withCheckedThrowingContinuation { continuation in
            let task = session.dataTask(with: request)
            lock.lock()
            pending[task.taskIdentifier] = Pending(limit: maxBytes, continuation: continuation)
            lock.unlock()
            task.resume()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        guard Self.matchesOrigin(request.url, origin: origin) else {
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse,
              Self.matchesOrigin(http.url, origin: origin) else {
            setError(PortalHTTPError.invalidResponse, taskID: dataTask.taskIdentifier)
            completionHandler(.cancel)
            return
        }
        lock.lock()
        if var state = pending[dataTask.taskIdentifier] {
            if http.expectedContentLength > Int64(state.limit) {
                state.error = PortalHTTPError.responseTooLarge
            } else {
                state.response = http
            }
            pending[dataTask.taskIdentifier] = state
        }
        let oversized = pending[dataTask.taskIdentifier]?.error != nil
        lock.unlock()
        completionHandler(oversized ? .cancel : .allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        if var state = pending[dataTask.taskIdentifier] {
            if data.count > state.limit - state.data.count {
                state.error = PortalHTTPError.responseTooLarge
            } else {
                state.data.append(data)
            }
            pending[dataTask.taskIdentifier] = state
        }
        let oversized = pending[dataTask.taskIdentifier]?.error != nil
        lock.unlock()
        if oversized { dataTask.cancel() }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        let state = pending.removeValue(forKey: task.taskIdentifier)
        lock.unlock()
        guard let state else { return }
        if let stateError = state.error {
            state.continuation.resume(throwing: stateError)
        } else if let error {
            state.continuation.resume(throwing: error)
        } else if let response = state.response {
            state.continuation.resume(returning: PortalHTTPResponse(data: state.data, response: response))
        } else {
            state.continuation.resume(throwing: PortalHTTPError.invalidResponse)
        }
    }

    private func setError(_ error: Error, taskID: Int) {
        lock.lock()
        if var state = pending[taskID] {
            state.error = error
            pending[taskID] = state
        }
        lock.unlock()
    }

    static func matchesOrigin(_ candidate: URL?, origin: URL) -> Bool {
        guard let candidate,
              candidate.scheme?.lowercased() == origin.scheme?.lowercased(),
              candidate.host?.lowercased() == origin.host?.lowercased(),
              effectivePort(candidate) == effectivePort(origin) else { return false }
        return true
    }

    private static func effectivePort(_ url: URL) -> Int? {
        if let port = url.port { return port }
        return switch url.scheme?.lowercased() {
        case "https", "wss": 443
        case "http", "ws": 80
        default: nil
        }
    }
}
