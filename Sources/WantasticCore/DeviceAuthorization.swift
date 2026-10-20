import Foundation

public struct DeviceAuthorization: Decodable, Equatable, Sendable {
    public let deviceCode: String
    public let userCode: String
    public let verificationURI: URL
    public let verificationURIComplete: URL?
    public let expiresIn: Int
    public let interval: Int

    enum CodingKeys: String, CodingKey {
        case deviceCode = "device_code"
        case userCode = "user_code"
        case verificationURI = "verification_uri"
        case verificationURIComplete = "verification_uri_complete"
        case expiresIn = "expires_in"
        case interval
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        deviceCode = try values.decode(String.self, forKey: .deviceCode)
        userCode = try values.decode(String.self, forKey: .userCode)
        verificationURI = try values.decode(URL.self, forKey: .verificationURI)
        verificationURIComplete = try values.decodeIfPresent(URL.self, forKey: .verificationURIComplete)
        let suppliedExpiry = try values.decodeIfPresent(Int.self, forKey: .expiresIn) ?? 0
        let suppliedInterval = try values.decodeIfPresent(Int.self, forKey: .interval) ?? 0
        expiresIn = suppliedExpiry > 0 ? suppliedExpiry : 300
        interval = suppliedInterval > 0 ? suppliedInterval : 5
    }
}

public enum DeviceAuthorizationError: LocalizedError, Equatable {
    case invalidPortalURL
    case invalidResponse
    case httpStatus(Int)
    case authorizationPending
    case slowDown
    case expired
    case denied(String)
    case server(String)

    public var errorDescription: String? {
        switch self {
        case .invalidPortalURL: "Enter a valid HTTPS Wantastic console address."
        case .invalidResponse: "The console returned an invalid sign-in response."
        case .httpStatus(let status): "Console sign-in failed (HTTP \(status))."
        case .authorizationPending: "Approve the sign-in request in your browser."
        case .slowDown: "Sign-in polling was rate limited."
        case .expired: "This sign-in code expired. Start again to get a new one."
        case .denied(let reason): reason
        case .server(let reason): "Console sign-in failed: \(reason)"
        }
    }
}

/// RFC 8628 device authorization for the Wantastic console. The client accepts
/// only HTTPS console endpoints, bounds response sizes, and never persists the
/// short-lived device code.
public final class DeviceAuthorizationClient: @unchecked Sendable {
    private let baseURL: URL
    private let clientID: String
    private let transport: PortalHTTPTransport
    private let maxResponseBytes = 64 * 1024

    public convenience init(baseURL: URL, clientID: String) throws {
        try self.init(baseURL: baseURL, clientID: clientID, transport: PortalHTTPTransport(origin: baseURL))
    }

    init(baseURL: URL, clientID: String, transport: PortalHTTPTransport) throws {
        guard baseURL.scheme?.lowercased() == "https", baseURL.host != nil,
              !clientID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw DeviceAuthorizationError.invalidPortalURL
        }
        self.baseURL = baseURL
        self.clientID = clientID
        self.transport = transport
    }

    public func begin(deviceID: String? = nil) async throws -> DeviceAuthorization {
        var fields = ["client_id": clientID, "scope": "openid profile email"]
        if let deviceID, !deviceID.isEmpty { fields["device_id"] = deviceID }
        let request = try formRequest(path: "/oauth/device/code", fields: fields)
        let (data, response) = try await perform(request)
        guard response.statusCode == 200 else { throw DeviceAuthorizationError.httpStatus(response.statusCode) }
        let decoded: DeviceAuthorization
        do { decoded = try JSONDecoder().decode(DeviceAuthorization.self, from: data) }
        catch { throw DeviceAuthorizationError.invalidResponse }
        guard !decoded.deviceCode.isEmpty, !decoded.userCode.isEmpty,
              decoded.expiresIn > 0,
              decoded.verificationURI.scheme?.lowercased() == "https",
              PortalHTTPTransport.matchesOrigin(decoded.verificationURI, origin: baseURL) else {
            throw DeviceAuthorizationError.invalidResponse
        }
        if let complete = decoded.verificationURIComplete,
           !PortalHTTPTransport.matchesOrigin(complete, origin: baseURL) {
            throw DeviceAuthorizationError.invalidResponse
        }
        return decoded
    }

    /// Poll once. Callers should wait at least `interval` between calls, adding
    /// five seconds after `.slowDown`, and stop at `expiresIn`.
    public func poll(deviceCode: String) async throws -> String {
        let request = try formRequest(path: "/oauth/token", fields: [
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": deviceCode,
            "client_id": clientID,
        ])
        let (data, response) = try await perform(request)
        let payload: TokenPayload
        do { payload = try JSONDecoder().decode(TokenPayload.self, from: data) }
        catch { throw DeviceAuthorizationError.invalidResponse }
        if response.statusCode == 200, let token = payload.accessToken, !token.isEmpty { return token }
        switch payload.error {
        case "authorization_pending": throw DeviceAuthorizationError.authorizationPending
        case "slow_down": throw DeviceAuthorizationError.slowDown
        case "expired_token": throw DeviceAuthorizationError.expired
        case "access_denied": throw DeviceAuthorizationError.denied(payload.errorDescription ?? "Authorization was denied")
        case .some(let error): throw DeviceAuthorizationError.server("\(error): \(payload.errorDescription ?? "")")
        case .none: throw DeviceAuthorizationError.httpStatus(response.statusCode)
        }
    }

    private func formRequest(path: String, fields: [String: String]) throws -> URLRequest {
        guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL,
              PortalHTTPTransport.matchesOrigin(url, origin: baseURL) else {
            throw DeviceAuthorizationError.invalidPortalURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var components = URLComponents()
        components.queryItems = fields.keys.sorted().map { URLQueryItem(name: $0, value: fields[$0]) }
        request.httpBody = components.percentEncodedQuery?.data(using: .utf8)
        request.timeoutInterval = 15
        return request
    }

    private func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let response = try await transport.execute(request, maxBytes: maxResponseBytes)
        return (response.data, response.response)
    }
}

private struct TokenPayload: Decodable {
    let accessToken: String?
    let error: String?
    let errorDescription: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case error
        case errorDescription = "error_description"
    }
}
