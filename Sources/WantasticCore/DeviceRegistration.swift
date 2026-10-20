import CryptoKit
import Foundation

public struct RegisteredDevice: Codable, Equatable, Sendable {
    public let configuration: WireGuardConfiguration
    public let sessionToken: String
    public let serverURL: String?
    public let handoffURL: URL?
}

public enum DeviceRegistrationError: LocalizedError, Equatable {
    case invalidInput
    case invalidResponse
    case rejected(Int)
    case deviceLimitReached
    case decryptionFailed

    public var errorDescription: String? {
        switch self {
        case .invalidInput: "The sign-in details are invalid. Sign in again."
        case .invalidResponse: "The console returned an invalid device configuration."
        case .rejected(let status): "Device registration failed (HTTP \(status))."
        case .deviceLimitReached: "Your account has reached its device limit."
        case .decryptionFailed: "The device configuration could not be securely opened."
        }
    }
}

/// Registers the authenticated macOS device and decrypts the WireGuard config
/// using the same nonce/key construction as wantasticd. Secrets are returned
/// only in memory for the caller to place in Keychain.
public final class DeviceRegistrationClient: @unchecked Sendable {
    private let baseURL: URL
    private let transport: PortalHTTPTransport
    private let nonceGenerator: @Sendable () -> UInt64

    public convenience init(baseURL: URL) throws {
        try self.init(baseURL: baseURL, transport: PortalHTTPTransport(origin: baseURL))
    }

    init(baseURL: URL, transport: PortalHTTPTransport,
         nonceGenerator: @escaping @Sendable () -> UInt64 = { UInt64.random(in: 1...UInt64.max) }) throws {
        guard baseURL.scheme?.lowercased() == "https", let host = baseURL.host else {
            throw DeviceAuthorizationError.invalidPortalURL
        }
        self.nonceGenerator = nonceGenerator
        self.baseURL = baseURL
        self.transport = transport
        guard !host.isEmpty else { throw DeviceAuthorizationError.invalidPortalURL }
    }

    public func register(accessToken: String, deviceID: String) async throws -> RegisteredDevice {
        guard !accessToken.isEmpty, deviceID.count == 64,
              deviceID.allSatisfy(\.isHexDigit),
              let url = URL(string: "/api/agent/credentials", relativeTo: baseURL)?.absoluteURL else {
            throw DeviceRegistrationError.invalidInput
        }
        let nonce = nonceGenerator()
        guard nonce != 0 else { throw DeviceRegistrationError.invalidInput }
        let payload = RegistrationPayload(
            hostname: ProcessInfo.processInfo.hostName,
            os: "darwin",
            arch: Self.architecture,
            nonce: nonce
        )
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 20
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        let timestamp = String(Int(Date().timeIntervalSince1970))
        request.setValue(timestamp, forHTTPHeaderField: "x-wantastic-ts")
        request.setValue(deviceID, forHTTPHeaderField: "x-wantastic-device")
        request.setValue(Self.signature(timestamp: timestamp, deviceID: deviceID), forHTTPHeaderField: "x-wantastic-sig")
        request.httpBody = try JSONEncoder().encode(payload)

        let received = try await transport.execute(request, maxBytes: 1_048_576)
        let data = received.data
        let http = received.response
        guard http.statusCode == 200 || http.statusCode == 201 else {
            if http.statusCode == 403 { throw DeviceRegistrationError.deviceLimitReached }
            throw DeviceRegistrationError.rejected(http.statusCode)
        }
        let reply: RegistrationReply
        do { reply = try JSONDecoder().decode(RegistrationReply.self, from: data) }
        catch { throw DeviceRegistrationError.invalidResponse }
        guard !reply.encryptedConfig.isEmpty, !reply.token.isEmpty else {
            throw DeviceRegistrationError.invalidResponse
        }
        let plaintext = try Self.decrypt(reply.encryptedConfig, token: accessToken, nonce: nonce)
        guard let text = String(data: plaintext, encoding: .utf8) else {
            throw DeviceRegistrationError.invalidResponse
        }
        let configuration = try WireGuardConfiguration.parse(text)
        let handoffURL = reply.handoffURL.flatMap(URL.init(string:))
        if let handoffURL,
           !PortalHTTPTransport.matchesOrigin(handoffURL, origin: baseURL) {
            throw DeviceRegistrationError.invalidResponse
        }
        return RegisteredDevice(
            configuration: configuration,
            sessionToken: reply.token,
            serverURL: reply.serverURL,
            handoffURL: handoffURL
        )
    }

    private static var architecture: String {
        #if arch(arm64)
        "arm64"
        #elseif arch(x86_64)
        "amd64"
        #else
        "unknown"
        #endif
    }

    static func signature(timestamp: String, deviceID: String) -> String {
        let key = SymmetricKey(data: Data("wantastic_cipher_v_1_0_0".utf8))
        let data = Data("\(timestamp):\(deviceID)".utf8)
        return HMAC<SHA256>.authenticationCode(for: data, using: key)
            .map { String(format: "%02x", $0) }.joined()
    }

    static func decrypt(_ encrypted: Data, token: String, nonce: UInt64) throws -> Data {
        guard encrypted.count > 16 else { throw DeviceRegistrationError.decryptionFailed }
        let tokenDigest = SHA256.hash(data: Data(token.utf8))
        let key = SymmetricKey(data: Data(tokenDigest))
        var littleEndianNonce = nonce.littleEndian
        var nonceData = Data(repeating: 0, count: 12)
        withUnsafeBytes(of: &littleEndianNonce) { nonceData.replaceSubrange(0..<8, with: $0) }
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: ChaChaPoly.Nonce(data: nonceData),
                ciphertext: encrypted.dropLast(16),
                tag: encrypted.suffix(16)
            )
            return try ChaChaPoly.open(box, using: key)
        } catch {
            throw DeviceRegistrationError.decryptionFailed
        }
    }
}

private struct RegistrationPayload: Encodable {
    let hostname: String
    let os: String
    let arch: String
    let nonce: UInt64
}

private struct RegistrationReply: Decodable {
    let encryptedConfig: Data
    let token: String
    let serverURL: String?
    let handoffURL: String?

    enum CodingKeys: String, CodingKey {
        case encryptedConfig = "encrypted_config"
        case token
        case serverURL = "server_url"
        case handoffURL = "handoff_url"
    }
}
