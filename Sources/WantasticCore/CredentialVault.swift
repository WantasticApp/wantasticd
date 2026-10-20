import Foundation
import Security

/// Stores bearer credentials in the macOS Keychain rather than app preferences
/// or files. Values are scoped by service and account name.
public protocol CredentialPersistence: Sendable {
    func read(account: String) throws -> Data?
    func write(_ data: Data, account: String) throws
    func delete(account: String) throws
}

public struct CredentialVault: CredentialPersistence, Sendable {
    private let service: String
    private let accessGroup: String?

    public init(service: String = "app.wantastic.desktop", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup ??
            (Bundle.main.object(forInfoDictionaryKey: "WantasticKeychainAccessGroup") as? String)
    }

    public func read(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError(status: status)
        }
        return data
    }

    public func write(_ data: Data, account: String) throws {
        var query = baseQuery(account: account)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let attributes = [kSecValueData as String: data]
            let updateStatus = SecItemUpdate(baseQuery(account: account) as CFDictionary, attributes as CFDictionary)
            guard updateStatus == errSecSuccess else { throw KeychainError(status: updateStatus) }
        } else if status != errSecSuccess {
            throw KeychainError(status: status)
        }
    }

    public func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError(status: status)
        }
    }

    private func baseQuery(account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }
}

/// Keeps registration serialization and account scoping out of the SwiftUI
/// layer, while allowing the persistence boundary to be exercised with a
/// deterministic test store.
public struct RegisteredDeviceStore: Sendable {
    private let credentials: any CredentialPersistence

    public init(credentials: any CredentialPersistence = CredentialVault()) {
        self.credentials = credentials
    }

    public func load(consoleHost: String) throws -> RegisteredDevice? {
        guard let data = try credentials.read(account: account(consoleHost: consoleHost)) else { return nil }
        do {
            return try JSONDecoder().decode(RegisteredDevice.self, from: data)
        } catch {
            throw RegisteredDeviceStoreError.invalidStoredData
        }
    }

    public func save(_ device: RegisteredDevice, consoleHost: String) throws {
        let data = try JSONEncoder().encode(device)
        try credentials.write(data, account: account(consoleHost: consoleHost))
    }

    public func remove(consoleHost: String) throws {
        try credentials.delete(account: account(consoleHost: consoleHost))
    }

    private func account(consoleHost: String) throws -> String {
        let host = consoleHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !host.isEmpty, !host.contains("/"), !host.contains("@") else {
            throw RegisteredDeviceStoreError.invalidConsoleHost
        }
        return "registered-device:\(host)"
    }
}

/// Stores a manually imported tunnel configuration separately from the
/// account-backed registration so switching setup methods never overwrites a
/// console session token or the other configuration's private key.
public struct ManualWireGuardConfigurationStore: Sendable {
    private let credentials: any CredentialPersistence

    public init(credentials: any CredentialPersistence = CredentialVault()) {
        self.credentials = credentials
    }

    public func load(consoleHost: String) throws -> WireGuardConfiguration? {
        guard let data = try credentials.read(account: account(consoleHost: consoleHost)) else { return nil }
        do { return try JSONDecoder().decode(WireGuardConfiguration.self, from: data) }
        catch { throw RegisteredDeviceStoreError.invalidStoredData }
    }

    public func save(_ configuration: WireGuardConfiguration, consoleHost: String) throws {
        try credentials.write(JSONEncoder().encode(configuration), account: account(consoleHost: consoleHost))
    }

    public func remove(consoleHost: String) throws {
        try credentials.delete(account: account(consoleHost: consoleHost))
    }

    private func account(consoleHost: String) throws -> String {
        let host = consoleHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !host.isEmpty, !host.contains("/"), !host.contains("@"), !host.contains(":"),
              !host.contains("\\") else {
            throw RegisteredDeviceStoreError.invalidConsoleHost
        }
        return "manual-wireguard:\(host)"
    }
}

public enum RegisteredDeviceStoreError: Error, Equatable {
    case invalidConsoleHost
    case invalidStoredData
}

public struct KeychainError: Error, Equatable, Sendable {
    public let status: OSStatus
    public init(status: OSStatus) { self.status = status }
}
