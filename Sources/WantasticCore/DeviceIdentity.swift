import CryptoKit
import Foundation
import IOKit

public enum DeviceIdentity {
    /// Matches wantasticd's macOS machine-id fingerprint algorithm: lowercase
    /// IOPlatformUUID, then HMAC-SHA256 using the client protocol signing key.
    /// The hardware identifier itself is never persisted or sent.
    public static func hashedPlatformIdentifier() throws -> String {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != IO_OBJECT_NULL else { throw DeviceIdentityError.unavailable }
        defer { IOObjectRelease(service) }
        guard let value = IORegistryEntryCreateCFProperty(
            service,
            "IOPlatformUUID" as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() as? String else {
            throw DeviceIdentityError.unavailable
        }
        return hashedIdentifier(value)
    }

    static func hashedIdentifier(_ identifier: String) -> String {
        let normalized = Data(identifier.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().utf8)
        let signingKey = SymmetricKey(data: Data("wantastic_cipher_v_1_0_0".utf8))
        let digest = HMAC<SHA256>.authenticationCode(for: normalized, using: signingKey)
        return Data(digest).map { String(format: "%02x", $0) }.joined()
    }
}

public enum DeviceIdentityError: Error, Equatable {
    case unavailable
}
