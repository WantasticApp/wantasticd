import CryptoKit
import Foundation

/// Native X25519 key operations used by WireGuard's Noise IK handshake.
/// CryptoKit performs the scalar clamping required by RFC 7748 as part of
/// X25519; public keys and shared secrets are kept in their 32-byte wire form.
public struct WireGuardKeyAgreement: Sendable {
    private let privateKey: Curve25519.KeyAgreement.PrivateKey

    public var publicKey: Data { privateKey.publicKey.rawRepresentation }

    public init(privateKey rawRepresentation: Data) throws {
        guard rawRepresentation.count == 32 else { throw WireGuardKeyError.invalidPrivateKey }
        do {
            self.privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
        } catch {
            throw WireGuardKeyError.invalidPrivateKey
        }
    }

    private init(privateKey: Curve25519.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
    }

    public init(base64PrivateKey: String) throws {
        guard let data = Data(base64Encoded: base64PrivateKey), data.count == 32 else {
            throw WireGuardKeyError.invalidPrivateKey
        }
        try self.init(privateKey: data)
    }

    public static func generate() -> WireGuardKeyAgreement {
        WireGuardKeyAgreement(privateKey: Curve25519.KeyAgreement.PrivateKey())
    }

    public func sharedSecret(with peerPublicKey: Data) throws -> Data {
        guard peerPublicKey.count == 32 else { throw WireGuardKeyError.invalidPublicKey }
        do {
            let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            return secret.withUnsafeBytes { Data($0) }
        } catch {
            // X25519 rejects low-order public keys, which would otherwise
            // produce the all-zero secret and invalidate WireGuard's DH step.
            throw WireGuardKeyError.invalidPublicKey
        }
    }

    public var base64PrivateKey: String { privateKey.rawRepresentation.base64EncodedString() }
}

public enum WireGuardKeyError: Error, Equatable {
    case invalidPrivateKey
    case invalidPublicKey
}
