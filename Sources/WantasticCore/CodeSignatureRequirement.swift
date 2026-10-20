import CryptoKit
import Foundation
import Security

public enum CodeSignatureRequirementError: Error, Equatable {
    case unsignedOrAdHoc
    case signingInformationUnavailable
    case invalidIdentifier
}

/// Builds a peer requirement pinned to this process's actual signing
/// certificate. This supports a locally self-signed development identity
/// without trusting every certificate accepted by the system trust store.
public enum CodeSignatureRequirement {
    public static func pinnedPeer(identifier: String) throws -> String {
        try pinnedPeer(identifiers: [identifier])
    }

    public static func pinnedPeer(identifiers: [String]) throws -> String {
        guard !identifiers.isEmpty,
              identifiers.allSatisfy(isValidIdentifier) else {
            throw CodeSignatureRequirementError.invalidIdentifier
        }

        var code: SecCode?
        let codeStatus = SecCodeCopySelf(SecCSFlags(rawValue: 0), &code)
        guard codeStatus == errSecSuccess, let code else {
            throw CodeSignatureRequirementError.signingInformationUnavailable
        }

        var staticCode: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(code, SecCSFlags(rawValue: 0), &staticCode)
        guard staticStatus == errSecSuccess, let staticCode else {
            throw CodeSignatureRequirementError.signingInformationUnavailable
        }

        var signingInformation: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInformation)
        guard infoStatus == errSecSuccess,
              let signingInformation,
              let certificates = (signingInformation as NSDictionary)
                .object(forKey: kSecCodeInfoCertificates) as? [SecCertificate],
              let leaf = certificates.first else {
            throw CodeSignatureRequirementError.unsignedOrAdHoc
        }

        let certificateData = SecCertificateCopyData(leaf) as Data
        let fingerprint = Insecure.SHA1.hash(data: certificateData)
            .map { String(format: "%02X", $0) }
            .joined()
        return try peerRequirement(identifiers: identifiers, certificateSHA1: fingerprint)
    }

    public static func peerRequirement(identifier: String, certificateSHA1: String) throws -> String {
        try peerRequirement(identifiers: [identifier], certificateSHA1: certificateSHA1)
    }

    public static func peerRequirement(identifiers: [String], certificateSHA1: String) throws -> String {
        guard !identifiers.isEmpty, identifiers.allSatisfy(isValidIdentifier) else {
            throw CodeSignatureRequirementError.invalidIdentifier
        }
        guard certificateSHA1.utf8.count == 40,
              certificateSHA1.utf8.allSatisfy({
                  (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
              }) else {
            throw CodeSignatureRequirementError.signingInformationUnavailable
        }
        return identifiers.map {
            "identifier \"\($0)\" and certificate leaf = H\"\(certificateSHA1)\""
        }.joined(separator: " or ")
    }

    private static func isValidIdentifier(_ identifier: String) -> Bool {
        !identifier.isEmpty && identifier.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) ||
                (48...57).contains($0) || $0 == 46 || $0 == 45
        }
    }
}
