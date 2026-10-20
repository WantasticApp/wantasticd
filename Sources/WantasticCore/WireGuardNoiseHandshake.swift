import CryptoKit
import Foundation

public struct WireGuardInitiationPayload: Equatable, Sendable {
    public let ephemeralPublicKey: Data
    public let encryptedStaticKey: Data
    public let encryptedTimestamp: Data
}

public struct WireGuardResponsePayload: Equatable, Sendable {
    public let ephemeralPublicKey: Data
    public let encryptedEmpty: Data
}

public struct WireGuardSessionKeys: Equatable, Sendable {
    public let send: Data
    public let receive: Data
}

public enum WireGuardHandshakeRole: Equatable, Sendable {
    case initiator
    case responder
}

public enum WireGuardHandshakeError: Error, Equatable {
    case invalidConfiguration
    case invalidState
    case malformedMessage
    case authenticationFailed
}

/// Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s transcript used by WireGuard.
/// This produces/consumes the encrypted handshake fields only. Message indexes,
/// MAC1/MAC2, cookie replies, replay/flood policy, and UDP packet I/O belong to
/// the transport layer and are deliberately not implied by this type.
public struct WireGuardNoiseHandshake: Sendable {
    private enum State: Equatable, Sendable {
        case ready
        case initiationCreated
        case initiationConsumed
        case responseCreated
        case complete
    }

    private static let construction = Data("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8)
    private static let identifier = Data("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8)
    private static let initialChainKey = WireGuardKDF.blake2s(construction)
    private static let initialHash = WireGuardKDF.blake2s(initialChainKey + identifier)
    private static let zeroNonceData = Data(repeating: 0, count: 12)

    private let role: WireGuardHandshakeRole
    private let localKey: WireGuardKeyAgreement
    private let remoteStaticKey: Data
    private let presharedKey: Data
    private var state: State = .ready
    private var chainKey = Data()
    private var hash = Data()
    private var localEphemeral: WireGuardKeyAgreement?
    private var remoteEphemeral: Data?

    public init(role: WireGuardHandshakeRole, localPrivateKey: Data,
                remoteStaticPublicKey: Data, presharedKey: Data = Data(repeating: 0, count: 32)) throws {
        guard remoteStaticPublicKey.count == 32, presharedKey.count == 32 else {
            throw WireGuardHandshakeError.invalidConfiguration
        }
        self.role = role
        do {
            localKey = try WireGuardKeyAgreement(privateKey: localPrivateKey)
            _ = try localKey.sharedSecret(with: remoteStaticPublicKey)
        } catch {
            throw WireGuardHandshakeError.invalidConfiguration
        }
        self.remoteStaticKey = remoteStaticPublicKey
        self.presharedKey = presharedKey
    }

    public mutating func createInitiation(timestamp: Data) throws -> WireGuardInitiationPayload {
        guard role == .initiator, state == .ready, timestamp.count == 12 else {
            throw role == .initiator && state == .ready ? WireGuardHandshakeError.malformedMessage : .invalidState
        }

        var currentChain = Self.initialChainKey
        var currentHash = mixHash(Self.initialHash, remoteStaticKey)
        let ephemeral = WireGuardKeyAgreement.generate()
        let ephemeralPublic = ephemeral.publicKey
        currentChain = mixKey(currentChain, ephemeralPublic)
        currentHash = mixHash(currentHash, ephemeralPublic)

        let ephemeralStatic = try ephemeral.sharedSecret(with: remoteStaticKey)
        let staticMaterial = WireGuardKDF.derive2(chainingKey: currentChain, input: ephemeralStatic)
        currentChain = staticMaterial[0]
        let encryptedStatic = try seal(localKey.publicKey, key: staticMaterial[1], authenticating: currentHash)
        currentHash = mixHash(currentHash, encryptedStatic)

        let staticStatic = try localKey.sharedSecret(with: remoteStaticKey)
        let timestampMaterial = WireGuardKDF.derive2(chainingKey: currentChain, input: staticStatic)
        currentChain = timestampMaterial[0]
        let encryptedTimestamp = try seal(timestamp, key: timestampMaterial[1], authenticating: currentHash)
        currentHash = mixHash(currentHash, encryptedTimestamp)

        chainKey = currentChain
        hash = currentHash
        localEphemeral = ephemeral
        state = .initiationCreated
        return WireGuardInitiationPayload(ephemeralPublicKey: ephemeralPublic,
                                          encryptedStaticKey: encryptedStatic,
                                          encryptedTimestamp: encryptedTimestamp)
    }

    public mutating func consumeInitiation(_ payload: WireGuardInitiationPayload) throws {
        guard role == .responder, state == .ready else { throw WireGuardHandshakeError.invalidState }
        guard payload.ephemeralPublicKey.count == 32, payload.encryptedStaticKey.count == 48,
              payload.encryptedTimestamp.count == 28 else { throw WireGuardHandshakeError.malformedMessage }

        var currentHash = mixHash(Self.initialHash, localKey.publicKey)
        currentHash = mixHash(currentHash, payload.ephemeralPublicKey)
        var currentChain = mixKey(Self.initialChainKey, payload.ephemeralPublicKey)

        let ephemeralStatic = try localKey.sharedSecret(with: payload.ephemeralPublicKey)
        let staticMaterial = WireGuardKDF.derive2(chainingKey: currentChain, input: ephemeralStatic)
        currentChain = staticMaterial[0]
        let remoteStatic = try open(payload.encryptedStaticKey, key: staticMaterial[1], authenticating: currentHash)
        guard remoteStatic == remoteStaticKey else { throw WireGuardHandshakeError.authenticationFailed }
        currentHash = mixHash(currentHash, payload.encryptedStaticKey)

        let staticStatic = try localKey.sharedSecret(with: remoteStatic)
        let timestampMaterial = WireGuardKDF.derive2(chainingKey: currentChain, input: staticStatic)
        currentChain = timestampMaterial[0]
        let timestamp = try open(payload.encryptedTimestamp, key: timestampMaterial[1], authenticating: currentHash)
        guard timestamp.count == 12 else { throw WireGuardHandshakeError.authenticationFailed }
        currentHash = mixHash(currentHash, payload.encryptedTimestamp)

        chainKey = currentChain
        hash = currentHash
        remoteEphemeral = payload.ephemeralPublicKey
        state = .initiationConsumed
    }

    public mutating func createResponse() throws -> WireGuardResponsePayload {
        guard role == .responder, state == .initiationConsumed, let remoteEphemeral else {
            throw WireGuardHandshakeError.invalidState
        }

        let ephemeral = WireGuardKeyAgreement.generate()
        let ephemeralPublic = ephemeral.publicKey
        var currentHash = mixHash(hash, ephemeralPublic)
        var currentChain = mixKey(chainKey, ephemeralPublic)

        currentChain = mixKey(currentChain, try ephemeral.sharedSecret(with: remoteEphemeral))
        currentChain = mixKey(currentChain, try ephemeral.sharedSecret(with: remoteStaticKey))

        let pskMaterial = WireGuardKDF.derive3(chainingKey: currentChain, input: presharedKey)
        currentChain = pskMaterial[0]
        currentHash = mixHash(currentHash, pskMaterial[1])
        let encryptedEmpty = try seal(Data(), key: pskMaterial[2], authenticating: currentHash)
        currentHash = mixHash(currentHash, encryptedEmpty)

        chainKey = currentChain
        hash = currentHash
        localEphemeral = ephemeral
        state = .responseCreated
        return WireGuardResponsePayload(ephemeralPublicKey: ephemeralPublic, encryptedEmpty: encryptedEmpty)
    }

    public mutating func consumeResponse(_ payload: WireGuardResponsePayload) throws -> WireGuardSessionKeys {
        guard role == .initiator, state == .initiationCreated, let localEphemeral else {
            throw WireGuardHandshakeError.invalidState
        }
        guard payload.ephemeralPublicKey.count == 32, payload.encryptedEmpty.count == 16 else {
            throw WireGuardHandshakeError.malformedMessage
        }

        var currentHash = mixHash(hash, payload.ephemeralPublicKey)
        var currentChain = mixKey(chainKey, payload.ephemeralPublicKey)
        currentChain = mixKey(currentChain, try localEphemeral.sharedSecret(with: payload.ephemeralPublicKey))
        currentChain = mixKey(currentChain, try localKey.sharedSecret(with: payload.ephemeralPublicKey))

        let pskMaterial = WireGuardKDF.derive3(chainingKey: currentChain, input: presharedKey)
        currentChain = pskMaterial[0]
        currentHash = mixHash(currentHash, pskMaterial[1])
        let plaintext = try open(payload.encryptedEmpty, key: pskMaterial[2], authenticating: currentHash)
        guard plaintext.isEmpty else { throw WireGuardHandshakeError.authenticationFailed }
        currentHash = mixHash(currentHash, payload.encryptedEmpty)
        chainKey = currentChain
        hash = currentHash
        return try finishSession(isInitiator: true)
    }

    public mutating func responderSessionKeys() throws -> WireGuardSessionKeys {
        guard role == .responder, state == .responseCreated else { throw WireGuardHandshakeError.invalidState }
        return try finishSession(isInitiator: false)
    }

    private mutating func finishSession(isInitiator: Bool) throws -> WireGuardSessionKeys {
        guard state == .initiationCreated || state == .responseCreated else {
            throw WireGuardHandshakeError.invalidState
        }
        let keys = WireGuardKDF.derive2(chainingKey: chainKey, input: Data())
        guard keys.count == 2, keys.allSatisfy({ $0.count == 32 }) else {
            throw WireGuardHandshakeError.invalidConfiguration
        }
        chainKey.resetBytes(in: 0..<chainKey.count)
        hash.resetBytes(in: 0..<hash.count)
        localEphemeral = nil
        remoteEphemeral = nil
        state = .complete
        return isInitiator
            ? WireGuardSessionKeys(send: keys[0], receive: keys[1])
            : WireGuardSessionKeys(send: keys[1], receive: keys[0])
    }

    private func mixKey(_ chainingKey: Data, _ input: Data) -> Data {
        WireGuardKDF.derive1(chainingKey: chainingKey, input: input)[0]
    }

    private func mixHash(_ currentHash: Data, _ input: Data) -> Data {
        WireGuardKDF.blake2s(currentHash + input)
    }

    private func seal(_ plaintext: Data, key: Data, authenticating aad: Data) throws -> Data {
        let nonce = try ChaChaPoly.Nonce(data: Self.zeroNonceData)
        let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key), nonce: nonce,
                                      authenticating: aad)
        var result = Data()
        result.append(contentsOf: box.ciphertext)
        result.append(contentsOf: box.tag)
        return result
    }

    private func open(_ ciphertextAndTag: Data, key: Data, authenticating aad: Data) throws -> Data {
        guard ciphertextAndTag.count >= 16 else { throw WireGuardHandshakeError.malformedMessage }
        let split = ciphertextAndTag.count - 16
        let nonce = try ChaChaPoly.Nonce(data: Self.zeroNonceData)
        let ciphertext = Data(ciphertextAndTag.prefix(split))
        let tag = Data(ciphertextAndTag.suffix(16))
        let box = try ChaChaPoly.SealedBox(nonce: nonce,
                                           ciphertext: ciphertext,
                                           tag: tag)
        do {
            return try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: aad)
        } catch {
            throw WireGuardHandshakeError.authenticationFailed
        }
    }
}
