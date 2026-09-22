//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
// MODIFIED in the LogRaker fork of swift-nio-ssh, which adds RSA client
// authentication. Every change is marked `LOGRAKER FORK:` below.
// See FORK.md for the upstream revision and the rebase procedure.
//
//===----------------------------------------------------------------------===//

@preconcurrency import Crypto
// LOGRAKER FORK: `_RSA.Signing` lives in CryptoExtras, not Crypto.
import CryptoExtras
import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An SSH private key.
///
/// This object identifies a single SSH entity, usually a server. It is used as part of the SSH handshake and key exchange process,
/// and is also presented to clients that want to validate that they are communicating with the appropriate server. Clients use
/// this key to sign data in order to validate their identity as part of user auth.
///
/// Users cannot do much with this key other than construct it, but NIO uses it internally.
public struct NIOSSHPrivateKey: Sendable {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: BackingKey

    private init(backingKey: BackingKey) {
        self.backingKey = backingKey
    }

    public init(ed25519Key key: Curve25519.Signing.PrivateKey) {
        self.backingKey = .ed25519(key)
    }

    public init(p256Key key: P256.Signing.PrivateKey) {
        self.backingKey = .ecdsaP256(key)
    }

    public init(p384Key key: P384.Signing.PrivateKey) {
        self.backingKey = .ecdsaP384(key)
    }

    public init(p521Key key: P521.Signing.PrivateKey) {
        self.backingKey = .ecdsaP521(key)
    }

    #if canImport(Darwin)
    public init(secureEnclaveP256Key key: SecureEnclave.P256.Signing.PrivateKey) {
        self.backingKey = .secureEnclaveP256(key)
    }
    #endif

    /// LOGRAKER FORK: Create a private key from an RSA key.
    ///
    /// Signatures are always produced as `rsa-sha2-512`; see
    /// `NIOSSHPublicKey.signatureAlgorithmName`.
    public init(rsaKey key: _RSA.Signing.PrivateKey) {
        self.backingKey = .rsa(key)
    }

    // The algorithms that apply to this host key.
    internal var hostKeyAlgorithms: [Substring] {
        switch self.backingKey {
        case .ed25519:
            return ["ssh-ed25519"]
        case .ecdsaP256:
            return ["ecdsa-sha2-nistp256"]
        case .ecdsaP384:
            return ["ecdsa-sha2-nistp384"]
        case .ecdsaP521:
            return ["ecdsa-sha2-nistp521"]
        // LOGRAKER FORK: only consulted when the key is used as a *host*
        // key. We do not add RSA to the host-key negotiation list, so this
        // is here for completeness rather than because we advertise it.
        case .rsa:
            return ["rsa-sha2-512"]
        #if canImport(Darwin)
        case .secureEnclaveP256:
            return ["ecdsa-sha2-nistp256"]
        #endif
        }
    }
}

extension NIOSSHPrivateKey {
    /// The various key types that can be used with NIOSSH.
    internal enum BackingKey {
        case ed25519(Curve25519.Signing.PrivateKey)
        case ecdsaP256(P256.Signing.PrivateKey)
        case ecdsaP384(P384.Signing.PrivateKey)
        case ecdsaP521(P521.Signing.PrivateKey)
        // LOGRAKER FORK
        case rsa(_RSA.Signing.PrivateKey)

        #if canImport(Darwin)
        case secureEnclaveP256(SecureEnclave.P256.Signing.PrivateKey)
        #endif
    }
}

extension NIOSSHPrivateKey {
    func sign<DigestBytes: Digest>(digest: DigestBytes) throws -> NIOSSHSignature {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        // LOGRAKER FORK: only reachable for RSA host keys, which we never
        // negotiate. Sign the digest we were handed under the hash that
        // actually produced it, so the PKCS#1 DigestInfo stays honest.
        case .rsa(let key):
            let hash: NIOSSHSignature.RSAHash
            switch DigestBytes.byteCount {
            case NIOSSHSignature.RSAHash.sha256.digestByteCount:
                hash = .sha256
            case NIOSSHSignature.RSAHash.sha512.digestByteCount:
                hash = .sha512
            default:
                throw NIOSSHError.unknownSignature(
                    algorithm: "rsa with \(DigestBytes.byteCount)-byte digest"
                )
            }
            let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsa(hash: hash, signature: signature))

        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }

    func sign(_ payload: UserAuthSignablePayload) throws -> NIOSSHSignature {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        // LOGRAKER FORK: `rsa-sha2-512` is the algorithm name we advertise
        // in the userauth request, so SHA-512 is what we must sign under.
        case .rsa(let key):
            let hash = NIOSSHSignature.RSAHash.sha512
            let signature = try hash.sign(payload.bytes.readableBytesView, with: key)
            return NIOSSHSignature(backingSignature: .rsa(hash: hash, signature: signature))
        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }
}

extension NIOSSHPrivateKey {
    /// Obtains the public key for a corresponding private key.
    public var publicKey: NIOSSHPublicKey {
        switch self.backingKey {
        case .ed25519(let privateKey):
            return NIOSSHPublicKey(backingKey: .ed25519(privateKey.publicKey))
        case .ecdsaP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        case .ecdsaP384(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP384(privateKey.publicKey))
        case .ecdsaP521(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP521(privateKey.publicKey))
        // LOGRAKER FORK
        case .rsa(let privateKey):
            return NIOSSHPublicKey(backingKey: .rsa(privateKey.publicKey))
        #if canImport(Darwin)
        case .secureEnclaveP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        #endif
        }
    }
}

// MARK: - LOGRAKER FORK: RSA convenience API
//
// These exist so callers can load RSA keys without importing
// CryptoExtras themselves. Keeping `_RSA` an implementation detail of
// this package means an app links one SSH library rather than an SSH
// library plus somebody else's crypto internals.

/// LOGRAKER FORK: Errors specific to loading an RSA key.
public enum NIOSSHRSAKeyError: Error, Equatable {
    /// The key parsed, but is smaller than `NIOSSHPrivateKey.minimumRSAKeySizeInBits`.
    /// Carries the actual size so callers can say how small it was.
    case keyTooSmall(bits: Int)
}

extension NIOSSHPrivateKey {
    /// LOGRAKER FORK: The smallest RSA key we will load.
    ///
    /// Matches swift-crypto's own floor for its safe initializers.
    /// Anything below this is too weak to accept in 2026, and the
    /// `unsafe*` initializers that would permit it are deliberately not
    /// used here.
    public static let minimumRSAKeySizeInBits = 2048

    /// LOGRAKER FORK: Create a private key from a PEM-encoded RSA key.
    ///
    /// Accepts both PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`, which is
    /// what AWS EC2 hands out) and PKCS#8 (`-----BEGIN PRIVATE KEY-----`).
    /// The PEM must be unencrypted; callers are expected to have dealt
    /// with any passphrase layer already.
    ///
    /// - Throws: ``NIOSSHRSAKeyError/keyTooSmall(bits:)`` if the key parses
    ///   but is under ``minimumRSAKeySizeInBits``, so the caller can report
    ///   the real size rather than a generic parse failure. Other parse
    ///   errors surface as `CryptoKitError`.
    public init(rsaPEMRepresentation pem: String) throws {
        // Parse with the unsafe initializer purely so an undersized key
        // can be reported with its actual bit count. The key is never
        // returned unless it clears the floor below.
        let key = try _RSA.Signing.PrivateKey(unsafePEMRepresentation: pem)
        guard key.keySizeInBits >= Self.minimumRSAKeySizeInBits else {
            throw NIOSSHRSAKeyError.keyTooSmall(bits: key.keySizeInBits)
        }
        self.init(rsaKey: key)
    }

    /// LOGRAKER FORK: Create a private key from raw RSA components.
    ///
    /// This is the shape an OpenSSH-format private key file stores its RSA
    /// keys in. Per `PROTOCOL.key` the on-disk order is n, e, d, iqmp, p, q;
    /// `iqmp` is recomputed from p and q and so is not taken here.
    ///
    /// - Throws: ``NIOSSHRSAKeyError/keyTooSmall(bits:)`` as above.
    public init(
        rsaModulus n: some ContiguousBytes,
        publicExponent e: some ContiguousBytes,
        privateExponent d: some ContiguousBytes,
        prime1 p: some ContiguousBytes,
        prime2 q: some ContiguousBytes
    ) throws {
        let key = try _RSA.Signing.PrivateKey(n: n, e: e, d: d, p: p, q: q)
        guard key.keySizeInBits >= Self.minimumRSAKeySizeInBits else {
            throw NIOSSHRSAKeyError.keyTooSmall(bits: key.keySizeInBits)
        }
        self.init(rsaKey: key)
    }
}
