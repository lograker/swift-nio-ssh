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
import Foundation
import NIOCore
import NIOFoundationCompat

/// An SSH public key.
///
/// This object identifies a single SSH server or user. It is used as part of the SSH handshake and key exchange process,
/// is presented to clients that want to validate that they are communicating with the appropriate server, and is also used
/// to validate users.
///
/// This key is not capable of signing, only verifying.
public struct NIOSSHPublicKey: Sendable, Hashable {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: BackingKey

    internal init(backingKey: BackingKey) {
        self.backingKey = backingKey
    }

    /// Create a ``NIOSSHPublicKey`` from the OpenSSH public key string.
    public init(openSSHPublicKey: String) throws {
        // The OpenSSH public key format is like this: "algorithm-id base64-encoded-key comments"
        //
        // We split on spaces, no more than twice. We then check if we know about the algorithm identifier and, if we
        // do, we parse the key.
        var components = ArraySlice(
            openSSHPublicKey.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        )
        guard let keyIdentifier = components.popFirst(), let keyData = components.popFirst() else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "invalid number of sections")
        }
        guard let rawBytes = Data(base64Encoded: String(keyData)) else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "could not base64-decode string")
        }

        var buffer = ByteBufferAllocator().buffer(capacity: rawBytes.count)
        buffer.writeContiguousBytes(rawBytes)
        guard let key = try buffer.readSSHHostKey() else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "incomplete key data")
        }
        guard key.keyPrefix.elementsEqual(keyIdentifier.utf8) else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "inconsistent key type within openssh key format")
        }
        self = key
    }

    /// Encapsulate a ``NIOSSHCertifiedPublicKey`` in a ``NIOSSHPublicKey``.
    ///
    /// This initializer can be used to "wrap" a ``NIOSSHCertifiedPublicKey`` into the interface of ``NIOSSHPublicKey``.
    /// It is typically used in cases where the fact that the key is certified is not relevant.
    public init(_ certifiedKey: NIOSSHCertifiedPublicKey) {
        self.backingKey = .certified(certifiedKey)
    }
}

extension NIOSSHPublicKey {
    /// Verifies that a given `NIOSSHSignature` was created by the holder of the private key associated with this
    /// public key.
    internal func isValidSignature<DigestBytes: Digest>(_ signature: NIOSSHSignature, for digest: DigestBytes) -> Bool {
        switch (self.backingKey, signature.backingSignature) {
        case (.ed25519(let key), .ed25519(let sig)):
            return digest.withUnsafeBytes { digestPtr in
                switch sig {
                case .byteBuffer(let buf):
                    return key.isValidSignature(buf.readableBytesView, for: digestPtr)
                case .data(let d):
                    return key.isValidSignature(d, for: digestPtr)
                }
            }
        case (.ecdsaP256(let key), .ecdsaP256(let sig)):
            return digest.withUnsafeBytes { digestPtr in
                key.isValidSignature(sig, for: digestPtr)
            }
        case (.ecdsaP384(let key), .ecdsaP384(let sig)):
            return digest.withUnsafeBytes { digestPtr in
                key.isValidSignature(sig, for: digestPtr)
            }
        case (.ecdsaP521(let key), .ecdsaP521(let sig)):
            return digest.withUnsafeBytes { digestPtr in
                key.isValidSignature(sig, for: digestPtr)
            }
        // LOGRAKER FORK
        case (.rsa(let key), .rsa(let hash, let sig)):
            // Only reachable for RSA host keys, which we do not negotiate.
            // Verify against the digest we were handed, but only if its
            // width matches the hash the signature claims - otherwise the
            // PKCS#1 DigestInfo would disagree with the payload.
            guard hash.digestByteCount == DigestBytes.byteCount else {
                return false
            }
            return key.isValidSignature(sig, for: digest, padding: .insecurePKCS1v1_5)
        case (.certified(let key), _):
            return key.isValidSignature(signature, for: digest)
        case (.ed25519, _),
            (.ecdsaP256, _),
            (.ecdsaP384, _),
            (.ecdsaP521, _),
            // LOGRAKER FORK
            (.rsa, _):
            return false
        }
    }

    internal func isValidSignature(_ signature: NIOSSHSignature, for bytes: ByteBuffer) -> Bool {
        switch (self.backingKey, signature.backingSignature) {
        case (.ed25519(let key), .ed25519(.byteBuffer(let buf))):
            return key.isValidSignature(buf.readableBytesView, for: bytes.readableBytesView)
        case (.ed25519(let key), .ed25519(.data(let buf))):
            return key.isValidSignature(buf, for: bytes.readableBytesView)
        case (.ecdsaP256(let key), .ecdsaP256(let sig)):
            return key.isValidSignature(sig, for: bytes.readableBytesView)
        case (.ecdsaP384(let key), .ecdsaP384(let sig)):
            return key.isValidSignature(sig, for: bytes.readableBytesView)
        case (.ecdsaP521(let key), .ecdsaP521(let sig)):
            return key.isValidSignature(sig, for: bytes.readableBytesView)
        // LOGRAKER FORK
        case (.rsa(let key), .rsa(let hash, let sig)):
            return hash.isValidSignature(sig, for: bytes.readableBytesView, key: key)
        case (.certified(let key), _):
            return key.isValidSignature(signature, for: bytes)
        case (.ed25519, _),
            (.ecdsaP256, _),
            (.ecdsaP384, _),
            (.ecdsaP521, _),
            // LOGRAKER FORK
            (.rsa, _):
            return false
        }
    }

    internal func isValidSignature(_ signature: NIOSSHSignature, for payload: UserAuthSignablePayload) -> Bool {
        switch (self.backingKey, signature.backingSignature) {
        case (.ed25519(let key), .ed25519(.byteBuffer(let sig))):
            return key.isValidSignature(sig.readableBytesView, for: payload.bytes.readableBytesView)
        case (.ed25519(let key), .ed25519(.data(let sig))):
            return key.isValidSignature(sig, for: payload.bytes.readableBytesView)
        case (.ecdsaP256(let key), .ecdsaP256(let sig)):
            return key.isValidSignature(sig, for: payload.bytes.readableBytesView)
        case (.ecdsaP384(let key), .ecdsaP384(let sig)):
            return key.isValidSignature(sig, for: payload.bytes.readableBytesView)
        case (.ecdsaP521(let key), .ecdsaP521(let sig)):
            return key.isValidSignature(sig, for: payload.bytes.readableBytesView)
        // LOGRAKER FORK
        case (.rsa(let key), .rsa(let hash, let sig)):
            return hash.isValidSignature(sig, for: payload.bytes.readableBytesView, key: key)
        case (.certified(let key), _):
            return key.isValidSignature(signature, for: payload)
        case (.ed25519, _),
            (.ecdsaP256, _),
            (.ecdsaP384, _),
            (.ecdsaP521, _),
            // LOGRAKER FORK
            (.rsa, _):
            return false
        }
    }
}

// swift-format-ignore: DontRepeatTypeInStaticProperties
extension NIOSSHPublicKey {
    /// The various key types that can be used with NIOSSH.
    internal enum BackingKey {
        case ed25519(Curve25519.Signing.PublicKey)
        case ecdsaP256(P256.Signing.PublicKey)
        case ecdsaP384(P384.Signing.PublicKey)
        case ecdsaP521(P521.Signing.PublicKey)
        // LOGRAKER FORK: RSA public keys.
        case rsa(_RSA.Signing.PublicKey)
        case certified(NIOSSHCertifiedPublicKey)  // This case recursively contains `NIOSSHPublicKey`.
    }

    /// The prefix of an Ed25519 public key.
    internal static let ed25519PublicKeyPrefix = "ssh-ed25519".utf8

    /// The prefix of a P256 ECDSA public key.
    internal static let ecdsaP256PublicKeyPrefix = "ecdsa-sha2-nistp256".utf8

    /// The prefix of a P384 ECDSA public key.
    internal static let ecdsaP384PublicKeyPrefix = "ecdsa-sha2-nistp384".utf8

    /// The prefix of a P521 ECDSA public key.
    internal static let ecdsaP521PublicKeyPrefix = "ecdsa-sha2-nistp521".utf8

    /// LOGRAKER FORK: The prefix of an RSA public key.
    ///
    /// Note this is the *key blob* tag only. RSA is the one algorithm
    /// where the key tag and the signature algorithm name differ - see
    /// `signatureAlgorithmName`.
    internal static let rsaPublicKeyPrefix = "ssh-rsa".utf8

    /// LOGRAKER FORK: RSA signature algorithm names (RFC 8332).
    internal static let rsaSHA256SignatureAlgorithm = "rsa-sha2-256".utf8
    internal static let rsaSHA512SignatureAlgorithm = "rsa-sha2-512".utf8

    internal var keyPrefix: String.UTF8View {
        switch self.backingKey {
        case .ed25519:
            return Self.ed25519PublicKeyPrefix
        case .ecdsaP256:
            return Self.ecdsaP256PublicKeyPrefix
        case .ecdsaP384:
            return Self.ecdsaP384PublicKeyPrefix
        case .ecdsaP521:
            return Self.ecdsaP521PublicKeyPrefix
        // LOGRAKER FORK
        case .rsa:
            return Self.rsaPublicKeyPrefix
        case .certified(let base):
            return base.keyPrefix
        }
    }

    /// LOGRAKER FORK: The algorithm name to advertise in the publickey
    /// userauth request.
    ///
    /// For every algorithm upstream supports this is identical to
    /// `keyPrefix`, which is why upstream uses `keyPrefix` directly.
    /// RSA is the exception: the key blob stays tagged `ssh-rsa`, but the
    /// algorithm name must name the *signature* algorithm, because
    /// OpenSSH 8.8 disabled the SHA-1 `ssh-rsa` signature algorithm by
    /// default and rejects that name outright.
    ///
    /// This value MUST match the one baked into `UserAuthSignablePayload`,
    /// byte for byte. They are the wire field and the signed-over field
    /// respectively, and a mismatch surfaces only as a server-side
    /// signature rejection.
    internal var signatureAlgorithmName: String.UTF8View {
        switch self.backingKey {
        case .rsa:
            return Self.rsaSHA512SignatureAlgorithm
        case .ed25519, .ecdsaP256, .ecdsaP384, .ecdsaP521, .certified:
            return self.keyPrefix
        }
    }

    internal static var knownAlgorithms: [String.UTF8View] {
        [
            Self.ed25519PublicKeyPrefix, Self.ecdsaP384PublicKeyPrefix, Self.ecdsaP256PublicKeyPrefix,
            Self.ecdsaP521PublicKeyPrefix,
            // LOGRAKER FORK: both the key tag and the signature algorithm
            // names, since this list is checked against the algorithm-name
            // field of userauth requests and PK_OK replies.
            Self.rsaPublicKeyPrefix, Self.rsaSHA256SignatureAlgorithm, Self.rsaSHA512SignatureAlgorithm,
        ]
    }

    /// LOGRAKER FORK: Whether `algorithmName` is a legal algorithm-name
    /// field for a key blob tagged with this key's prefix.
    ///
    /// Upstream asserts the two are equal. That holds for every algorithm
    /// it supports, but for RSA the pairing is one key tag (`ssh-rsa`) to
    /// several signature algorithm names.
    internal func isCompatibleAlgorithmName<Bytes: Collection>(_ algorithmName: Bytes) -> Bool
    where Bytes.Element == UInt8 {
        if algorithmName.elementsEqual(self.keyPrefix) {
            return true
        }
        if case .rsa = self.backingKey {
            return algorithmName.elementsEqual(Self.rsaSHA256SignatureAlgorithm)
                || algorithmName.elementsEqual(Self.rsaSHA512SignatureAlgorithm)
        }
        return false
    }
}

extension NIOSSHPublicKey.BackingKey: Equatable {
    static func == (lhs: NIOSSHPublicKey.BackingKey, rhs: NIOSSHPublicKey.BackingKey) -> Bool {
        // We implement equatable in terms of the key representation.
        switch (lhs, rhs) {
        case (.ed25519(let lhs), .ed25519(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ecdsaP256(let lhs), .ecdsaP256(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ecdsaP384(let lhs), .ecdsaP384(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ecdsaP521(let lhs), .ecdsaP521(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        // LOGRAKER FORK
        case (.rsa(let lhs), .rsa(let rhs)):
            return lhs.pkcs1DERRepresentation == rhs.pkcs1DERRepresentation
        case (.certified(let lhs), .certified(let rhs)):
            return lhs == rhs
        case (.ed25519, _),
            (.ecdsaP256, _),
            (.ecdsaP384, _),
            (.ecdsaP521, _),
            // LOGRAKER FORK
            (.rsa, _),
            (.certified, _):
            return false
        }
    }
}

extension NIOSSHPublicKey.BackingKey: Hashable {
    func hash(into hasher: inout Hasher) {
        switch self {
        case .ed25519(let pkey):
            hasher.combine(1)
            hasher.combine(pkey.rawRepresentation)
        case .ecdsaP256(let pkey):
            hasher.combine(2)
            hasher.combine(pkey.rawRepresentation)
        case .ecdsaP384(let pkey):
            hasher.combine(3)
            hasher.combine(pkey.rawRepresentation)
        case .ecdsaP521(let pkey):
            hasher.combine(4)
            hasher.combine(pkey.rawRepresentation)
        // LOGRAKER FORK
        case .rsa(let pkey):
            hasher.combine(6)
            hasher.combine(pkey.pkcs1DERRepresentation)
        case .certified(let pkey):
            hasher.combine(5)
            hasher.combine(pkey)
        }
    }
}

extension ByteBuffer {
    /// Writes an SSH host key to this `ByteBuffer`.
    @discardableResult
    mutating func writeSSHHostKey(_ key: NIOSSHPublicKey) -> Int {
        var writtenBytes = 0

        switch key.backingKey {
        case .ed25519(let key):
            writtenBytes += self.writeSSHString(NIOSSHPublicKey.ed25519PublicKeyPrefix)
            writtenBytes += self.writeEd25519PublicKey(baseKey: key)
        case .ecdsaP256(let key):
            writtenBytes += self.writeSSHString(NIOSSHPublicKey.ecdsaP256PublicKeyPrefix)
            writtenBytes += self.writeECDSAP256PublicKey(baseKey: key)
        case .ecdsaP384(let key):
            writtenBytes += self.writeSSHString(NIOSSHPublicKey.ecdsaP384PublicKeyPrefix)
            writtenBytes += self.writeECDSAP384PublicKey(baseKey: key)
        case .ecdsaP521(let key):
            writtenBytes += self.writeSSHString(NIOSSHPublicKey.ecdsaP521PublicKeyPrefix)
            writtenBytes += self.writeECDSAP521PublicKey(baseKey: key)
        // LOGRAKER FORK
        case .rsa(let key):
            writtenBytes += self.writeSSHString(NIOSSHPublicKey.rsaPublicKeyPrefix)
            writtenBytes += self.writeRSAPublicKey(baseKey: key)
        case .certified(let key):
            return self.writeCertifiedKey(key)
        }

        return writtenBytes
    }

    /// Writes an SSH host key to this `ByteBuffer`, without a prefix.
    ///
    /// This is mostly used as part of the certified key structure.
    @discardableResult
    mutating func writePublicKeyWithoutPrefix(_ key: NIOSSHPublicKey) -> Int {
        switch key.backingKey {
        case .ed25519(let key):
            return self.writeEd25519PublicKey(baseKey: key)
        case .ecdsaP256(let key):
            return self.writeECDSAP256PublicKey(baseKey: key)
        case .ecdsaP384(let key):
            return self.writeECDSAP384PublicKey(baseKey: key)
        case .ecdsaP521(let key):
            return self.writeECDSAP521PublicKey(baseKey: key)
        // LOGRAKER FORK
        case .rsa(let key):
            return self.writeRSAPublicKey(baseKey: key)
        case .certified:
            preconditionFailure("Certified keys are the only callers of this method, and cannot contain themselves")
        }
    }

    mutating func readSSHHostKey() throws -> NIOSSHPublicKey? {
        try self.rewindOnNilOrError { buffer in
            // The wire format always begins with an SSH string containing the key format identifier. Let's grab that.
            guard let keyIdentifierBytes = buffer.readSSHString() else {
                return nil
            }

            // Now we need to check if they match our supported key algorithms.
            return try buffer.readPublicKeyWithoutPrefixForIdentifier(keyIdentifierBytes.readableBytesView)
        }
    }

    mutating func readPublicKeyWithoutPrefixForIdentifier<Bytes: Collection>(
        _ keyIdentifierBytes: Bytes
    ) throws -> NIOSSHPublicKey? where Bytes.Element == UInt8 {
        try self.rewindOnNilOrError { buffer in
            if keyIdentifierBytes.elementsEqual(NIOSSHPublicKey.ed25519PublicKeyPrefix) {
                return try buffer.readEd25519PublicKey()
            } else if keyIdentifierBytes.elementsEqual(NIOSSHPublicKey.ecdsaP256PublicKeyPrefix) {
                return try buffer.readECDSAP256PublicKey()
            } else if keyIdentifierBytes.elementsEqual(NIOSSHPublicKey.ecdsaP384PublicKeyPrefix) {
                return try buffer.readECDSAP384PublicKey()
            } else if keyIdentifierBytes.elementsEqual(NIOSSHPublicKey.ecdsaP521PublicKeyPrefix) {
                return try buffer.readECDSAP521PublicKey()
            // LOGRAKER FORK
            } else if keyIdentifierBytes.elementsEqual(NIOSSHPublicKey.rsaPublicKeyPrefix) {
                return try buffer.readRSAPublicKey()
            } else {
                // We don't know this public key type. Maybe the certified keys do.
                return try buffer.readCertifiedKeyWithoutKeyPrefix(keyIdentifierBytes).map(NIOSSHPublicKey.init)
            }
        }
    }

    /// LOGRAKER FORK: Writes an RSA public key body.
    ///
    /// Per RFC 4253 the `ssh-rsa` blob body is `mpint e` followed by
    /// `mpint n`, in that order. Note the exponent comes first, which is
    /// the reverse of the order `_RSA.Signing.PublicKey(n:e:)` takes them.
    private mutating func writeRSAPublicKey(baseKey: _RSA.Signing.PublicKey) -> Int {
        // `getKeyPrimitives` only throws if the key is malformed, which
        // cannot happen for a key we already parsed or derived.
        guard let primitives = try? baseKey.getKeyPrimitives() else {
            preconditionFailure("RSA public key without recoverable primitives")
        }
        var writtenBytes = 0
        writtenBytes += self.writePositiveMPInt(primitives.publicExponent)
        writtenBytes += self.writePositiveMPInt(primitives.modulus)
        return writtenBytes
    }

    /// LOGRAKER FORK: A helper function that reads an RSA public key.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readRSAPublicKey() throws -> NIOSSHPublicKey? {
        // `mpint e` then `mpint n`. mpints are length-prefixed exactly like
        // strings, and any leading zero pad is harmless to the parser below.
        guard let eBytes = self.readSSHString(), let nBytes = self.readSSHString() else {
            return nil
        }

        let key = try _RSA.Signing.PublicKey(
            n: Array(nBytes.readableBytesView),
            e: Array(eBytes.readableBytesView)
        )
        return NIOSSHPublicKey(backingKey: .rsa(key))
    }

    private mutating func writeEd25519PublicKey(baseKey: Curve25519.Signing.PublicKey) -> Int {
        // For Ed25519 the key format is  Q as a String.
        self.writeSSHString(baseKey.rawRepresentation)
    }

    private mutating func writeECDSAP256PublicKey(baseKey: P256.Signing.PublicKey) -> Int {
        // For ECDSA-P256, the key format is the string "nistp256", followed by the
        // the public point Q.
        var writtenBytes = 0
        writtenBytes += self.writeSSHString("nistp256".utf8)
        writtenBytes += self.writeSSHString(baseKey.x963Representation)
        return writtenBytes
    }

    private mutating func writeECDSAP384PublicKey(baseKey: P384.Signing.PublicKey) -> Int {
        // For ECDSA-P384, the key format is the string "nistp384", followed by the
        // the public point Q.
        var writtenBytes = 0
        writtenBytes += self.writeSSHString("nistp384".utf8)
        writtenBytes += self.writeSSHString(baseKey.x963Representation)
        return writtenBytes
    }

    private mutating func writeECDSAP521PublicKey(baseKey: P521.Signing.PublicKey) -> Int {
        // For ECDSA-P521, the key format is the string "nistp521", followed by the
        // the public point Q.
        var writtenBytes = 0
        writtenBytes += self.writeSSHString("nistp521".utf8)
        writtenBytes += self.writeSSHString(baseKey.x963Representation)
        return writtenBytes
    }

    /// A helper function that reads an Ed25519 public key.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readEd25519PublicKey() throws -> NIOSSHPublicKey? {
        // For ed25519 the key format is just Q encoded as a String.
        guard let qBytes = self.readSSHString() else {
            return nil
        }

        let key = try Curve25519.Signing.PublicKey(rawRepresentation: qBytes.readableBytesView)
        return NIOSSHPublicKey(backingKey: .ed25519(key))
    }

    /// A helper function that reads an ECDSA P-256 public key.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP256PublicKey() throws -> NIOSSHPublicKey? {
        // For ECDSA-P256, the key format is the string "nistp256" followed by the
        // the public point Q.
        guard var domainParameter = self.readSSHString() else {
            return nil
        }
        guard domainParameter.readableBytesView.elementsEqual("nistp256".utf8) else {
            let unexpectedParameter =
                domainParameter.readString(length: domainParameter.readableBytes) ?? "<unknown domain parameter>"
            throw NIOSSHError.invalidDomainParametersForKey(parameters: unexpectedParameter)
        }

        guard let qBytes = self.readSSHString() else {
            return nil
        }

        let key = try P256.Signing.PublicKey(x963Representation: qBytes.readableBytesView)
        return NIOSSHPublicKey(backingKey: .ecdsaP256(key))
    }

    /// A helper function that reads an ECDSA P-384 public key.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP384PublicKey() throws -> NIOSSHPublicKey? {
        // For ECDSA-P384, the key format is the string "nistp384" followed by the
        // the public point Q.
        guard var domainParameter = self.readSSHString() else {
            return nil
        }
        guard domainParameter.readableBytesView.elementsEqual("nistp384".utf8) else {
            let unexpectedParameter =
                domainParameter.readString(length: domainParameter.readableBytes) ?? "<unknown domain parameter>"
            throw NIOSSHError.invalidDomainParametersForKey(parameters: unexpectedParameter)
        }

        guard let qBytes = self.readSSHString() else {
            return nil
        }

        let key = try P384.Signing.PublicKey(x963Representation: qBytes.readableBytesView)
        return NIOSSHPublicKey(backingKey: .ecdsaP384(key))
    }

    /// A helper function that reads an ECDSA P-521 public key.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP521PublicKey() throws -> NIOSSHPublicKey? {
        // For ECDSA-P521, the key format is the string "nistp521" followed by the
        // the public point Q.
        guard var domainParameter = self.readSSHString() else {
            return nil
        }
        guard domainParameter.readableBytesView.elementsEqual("nistp521".utf8) else {
            let unexpectedParameter =
                domainParameter.readString(length: domainParameter.readableBytes) ?? "<unknown domain parameter>"
            throw NIOSSHError.invalidDomainParametersForKey(parameters: unexpectedParameter)
        }

        guard let qBytes = self.readSSHString() else {
            return nil
        }

        let key = try P521.Signing.PublicKey(x963Representation: qBytes.readableBytesView)
        return NIOSSHPublicKey(backingKey: .ecdsaP521(key))
    }

    /// A helper function for complex readers that will reset a buffer on nil or on error, as though the read
    /// never occurred.
    internal mutating func rewindOnNilOrError<T>(_ body: (inout ByteBuffer) throws -> T?) rethrows -> T? {
        let originalSelf = self

        let returnValue: T?
        do {
            returnValue = try body(&self)
        } catch {
            self = originalSelf
            throw error
        }

        if returnValue == nil {
            self = originalSelf
        }

        return returnValue
    }
}

extension String {
    /// Takes a NIOSSHPublicKey and turns it into OpenSSH public key string in the format of "algorithm-id base64-encoded-key"
    public init(openSSHPublicKey: NIOSSHPublicKey) {
        var buffer = ByteBuffer()
        buffer.writeSSHHostKey(openSSHPublicKey)
        let next = Data(buffer.readableBytesView).base64EncodedString()
        let publicKeyString = String(openSSHPublicKey.keyPrefix) + " " + next
        self = publicKeyString
    }
}
