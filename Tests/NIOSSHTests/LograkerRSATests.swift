//===----------------------------------------------------------------------===//
//
// LOGRAKER FORK: tests for the RSA support added to this fork.
//
// The point of this file is interop, not self-consistency. The fixture
// below is a real key produced by `ssh-keygen -t rsa -b 2048 -m PEM`, and
// the expected public key string is exactly what `ssh-keygen -y` prints
// for it. If our wire format ever drifts from OpenSSH's, these fail.
//
//===----------------------------------------------------------------------===//

import Crypto
import CryptoExtras
import NIOCore
import XCTest

@testable import NIOSSH

/// A throwaway 2048-bit RSA key. Test fixture only, never used anywhere.
private let fixturePEM = """
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxRp7zvfkzjf5jsgv1JiX/LzHdqrs0bRW3nQ1iNwTeW6SHufP
iiA4MRwX6bwPT/0BudIvIUVrIfYvZeZWWBKz/T3GpJqwB0ogA82uZmumoIVjNG5Z
WbhDJF4UM4gKxDIxKRJoowG3prQlcwrVV+0b+g/dm/1h+6OHzrc1xu9dkIA7AzpL
xi+OajAjjz8RGAw5QdotBhEgPQpHLSI3fJL8wJTLdnGCEtoyHmWwVTH0iVyFkdCB
FP78tghuMBPCsN0Dtz/mwISjcWvofQqOdLjHtYcEqO+92ZPtASR5VY+eaT2zM79v
eE9w4/Ui669svUq3+/lGF7m2HYchOrw1gdlseQIDAQABAoIBAERkEBmcglPbsEgO
xinqWLJlfoB6hnmtLYc6o2i9lDRKXYFDxguTamv/53w+uMF0dKjZeWj+AVJjbcbZ
yZP9yV5RlR+AXRvqaHlpYN5A9Cw2nFmRAIfVG9b+ndvTlIjHMa+ip5QIAIVjdKsa
UzSTHWYDI04A+YKrF3BuucYxQDHm75ElQZ9lObR3W+1RxUsYe3UZCoEb5irHbdkf
2ZHYBk6ijCKlT5bo6q+ynQv6eXY0ZbA1pjPhkeMjEE+e+UxmeWIVoQ0YBGTg8do2
0vLrhkU/o/9KNahIR5b+GG4ArCJMUl7/R8KtCjxJrsDM6EYFsz43VSU/1cofG6ID
VuAqMgECgYEA/TxJM8K6X/nKQRJPNzY+YDCmXviykNVrkn6QJXRsbllyVQKQ9v6c
QictoqSZw/zrQpYjSkiQ6gMS7ZKkG9bnimUlurD3A4BHj3wLaCmPcMfIOwcQhr6D
6z/S3KXmqcmrOKTmA47e7+O9GvTN0YICM8qxkkbTtanMeeaCtc6WpJECgYEAx0FT
f/t0ieCl0vHc3R1QlqyNjkOxyQOWruloHc+S8ZNj6AHAufQhGYWuhWXCO3A7c3l0
fj7EBFOHLuYftjbFFzzEzbDL4rZoIh7vPZmTx2gpliyWQTWnZtuB+0t0Pth8Z/fM
JsSBVc0nppRyo3BxQUcXTS8ujqMi7NgKkRZznWkCgYA0CGEaK5bUBaVTPYndVF34
scZdmUhHjjKuRSclKwjkm6hsYzyaI7LDvP0ZgCzAIoXMhsD1kHeGPd9zxT/HIJ8u
xp28AISgyYjqqJhHbNK2X7Z6unbg2OCOQ+z1vXjpxjBSUT+Z149jRy4iDc8Ej2wY
bDuUTM1PdHY5Te3poWs+oQKBgByzbDOjJMY3datM62NuNY1+jWVQmus5eRr4w+aH
X8MsV9ezaO9gGuRyPRE59yBYqjeX5w/IOrPk1DQNMcQtX3ZZan+2V6fwXk+L5Soa
VQ8EEflvsrTx5YsLU02/MJ9cz46qQt3SsE6LnoqAF4MzTxz4AIM9qJcjKIS1GdCM
S1sBAoGAO+sUNlygAPmPOdy7UaGcxNzfuEKJkOubSkkL/jJfmSVCQsiQdjufAC40
FJr2om9QMVXUCqkQDmNOn0HlgniMvti/NdXSdx49wnOMhlzwDxSEm6jNIrQ9N7uG
PUNjXxnmYvSwM8mCgssexwgRLqKCvo1JFTHTZV8Q9US14RR6aVg=
-----END RSA PRIVATE KEY-----
"""

/// Exactly what `ssh-keygen -y` prints for the key above.
private let fixtureOpenSSHPublicKey =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFGnvO9+TON/mOyC/UmJf8vMd2quzRtFbedDWI3BN5bpIe58+KIDgxHBfpvA9P/QG50i8hRWsh9i9l5lZYErP9PcakmrAHSiADza5ma6aghWM0bllZuEMkXhQziArEMjEpEmijAbemtCVzCtVX7Rv6D92b/WH7o4fOtzXG712QgDsDOkvGL45qMCOPPxEYDDlB2i0GESA9CkctIjd8kvzAlMt2cYIS2jIeZbBVMfSJXIWR0IEU/vy2CG4wE8Kw3QO3P+bAhKNxa+h9Co50uMe1hwSo773Zk+0BJHlVj55pPbMzv294T3Dj9SLrr2y9Srf7+UYXubYdhyE6vDWB2Wx5"

/// A 1024-bit RSA key, below the floor we accept. Fixture only.
private let undersizedPEM = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCd6Y6Tzum7BATmT5KDRfHXs6+F5ttTCusX8/9uetiHbnazXJB1
q3htl36CQLeN8Dw94BPQS4PMMB5ywsoaRedqS25LTRLJFKYiruG4omD7nsyzLsnY
7e7p2A8cx3tJBqnj1iiKjRkrhehdRw+LhsuOn6Eh/Bmjn9ehWL8rFmv//wIDAQAB
AoGAPaqspCokeoT6SNqAM8WHyR2BiP/7XHWiE0uUz5cnodPQhQC75UfeEqYboFAX
nlVXoS41bp1ezcloypYpCJON6Aadshs5tvjnk3/EXRABXprSYCtKFxhOG+oiVdGw
0zKHovG1lrIb+65aHrgavQrNzQnXlTa1273ubshoDF2Y7KECQQDJdhyiFoWBsULu
W4b8+8NR8nPB5+DBmbRm3Bhwzg527uIBamG8CTLm3boA7QPZFcmLYwAMnFnhb9aH
Fov/hFexAkEAyKldD7b5GPUrihIYCQ7uI1TU1Fu/trqIxcUY7If9XHVIiXJnmMpL
Ug1wFnUPo+s+/Gj0JmnogmCVSTP7WSZurwJAc2qxWMMiVXziZYAWQ9VQvx/x5YMc
po2SZuNtNSM38jdFT55Mw9dZTB53M5SWAcaTosFjA9aHP7o840OtjQOa4QJAZ69b
7urU/BhzTvzafpPAaXFEKBbgkUMBuW+G2XHLcSMJQDxlW4XsNZHMAU6rrj+4ZCS3
Q8Il6niNqy25Cu/Y8QJBAIzG5CreMcHYLdEfDQGrTfEXj77AVzXHS3AfqYrjfdwv
uVxS8vflSHPMZ8KU73YMFSLusw7uRyQnTAtkAxqHKKg=
-----END RSA PRIVATE KEY-----
"""

/// The fixture key's PKCS#1 components, base64-encoded big-endian.
private let fixtureN =
    "AMUae8735M43+Y7IL9SYl/y8x3aq7NG0Vt50NYjcE3lukh7nz4ogODEcF+m8D0/9AbnSLyFFayH2L2XmVlgSs/09xqSasAdKIAPNrmZrpqCFYzRuWVm4QyReFDOICsQyMSkSaKMBt6a0JXMK1VftG/oP3Zv9Yfujh863NcbvXZCAOwM6S8YvjmowI48/ERgMOUHaLQYRID0KRy0iN3yS/MCUy3ZxghLaMh5lsFUx9IlchZHQgRT+/LYIbjATwrDdA7c/5sCEo3Fr6H0KjnS4x7WHBKjvvdmT7QEkeVWPnmk9szO/b3hPcOP1IuuvbL1Kt/v5Rhe5th2HITq8NYHZbHk="
private let fixtureE = "AQAB"
private let fixtureD =
    "RGQQGZyCU9uwSA7GKepYsmV+gHqGea0thzqjaL2UNEpdgUPGC5Nqa//nfD64wXR0qNl5aP4BUmNtxtnJk/3JXlGVH4BdG+poeWlg3kD0LDacWZEAh9Ub1v6d29OUiMcxr6KnlAgAhWN0qxpTNJMdZgMjTgD5gqsXcG65xjFAMebvkSVBn2U5tHdb7VHFSxh7dRkKgRvmKsdt2R/ZkdgGTqKMIqVPlujqr7KdC/p5djRlsDWmM+GR4yMQT575TGZ5YhWhDRgEZODx2jbS8uuGRT+j/0o1qEhHlv4YbgCsIkxSXv9Hwq0KPEmuwMzoRgWzPjdVJT/Vyh8bogNW4CoyAQ=="
private let fixtureP =
    "AP08STPCul/5ykESTzc2PmAwpl74spDVa5J+kCV0bG5ZclUCkPb+nEInLaKkmcP860KWI0pIkOoDEu2SpBvW54plJbqw9wOAR498C2gpj3DHyDsHEIa+g+s/0tyl5qnJqzik5gOO3u/jvRr0zdGCAjPKsZJG07WpzHnmgrXOlqSR"
private let fixtureQ =
    "AMdBU3/7dIngpdLx3N0dUJasjY5DsckDlq7paB3PkvGTY+gBwLn0IRmFroVlwjtwO3N5dH4+xARThy7mH7Y2xRc8xM2wy+K2aCIe7z2Zk8doKZYslkE1p2bbgftLdD7YfGf3zCbEgVXNJ6aUcqNwcUFHF00vLo6jIuzYCpEWc51p"

private enum LograkerRSATestError: Error {
    case badFixture
}

final class LograkerRSATests: XCTestCase {
    private func fixtureKey() throws -> NIOSSHPrivateKey {
        NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(pemRepresentation: fixturePEM))
    }

    private func fixturePayload(userName: String = "ec2-user") throws -> UserAuthSignablePayload {
        UserAuthSignablePayload(
            sessionIdentifier: ByteBuffer(string: "session-id"),
            userName: userName,
            serviceName: "ssh-connection",
            publicKey: try self.fixtureKey().publicKey
        )
    }

    /// The PEM convenience initializer must reach the same key as going
    /// through CryptoExtras by hand.
    func testPEMConvenienceInitializer() throws {
        let viaConvenience = try NIOSSHPrivateKey(rsaPEMRepresentation: fixturePEM)
        XCTAssertEqual(String(openSSHPublicKey: viaConvenience.publicKey), fixtureOpenSSHPublicKey)
    }

    /// Undersized keys are refused, and the error carries the real size so
    /// the caller can say how small it actually was.
    func testUndersizedKeyIsRejectedWithItsSize() throws {
        XCTAssertThrowsError(try NIOSSHPrivateKey(rsaPEMRepresentation: undersizedPEM)) { error in
            XCTAssertEqual(error as? NIOSSHRSAKeyError, .keyTooSmall(bits: 1024))
        }
    }

    /// The component initializer is the path OpenSSH-format key files take.
    /// The components below were pulled out of the fixture's own PKCS#1 DER,
    /// so this builds the key from raw integers exactly as the OpenSSH
    /// private-key parser will.
    func testComponentInitializer() throws {
        func bytes(_ base64: String) throws -> [UInt8] {
            guard let data = Data(base64Encoded: base64) else {
                throw LograkerRSATestError.badFixture
            }
            return Array(data)
        }

        let rebuilt = try NIOSSHPrivateKey(
            rsaModulus: try bytes(fixtureN),
            publicExponent: try bytes(fixtureE),
            privateExponent: try bytes(fixtureD),
            prime1: try bytes(fixtureP),
            prime2: try bytes(fixtureQ)
        )
        XCTAssertEqual(String(openSSHPublicKey: rebuilt.publicKey), fixtureOpenSSHPublicKey)

        // And it must actually sign: reconstructing from components is
        // worthless if the private half did not survive.
        let payload = try self.fixturePayload()
        XCTAssertTrue(rebuilt.publicKey.isValidSignature(try rebuilt.sign(payload), for: payload))
    }

    /// The public key blob we serialize must be byte-identical to OpenSSH's.
    func testPublicKeySerializationMatchesOpenSSH() throws {
        let key = try self.fixtureKey()
        XCTAssertEqual(String(openSSHPublicKey: key.publicKey), fixtureOpenSSHPublicKey)
    }

    /// ...and we must be able to read OpenSSH's back.
    func testPublicKeyParsingRoundTrips() throws {
        let key = try self.fixtureKey()
        let parsed = try NIOSSHPublicKey(openSSHPublicKey: fixtureOpenSSHPublicKey)
        XCTAssertEqual(parsed, key.publicKey)
    }

    /// The key tag and the algorithm name are deliberately different for RSA.
    /// This is the whole reason the fork exists; assert it explicitly.
    func testAlgorithmNameDiffersFromKeyPrefix() throws {
        let publicKey = try self.fixtureKey().publicKey
        XCTAssertEqual(String(publicKey.keyPrefix), "ssh-rsa")
        XCTAssertEqual(String(publicKey.signatureAlgorithmName), "rsa-sha2-512")
    }

    func testSignAndVerifyUserAuthPayload() throws {
        let key = try self.fixtureKey()
        let payload = try self.fixturePayload()
        XCTAssertTrue(key.publicKey.isValidSignature(try key.sign(payload), for: payload))
    }

    func testSignatureIsRejectedForADifferentPayload() throws {
        let key = try self.fixtureKey()
        let signature = try key.sign(try self.fixturePayload())
        XCTAssertFalse(
            key.publicKey.isValidSignature(signature, for: try self.fixturePayload(userName: "root"))
        )
    }

    /// RFC 8332: algorithm name, then the raw signature as a string. The
    /// signature is modulus-length with leading zeros preserved, so a
    /// 2048-bit key must always produce exactly 256 bytes.
    func testSignatureWireFormat() throws {
        let key = try self.fixtureKey()
        var buffer = ByteBuffer()
        buffer.writeSSHSignature(try key.sign(try self.fixturePayload()))

        guard let algorithm = buffer.readSSHString(), let blob = buffer.readSSHString() else {
            XCTFail("could not read back signature")
            return
        }
        XCTAssertEqual(String(buffer: algorithm), "rsa-sha2-512")
        XCTAssertEqual(blob.readableBytes, 256)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testSignatureRoundTripsThroughTheWire() throws {
        let key = try self.fixtureKey()
        let payload = try self.fixturePayload()
        var buffer = ByteBuffer()
        buffer.writeSSHSignature(try key.sign(payload))

        guard let recovered = try buffer.readSSHSignature() else {
            XCTFail("could not read back signature")
            return
        }
        XCTAssertTrue(key.publicKey.isValidSignature(recovered, for: payload))
    }

    /// The invariant the whole fork turns on: the algorithm name written
    /// into the userauth request MUST equal the one baked into the signed
    /// payload. If these ever diverge the signature verifies locally and is
    /// rejected by every real server, which is a miserable bug to chase.
    func testWireAlgorithmNameMatchesSignedAlgorithmName() throws {
        let key = try self.fixtureKey()
        let offer = NIOSSHUserAuthenticationOffer(
            username: "ec2-user",
            serviceName: "ssh-connection",
            offer: .privateKey(.init(privateKey: key))
        )
        let message = try SSHMessage.UserAuthRequestMessage(
            request: offer,
            sessionID: ByteBuffer(string: "session-id")
        )

        var buffer = ByteBuffer()
        buffer.writeUserAuthRequestMessage(message)

        // username, service name, "publickey", has-signature, algorithm name
        _ = buffer.readSSHString()
        _ = buffer.readSSHString()
        _ = buffer.readSSHString()
        _ = buffer.readSSHBoolean()
        guard let wireAlgorithm = buffer.readSSHString() else {
            XCTFail("could not read algorithm name")
            return
        }

        XCTAssertEqual(String(buffer: wireAlgorithm), "rsa-sha2-512")
        XCTAssertEqual(String(buffer: wireAlgorithm), String(key.publicKey.signatureAlgorithmName))

        // The key blob inside is still tagged ssh-rsa, not the algorithm name.
        guard var keyBlob = buffer.readSSHString(), let blobTag = keyBlob.readSSHString() else {
            XCTFail("could not read key blob")
            return
        }
        XCTAssertEqual(String(buffer: blobTag), "ssh-rsa")
    }
}
