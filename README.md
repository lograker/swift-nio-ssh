# swift-nio-ssh, with RSA client authentication

A fork of [apple/swift-nio-ssh](https://github.com/apple/swift-nio-ssh) that
adds RSA public-key client authentication, so an SSH client written in Swift
can use the RSA `.pem` keys Amazon EC2 hands out.

Forked from tag `0.15.0`. Upstream has no RSA support, by design, and no
extension point to add one from outside the module.

## Read this first

This exists to serve one application, [LogRaker](https://lograker.app), and
it is published because the problem it solves comes up for other people.

- **No support, no roadmap, no release schedule.** Issues and pull requests
  are welcome as information but will probably not be answered or merged in
  a timely manner.
- **Not independently audited.** This is cryptographic code written to make
  one app work, not a reviewed security product. The tests below are the
  whole of the evidence that it is correct. Read them before you trust it.
- **Pinned to upstream `0.15.0`.** It does not track upstream automatically
  and will fall behind. See "Staying current" below, and take that section
  seriously if you ship this.
- **Client authentication only.** RSA *host* keys are not exercised by
  LogRaker and should be treated as untested.

If you can use ed25519, use upstream instead. It is maintained and this is
not.

## Why

Amazon EC2 issues PKCS#1 RSA `.pem` key pairs, and only grew ed25519 key
pairs in 2021. Every key pair older than that is RSA, the instances those
keys open are still running, and a client cannot negotiate its way out of
the key it was given.

Upstream supports modern primitives only, which is the right default for a
new deployment and no help at all here. The relevant type stores its key in
an internal enum with a private memberwise initializer, so an algorithm
cannot be added from another module. Hence a fork.

## Installing

```swift
.package(url: "https://github.com/lograker/swift-nio-ssh.git", exact: "0.15.0-rsa.1")
```

Tags are `<upstream version>-rsa.<n>`. Pin one: the branch moves, and
nothing here is versioned for compatibility.

## What it adds

Load an RSA key from PEM, in either PKCS#1 (`BEGIN RSA PRIVATE KEY`, the EC2
format) or PKCS#8 (`BEGIN PRIVATE KEY`). The PEM must be unencrypted.

```swift
import NIOSSH

let key = try NIOSSHPrivateKey(rsaPEMRepresentation: pem)
```

Keys under 2048 bits are refused with `NIOSSHRSAKeyError.keyTooSmall(bits:)`,
which carries the real size so a caller can report it. The floor is exposed
as `NIOSSHPrivateKey.minimumRSAKeySizeInBits`.

There is also an initializer taking raw components (n, e, d, p, q), which is
the shape an OpenSSH-format private key file stores RSA keys in.

`_RSA.Signing` stays an implementation detail: it comes from swift-crypto's
`CryptoExtras` product, which this package depends on so that callers do not
have to import somebody else's crypto internals to load a key.

## The part worth knowing

RSA is the one SSH algorithm where the key blob tag and the signature
algorithm name are different strings. The blob stays tagged `ssh-rsa`, but
the algorithm name in a `publickey` userauth request has to name the
signature algorithm: `rsa-sha2-256` or `rsa-sha2-512`, per RFC 8332. The
bare `ssh-rsa` name means RSA with SHA-1, which OpenSSH 8.8 disabled by
default in 2021 and current servers reject outright.

Upstream writes the key's own tag into that field, because for ed25519 and
the ECDSA curves the two strings coincide. This fork adds
`signatureAlgorithmName` alongside `keyPrefix` and uses it in the two places
that write the field: the wire message, and the buffer that gets signed.

Those two **must** agree byte for byte. One is what you claim, the other is
what you sign, and a divergence surfaces only as a server-side signature
rejection that looks exactly like a wrong key. A test pins them together.

This fork always offers `rsa-sha2-512` and does not negotiate, because
nio-ssh does not parse `SSH_MSG_EXT_INFO`, so `server-sig-algs` never
reaches code that could act on it. `rsa-sha2-512` has been accepted since
OpenSSH 7.2, in 2016.

## What changed

Eight files: `Package.swift`, five sources under `Sources/NIOSSH/`, one
upstream test that had to change, and one new test file. Every edit carries
a `LOGRAKER FORK:` marker, so the whole diff against upstream is one
command:

```
grep -rn "LOGRAKER FORK" Sources/ Tests/ Package.swift
```

That is also the rebase checklist. `FORK.md` has the upstream revision and
the procedure.

The upstream test change is worth knowing about: `HostKeyTests` used
`ssh-rsa` as its example of an unrecognized algorithm, which this fork
recognizes, so that case moves to `ssh-dss`. RSA-backed *certificates* are
rejected outright, because no RSA certificate prefix is registered on the
read path.

## Tests

```
swift test --filter LograkerRSATests
```

Two of them carry the weight:

- **`testPublicKeySerializationMatchesOpenSSH`** compares the generated
  public-key blob byte for byte against what `ssh-keygen -y` prints for the
  same key. Hand-rolled SSH wire format is where a plausible-looking mistake
  survives review, and OpenSSH is the only opinion that counts.
- **`testWireAlgorithmNameMatchesSignedAlgorithmName`** pins the two write
  sites described above to each other.

The rest cover PEM loading, the size floor, signature wire format, and
round-tripping a signature through the wire.

## Staying current

Vendoring or forking opts out of every automatic signal: nothing will tell
you that upstream shipped a security fix. Check deliberately.

```
gh api repos/apple/swift-nio-ssh/security-advisories \
  --jq '.[] | "\(.severity) \(.ghsa_id) \(.summary)"'
```

Advisories also cover the wider SwiftNIO family; swift-nio-ssh's own
`SECURITY.md` defers to `apple/swift-nio`. Report anything you find in
upstream code to upstream, not here.

## License and attribution

Apache License 2.0, unchanged from upstream. `LICENSE.txt` is upstream's,
the per-file copyright and SPDX headers are untouched, and every modified
file carries a notice saying it was changed.

swift-nio-ssh is copyright Apple Inc. and the SwiftNIO project authors. This
fork is not affiliated with, endorsed by, or supported by Apple or the
SwiftNIO project. If upstream ever adds RSA, this fork should be deleted and
callers should go back to a stock dependency.
