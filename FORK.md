# LogRaker fork of swift-nio-ssh

Upstream: https://github.com/apple/swift-nio-ssh
Forked from tag `0.15.0`, revision `3ec281496f28a3b6581afd946b759e2642f5cd8d`.

Rebase history: originally cut from `0.13.0`
(`1a915a324afefd4031e396e81a0e210178621be8`), moved to `0.15.0` on
2026-08-24.

## Why

Upstream is "modern primitives only" and has no RSA support, and no
extension point to add one: `NIOSSHPrivateKey.backingKey` is a closed
internal enum. Re-verified at 0.15.0 - still no RSA code anywhere in
`Sources/`. If upstream ever adds it, this fork can be deleted and the
project can go back to a stock dependency.

LogRaker needs RSA because AWS EC2 hands out PKCS#1 RSA `.pem` key
pairs, and every instance created before ED25519 support (2021) can
only be reached with one.

## What we changed

Every edit is marked with a `LOGRAKER FORK:` comment so the diff
against upstream stays greppable:

    grep -rn "LOGRAKER FORK" Sources/ Tests/ Package.swift

- `Package.swift` - depend on `CryptoExtras` for `_RSA.Signing`.
- `Sources/NIOSSH/Keys And Signatures/NIOSSHPrivateKey.swift`
- `Sources/NIOSSH/Keys And Signatures/NIOSSHPublicKey.swift`
- `Sources/NIOSSH/Keys And Signatures/NIOSSHSignature.swift`
- `Sources/NIOSSH/Keys And Signatures/NIOSSHCertifiedPublicKey.swift` -
  rejects RSA-backed certificates. We do not support them: no RSA
  certificate prefix is registered on the read path, so one could be
  written and never read back. `keyPrefix` gains an `.rsa` case purely so
  it stays exhaustive.
- `Sources/NIOSSH/SSHMessages.swift`
- `Sources/NIOSSH/User Authentication/UserAuthSignablePayload.swift`
- `Tests/NIOSSHTests/HostKeyTests.swift` - upstream used `ssh-rsa` as its
  example of an *unrecognized* algorithm. This fork recognizes it, so that
  case moves to `ssh-dss` and a new test covers a truncated RSA key
  reporting incomplete rather than unknown.

Plus one new file, `Tests/NIOSSHTests/LograkerRSATests.swift`.

Second change, for jump hosts (2026-11-16): a refused channel open
(`SSH_MSG_CHANNEL_OPEN_FAILURE`) now carries its RFC 4254 reason code
as data, `NIOSSHError.channelOpenFailureReasonCode`, so LogRaker can
tell a jump host that forbids forwarding from one that cannot reach the
target without parsing error text. Upstream keeps the code only in the
private diagnostics string.

- `Sources/NIOSSH/NIOSSHError.swift`
- `Tests/NIOSSHTests/ChildChannelMultiplexerTests.swift` - one assertion
  in `testPromiseCompletionDelaysUntilResponseOnFailure`.

Third change, transport compression (2026-11-19): the fork offers
`zlib@openssh.com` when the configuration asks for it
(`SSHClientConfiguration.compressionEnabled`, and the server's, both
false by default, as upstream behaves). Upstream offers only `none` and
never reads the compression lists. LogRaker turns it on from Settings:
logs compress many times over, which matters on slow and metered links.

- `Sources/NIOSSH/TransportProtection/SSHCompression.swift` (new) - the
  algorithm names, and one zlib stream per direction that lasts the
  connection, each packet ended with a partial flush. Inflating stops past
  256 KiB per packet (OpenSSH's `PACKET_MAX_SIZE`) or the connection's
  packet limit if larger, so a peer can't make one packet fill memory.
- `Sources/NIOSSH/Key Exchange/SSHKeyExchangeStateMachine.swift` - offers
  the list, negotiates it per direction (the first name on the client's
  list the server also has, RFC 4253 section 7.1), and says which one the
  keys about to take effect bring.
- `Sources/NIOSSH/Connection State Machine/Operations/AcceptsKeyExchangeMessages.swift`
  and `.../SendsKeyExchangeMessages.swift` - hand that to the parser and
  serializer with the keys.
- `Sources/NIOSSH/SSHPacketParser.swift` - inflates a packet after
  decrypting it, once compression has started.
- `Sources/NIOSSH/SSHPacketSerializer.swift` - compresses a message before
  padding and encrypting it, once compression has started; the framing is
  split out as `finishSSHPacket` so both paths share it.
- `Sources/NIOSSH/Connection State Machine/SSHConnectionStateMachine.swift` -
  starts both directions right after `SSH_MSG_USERAUTH_SUCCESS`, received
  (client) or sent (server): the "delayed" in OpenSSH's name, so nothing
  from an unauthenticated peer is ever inflated. A rekey keeps a running
  stream, as OpenSSH does.
- `Sources/NIOSSH/SSHClientConfiguration.swift`,
  `Sources/NIOSSH/SSHServerConfiguration.swift`, `Sources/NIOSSH/Role.swift` -
  the switch.

Plus `Tests/NIOSSHTests/LograkerCompressionTests.swift`: a compressed
connection carries data intact and smaller, a server without compression
falls back to `none`, it is off by default, it survives rekeys both ways,
the stream carries on across packets, and an oversized inflate is refused.
Checked against OpenSSH 8.9 too: 1,000 lines read back byte for byte as
the server's file holds them.

zlib comes from the platform (`import zlib`, under `canImport(zlib)`);
where it is missing, only `none` is ever offered.

Each of the nineteen modified files also carries a `MODIFIED in the LogRaker
fork` notice in its header block, below upstream's copyright and SPDX
lines, which is what Apache 2.0 section 4(b) asks for. The new files say
`ADDED in the LogRaker fork` instead.

## The signature-algorithm-name split

Upstream writes the publickey userauth algorithm-name field as
`key.keyPrefix`, because for ed25519 and the ECDSA curves the key
prefix and the signature algorithm name are the same string.

RSA is the one case where they differ. The public-key blob is still
tagged `ssh-rsa`, but the algorithm name must be `rsa-sha2-256` or
`rsa-sha2-512`: OpenSSH 8.8 (2021) disabled the SHA-1 `ssh-rsa`
signature algorithm by default, so offering that name is rejected
outright by any current server.

So the fork introduces `signatureAlgorithmName` alongside `keyPrefix`
and uses it in the two places that write the algorithm-name field.
Those two places MUST agree byte for byte - one is the wire message,
the other is the payload the signature is computed over, and a
mismatch shows up only as a server-side signature rejection.

We always offer `rsa-sha2-512`. nio-ssh does not parse
`SSH_MSG_EXT_INFO` / `server-sig-algs`, so there is nothing to
negotiate against; `rsa-sha2-512` has been accepted since OpenSSH 7.2
(2016), which covers anything LogRaker will realistically meet.

## Security fixes: none outstanding

**CVE-2026-43798 / GHSA-998x-vgvp-xwpc** (critical) was backported by
hand while this fork sat on 0.13.0. It is upstream as of 0.14.1, so
the rebase onto 0.15.0 dropped the backport - the fix now comes from
upstream, along with its regression test
(`Tests/NIOSSHTests/NIOSSHSignatureTests.swift`). Nothing here carries
a hand-applied security patch any more.

## Staying on top of upstream security fixes

Vendoring opts out of every automatic signal: a local SwiftPM package
never reports a new version, so nothing will tell you. Check
deliberately:

    gh api repos/apple/swift-nio-ssh/security-advisories \
      --jq '.[] | "\(.severity) \(.ghsa_id) \(.summary)"'

Advisories also cover the wider SwiftNIO family; swift-nio-ssh's own
`SECURITY.md` defers to `apple/swift-nio`.

Nothing pushes this at you. Dependabot on the fork watches our own
dependencies (swift-nio, swift-crypto, swift-atomics), NOT upstream
swift-nio-ssh. For a nudge when upstream ships a release, watch
apple/swift-nio-ssh in the GitHub UI: Watch > Custom > Releases. The
REST API cannot set a releases-only watch, only all-activity.

## Rebasing onto a newer upstream

The fork is published at https://github.com/lograker/swift-nio-ssh, on
branch `rsa-client-auth`, with `upstream` already wired to
apple/swift-nio-ssh. So this is ordinary git now, not a manual re-apply:

1. In a clone of the fork: `git fetch upstream --tags`.
2. `git rebase <new tag>` onto `rsa-client-auth`. Every hunk is marked
   `LOGRAKER FORK:`, so conflicts are easy to spot.
3. `swift test` in the clone.
4. Tag `<upstream version>-rsa.<n>` and push branch and tag.
5. Copy the tree back over `vendor/swift-nio-ssh/` here, excluding
   `.git`, `.build` and `.swiftpm`.
6. Rebuild LogRaker and run its SSH paths.

**Step 5 is the one that matters.** LogRaker builds from THIS vendored
copy, not from GitHub, so an upstream fix does not reach the app until
the tree is copied back.

**Watch the README names when copying.** The published repo has our
readme as `README.md` and upstream's as `README-upstream.md`. This
vendored tree has upstream's as `README.md` and ours as
`README-FORK.md`. A blind rsync in either direction clobbers one of
them.
