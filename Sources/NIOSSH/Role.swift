//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
// MODIFIED in the LogRaker fork of swift-nio-ssh, which adds transport
// compression (`zlib@openssh.com`). Every change is marked
// `LOGRAKER FORK:` below. See FORK.md for the upstream revision and the
// rebase procedure.
//
//===----------------------------------------------------------------------===//

/// The role of a given party in an SSH connection.
public enum SSHConnectionRole {
    /// This entity is an SSH client.
    case client(SSHClientConfiguration)

    /// This entity is an SSH server.
    case server(SSHServerConfiguration)

    internal var isClient: Bool {
        switch self {
        case .client:
            return true
        case .server:
            return false
        }
    }

    internal var isServer: Bool {
        switch self {
        case .client:
            return false
        case .server:
            return true
        }
    }

    internal var transportProtectionSchemes: [NIOSSHTransportProtection.Type] {
        switch self {
        case .client(let configuration):
            return configuration.transportProtectionSchemes
        case .server(let configuration):
            return configuration.transportProtectionSchemes
        }
    }

    // LOGRAKER FORK: whether this peer offers transport compression.
    internal var compressionEnabled: Bool {
        switch self {
        case .client(let configuration):
            return configuration.compressionEnabled
        case .server(let configuration):
            return configuration.compressionEnabled
        }
    }

    /// The maximum size of a channel data payload this peer advertises it is willing to receive,
    /// and against which inbound encrypted packets are bounded.
    internal var maximumPacketSize: UInt32 {
        switch self {
        case .client(let configuration):
            return UInt32(truncatingIfNeeded: configuration.maximumPacketSize)
        case .server(let configuration):
            return UInt32(truncatingIfNeeded: configuration.maximumPacketSize)
        }
    }
}

@available(*, unavailable)
extension SSHConnectionRole: Sendable {}
