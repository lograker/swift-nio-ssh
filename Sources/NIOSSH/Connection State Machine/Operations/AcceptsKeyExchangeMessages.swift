//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
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

protocol AcceptsKeyExchangeMessages {
    var keyExchangeStateMachine: SSHKeyExchangeStateMachine { get set }

    var parser: SSHPacketParser { get set }
}

extension AcceptsKeyExchangeMessages {
    mutating func receiveKeyExchangeMessage(
        _ message: SSHMessage.KeyExchangeMessage
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let message = try self.keyExchangeStateMachine.handle(keyExchange: message)

        if let message = message {
            return .emitMessage(message)
        } else {
            return .noMessage
        }
    }

    mutating func receiveKeyExchangeInitMessage(
        _ message: SSHMessage.KeyExchangeECDHInitMessage
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let message = try self.keyExchangeStateMachine.handle(keyExchangeInit: message)

        if let message = message {
            return .emitMessage(message)
        } else {
            return .noMessage
        }
    }

    mutating func receiveKeyExchangeReplyMessage(
        _ message: SSHMessage.KeyExchangeECDHReplyMessage
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let message = try self.keyExchangeStateMachine.handle(keyExchangeReply: message)
        return .possibleFutureMessage(message)
    }

    mutating func receiveNewKeysMessage() throws {
        // Received a new keys message. Apply the encryption keys to the parser.
        // LOGRAKER FORK: the compression that comes with these keys.
        let compression = self.keyExchangeStateMachine.negotiatedCompression.inbound
        let result = try self.keyExchangeStateMachine.handleNewKeys()
        self.parser.addEncryption(result, compression: compression)
    }
}
