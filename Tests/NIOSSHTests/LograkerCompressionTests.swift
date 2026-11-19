//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
// ADDED in the LogRaker fork of swift-nio-ssh: tests for transport
// compression (`zlib@openssh.com`). See FORK.md.
//
// LOGRAKER FORK: the whole file.
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

/// Collects the channel data a child channel receives.
private final class DataCollector: ChannelInboundHandler {
    typealias InboundIn = SSHChannelData

    var received = ByteBuffer()

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if case .byteBuffer(var bytes) = self.unwrapInboundIn(data).data {
            self.received.writeBuffer(&bytes)
        }
    }
}

/// A client and a server in memory, either side offering compression or
/// not, counting the bytes each puts on the wire.
private final class CompressionPair {
    let loop = EmbeddedEventLoop()
    let client: EmbeddedChannel
    let server: EmbeddedChannel
    var clientToServerBytes = 0
    var serverToClientBytes = 0
    var serverCollectors: [DataCollector] = []
    var serverChannels: [Channel] = []

    init(clientCompression: Bool, serverCompression: Bool) throws {
        self.client = EmbeddedChannel(loop: self.loop)
        self.server = EmbeddedChannel(loop: self.loop)

        var clientConfiguration = SSHClientConfiguration(
            userAuthDelegate: InfinitePasswordDelegate(),
            serverAuthDelegate: AcceptAllHostKeysDelegate()
        )
        clientConfiguration.compressionEnabled = clientCompression
        var serverConfiguration = SSHServerConfiguration(
            hostKeys: [.init(ed25519Key: .init())],
            userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 0)
        )
        serverConfiguration.compressionEnabled = serverCompression

        let clientHandler = NIOSSHHandler(
            role: .client(clientConfiguration),
            allocator: self.client.allocator,
            inboundChildChannelInitializer: nil
        )
        let serverHandler = NIOSSHHandler(role: .server(serverConfiguration), allocator: self.server.allocator) {
            channel,
            _ in
            let collector = DataCollector()
            self.serverCollectors.append(collector)
            self.serverChannels.append(channel)
            return channel.pipeline.addHandler(collector)
        }
        try self.client.pipeline.syncOperations.addHandler(clientHandler)
        try self.server.pipeline.syncOperations.addHandler(serverHandler)
        try self.client.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
        try self.server.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
        try self.interact()
    }

    var clientHandler: NIOSSHHandler {
        try! self.client.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
    }

    var serverHandler: NIOSSHHandler {
        try! self.server.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
    }

    func interact() throws {
        var workToDo = true
        while workToDo {
            workToDo = false
            self.loop.run()
            if let datum = try self.client.readOutbound(as: IOData.self) {
                self.clientToServerBytes += datum.readableBytes
                try self.server.writeInbound(datum)
                workToDo = true
            }
            if let datum = try self.server.readOutbound(as: IOData.self) {
                self.serverToClientBytes += datum.readableBytes
                try self.client.writeInbound(datum)
                workToDo = true
            }
        }
    }

    func openChannel() throws -> Channel {
        var opened: Channel?
        self.clientHandler.createChannel { channel, _ in
            opened = channel
            return channel.eventLoop.makeSucceededFuture(())
        }
        try self.interact()
        return try XCTUnwrap(opened)
    }

    /// Sends `payload` from the client in `chunk`-sized writes, returning
    /// the bytes that put on the wire.
    func send(_ payload: ByteBuffer, over channel: Channel, chunk: Int = 4096) throws -> Int {
        let before = self.clientToServerBytes
        var payload = payload
        while let piece = payload.readSlice(length: min(chunk, payload.readableBytes)), piece.readableBytes > 0 {
            channel.write(SSHChannelData(type: .channel, data: .byteBuffer(piece)), promise: nil)
        }
        channel.flush()
        try self.interact()
        return self.clientToServerBytes - before
    }

    func finish() throws {
        _ = try self.client.finish(acceptAlreadyClosed: true)
        _ = try self.server.finish(acceptAlreadyClosed: true)
        try self.loop.syncShutdownGracefully()
    }
}

/// Log-like text: repetitive, as real logs are.
private func logText(lines: Int) -> ByteBuffer {
    var buffer = ByteBuffer()
    for i in 0..<lines {
        buffer.writeString("2026-11-19 10:\(i % 60):\(i % 60) INFO worker-\(i % 8) request \(i) served in \(i % 97) ms\n")
    }
    return buffer
}

final class LograkerCompressionTests: XCTestCase {
    func testCompressedConnectionCarriesDataIntactAndSmaller() throws {
        let pair = try CompressionPair(clientCompression: true, serverCompression: true)
        let channel = try pair.openChannel()
        let payload = logText(lines: 5000)
        let wire = try pair.send(payload, over: channel)

        XCTAssertEqual(pair.serverCollectors.first?.received, payload)
        // Log text compresses many times over; anything near the payload's
        // size means it went uncompressed.
        XCTAssertLessThan(wire, payload.readableBytes / 4)
        try pair.finish()
    }

    func testServerWithoutCompressionFallsBackToNone() throws {
        let pair = try CompressionPair(clientCompression: true, serverCompression: false)
        let channel = try pair.openChannel()
        let payload = logText(lines: 2000)
        let wire = try pair.send(payload, over: channel)

        XCTAssertEqual(pair.serverCollectors.first?.received, payload)
        XCTAssertGreaterThan(wire, payload.readableBytes)
        try pair.finish()
    }

    func testCompressionOffByDefault() throws {
        XCTAssertFalse(
            SSHClientConfiguration(
                userAuthDelegate: InfinitePasswordDelegate(),
                serverAuthDelegate: AcceptAllHostKeysDelegate()
            ).compressionEnabled
        )
        let pair = try CompressionPair(clientCompression: false, serverCompression: true)
        let channel = try pair.openChannel()
        let payload = logText(lines: 2000)
        XCTAssertGreaterThan(try pair.send(payload, over: channel), payload.readableBytes)
        try pair.finish()
    }

    func testCompressionSurvivesRekeying() throws {
        let pair = try CompressionPair(clientCompression: true, serverCompression: true)
        let channel = try pair.openChannel()
        let first = logText(lines: 1000)
        _ = try pair.send(first, over: channel)

        try pair.clientHandler._rekey()
        try pair.interact()
        try pair.serverHandler._rekey()
        try pair.interact()

        let second = logText(lines: 3000)
        let wire = try pair.send(second, over: channel)
        var expected = first
        var rest = second
        expected.writeBuffer(&rest)
        XCTAssertEqual(pair.serverCollectors.first?.received, expected)
        XCTAssertLessThan(wire, second.readableBytes / 4)
        try pair.finish()
    }

    func testStreamCarriesOnAcrossPackets() throws {
        let compressor = try SSHCompressionStream(direction: .compress)
        let decompressor = try SSHCompressionStream(direction: .decompress)
        for i in 0..<50 {
            let message = SSHMessage.ignore(.init(data: logText(lines: i * 3 + 1)))
            var packet = ByteBuffer()
            _ = try compressor.compress(message, into: &packet)
            var inflated = try decompressor.decompress(packet)
            XCTAssertEqual(try inflated.readSSHMessage(), message)
        }
    }

    func testInflatingPastTheLimitIsRefused() throws {
        let compressor = try SSHCompressionStream(direction: .compress)
        let decompressor = try SSHCompressionStream(direction: .decompress)
        // Zeros compress to almost nothing: a small packet that would
        // inflate past the limit.
        let huge = ByteBuffer(repeating: 0, count: SSHCompressionStream.minimumInflatedPayloadLimit * 4)
        var packet = ByteBuffer()
        _ = try compressor.compress(.ignore(.init(data: huge)), into: &packet)
        XCTAssertLessThan(packet.readableBytes, 4096)
        XCTAssertThrowsError(try decompressor.decompress(packet))
    }

    func testNegotiationPrefersTheClientsList() {
        XCTAssertEqual(
            SSHCompressionAlgorithm.offered(compressionEnabled: true),
            [SSHCompressionAlgorithm.zlibOpenSSHName, SSHCompressionAlgorithm.noneName]
        )
        XCTAssertEqual(SSHCompressionAlgorithm.offered(compressionEnabled: false), [SSHCompressionAlgorithm.noneName])
        XCTAssertNil(SSHCompressionAlgorithm(name: "zlib"))
    }
}
