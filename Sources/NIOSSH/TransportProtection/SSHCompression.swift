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
// ADDED in the LogRaker fork of swift-nio-ssh: transport compression
// (`zlib@openssh.com`). Not in upstream. See FORK.md.
//
//===----------------------------------------------------------------------===//

import NIOCore

#if canImport(zlib)
import zlib
#endif

// LOGRAKER FORK: SSH transport compression, OpenSSH's delayed form.
//
// `zlib@openssh.com` (OpenSSH PROTOCOL, section 1.2) is zlib (RFC 1950)
// over the payload of every packet, one stream per direction for the
// whole connection, each packet ended with a partial flush so nothing
// waits for the next. It starts only once user authentication has
// succeeded, so nothing a peer sends before it is authenticated is ever
// inflated; that is why it's the only form offered. It is not reset by a
// rekey.

/// A compression algorithm negotiated in the key exchange.
enum SSHCompressionAlgorithm: Equatable {
    case none
    case zlibOpenSSH

    static let noneName: Substring = "none"
    static let zlibOpenSSHName: Substring = "zlib@openssh.com"

    init?(name: Substring) {
        switch name {
        case Self.noneName: self = .none
        case Self.zlibOpenSSHName where Self.zlibAvailable: self = .zlibOpenSSH
        default: return nil
        }
    }

    /// Whether this build can compress at all.
    static var zlibAvailable: Bool {
        #if canImport(zlib)
        true
        #else
        false
        #endif
    }

    /// The names a peer offers in its key exchange, preferred first.
    static func offered(compressionEnabled: Bool) -> [Substring] {
        compressionEnabled && Self.zlibAvailable ? [Self.zlibOpenSSHName, Self.noneName] : [Self.noneName]
    }
}

#if canImport(zlib)

/// One direction's zlib stream, kept for the life of the connection.
final class SSHCompressionStream {
    enum Direction {
        case compress
        case decompress
    }

    /// The most a single packet may inflate to: OpenSSH's own packet
    /// limit (`PACKET_MAX_SIZE`), unless the connection allows larger
    /// packets. A peer can't make one packet fill memory.
    static let minimumInflatedPayloadLimit = 256 * 1024

    /// Bytes of output room asked for per zlib call.
    private static let outputChunk = 16 * 1024

    private let direction: Direction
    /// zlib keeps a pointer back to its stream, so the stream must not
    /// move: it lives in memory of its own, not in a Swift property.
    private let stream: UnsafeMutablePointer<z_stream>
    private let inflatedPayloadLimit: Int
    /// Where a message is written before it's compressed, reused.
    private var scratch = ByteBuffer()

    init(direction: Direction, inflatedPayloadLimit: Int = SSHCompressionStream.minimumInflatedPayloadLimit) throws {
        self.direction = direction
        self.inflatedPayloadLimit = max(inflatedPayloadLimit, Self.minimumInflatedPayloadLimit)
        self.stream = .allocate(capacity: 1)
        self.stream.initialize(to: z_stream())
        let status: Int32
        switch direction {
        case .compress:
            status = deflateInit_(self.stream, Z_DEFAULT_COMPRESSION, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        case .decompress:
            status = inflateInit_(self.stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        }
        guard status == Z_OK else {
            self.stream.deinitialize(count: 1)
            self.stream.deallocate()
            throw Self.failure("zlib could not start (\(status))")
        }
    }

    deinit {
        switch self.direction {
        case .compress: deflateEnd(self.stream)
        case .decompress: inflateEnd(self.stream)
        }
        self.stream.deinitialize(count: 1)
        self.stream.deallocate()
    }

    /// Writes `message` to `buffer`, compressed and flushed so the peer
    /// can inflate it on its own. Returns the bytes written.
    func compress(_ message: SSHMessage, into buffer: inout ByteBuffer) throws -> Int {
        precondition(self.direction == .compress)
        self.scratch.clear()
        self.scratch.writeSSHMessage(message)
        return try self.scratch.withUnsafeReadableBytes { input in
            try self.run(input: input, flush: Z_PARTIAL_FLUSH, into: &buffer, limit: nil)
        }
    }

    /// The payload `compressed` inflates to.
    func decompress(_ compressed: ByteBuffer) throws -> ByteBuffer {
        precondition(self.direction == .decompress)
        var output = ByteBuffer()
        output.reserveCapacity(min(self.inflatedPayloadLimit, compressed.readableBytes * 4 + Self.outputChunk))
        _ = try compressed.withUnsafeReadableBytes { input in
            try self.run(input: input, flush: Z_PARTIAL_FLUSH, into: &output, limit: self.inflatedPayloadLimit)
        }
        return output
    }

    /// Feeds all of `input` through the stream, appending what comes out
    /// to `output`, until zlib has nothing more to give for it.
    private func run(input: UnsafeRawBufferPointer, flush: Int32, into output: inout ByteBuffer, limit: Int?) throws -> Int {
        // zlib reads `next_in` but doesn't write it; the type is mutable
        // only because zlib.h is built without ZLIB_CONST.
        self.stream.pointee.next_in = UnsafeMutablePointer(
            mutating: input.baseAddress?.assumingMemoryBound(to: Bytef.self)
        )
        self.stream.pointee.avail_in = uInt(input.count)
        defer {
            self.stream.pointee.next_in = nil
            self.stream.pointee.avail_in = 0
        }
        var produced = 0
        while true {
            var status: Int32 = Z_OK
            var filled = false
            let written = output.writeWithUnsafeMutableBytes(minimumWritableBytes: Self.outputChunk) { room in
                self.stream.pointee.next_out = room.baseAddress!.assumingMemoryBound(to: Bytef.self)
                self.stream.pointee.avail_out = uInt(room.count)
                switch self.direction {
                case .compress: status = deflate(self.stream, flush)
                case .decompress: status = inflate(self.stream, flush)
                }
                let written = room.count - Int(self.stream.pointee.avail_out)
                filled = self.stream.pointee.avail_out == 0
                self.stream.pointee.next_out = nil
                self.stream.pointee.avail_out = 0
                return written
            }
            produced += written
            if let limit, produced > limit {
                throw Self.failure("a packet inflated past \(limit) bytes")
            }
            switch status {
            case Z_OK:
                // Room ran out: there may be more. Otherwise all of the
                // input is in and flushed.
                if !filled, self.stream.pointee.avail_in == 0 { return produced }
            case Z_BUF_ERROR:
                // No progress possible: everything is out.
                guard self.stream.pointee.avail_in == 0 else { throw Self.failure("zlib stalled") }
                return produced
            default:
                // Z_STREAM_END too: the stream lasts the whole connection.
                throw Self.failure("zlib failed (\(status))")
            }
        }
    }

    private static func failure(_ violation: String) -> NIOSSHError {
        NIOSSHError.protocolViolation(protocolName: "compression", violation: violation)
    }
}

extension ByteBuffer {
    /// As `writeSSHPacket(message:lengthEncrypted:blockSize:)`, with the
    /// payload compressed by `compressor`.
    mutating func writeSSHPacket(
        message: SSHMessage,
        lengthEncrypted: Bool,
        blockSize: Int,
        compressor: SSHCompressionStream
    ) throws {
        let index = self.writerIndex
        self.writeMultipleIntegers(UInt32(0), UInt8(0))
        let messageLength = try compressor.compress(message, into: &self)
        self.finishSSHPacket(at: index, messageLength: messageLength, lengthEncrypted: lengthEncrypted, blockSize: blockSize)
    }
}

#else

/// Without zlib nothing is ever negotiated but `none`, so no stream is
/// ever made.
final class SSHCompressionStream {
    enum Direction {
        case compress
        case decompress
    }

    init(direction: Direction, inflatedPayloadLimit: Int = 0) throws {
        throw NIOSSHError.protocolViolation(protocolName: "compression", violation: "zlib is not available")
    }

    func decompress(_ compressed: ByteBuffer) throws -> ByteBuffer { compressed }
}

extension ByteBuffer {
    mutating func writeSSHPacket(
        message: SSHMessage,
        lengthEncrypted: Bool,
        blockSize: Int,
        compressor: SSHCompressionStream
    ) throws {
        self.writeSSHPacket(message: message, lengthEncrypted: lengthEncrypted, blockSize: blockSize)
    }
}

#endif
