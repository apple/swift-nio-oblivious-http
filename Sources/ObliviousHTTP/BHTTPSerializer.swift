//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import NIOCore
import NIOHTTP1

// For now this type is entirely stateless, which is achieved by using the indefinite-length encoding.
// It also means it does not enforce correctness, and so can produce invalid encodings if a user holds
// it wrong.
//
// Later optimizations can be made by adding more state into this type.
/// Binary HTTP serialiser as described in [RFC9292](https://www.rfc-editor.org/rfc/rfc9292).
/// Currently only indeterminate-length encoding is supported.
public struct BHTTPSerializer {
    /// Initialise a Binary HTTP Serialiser.
    public init() {}

    /// Serialise a message into a buffer using binary HTTP encoding.
    /// - Parameters:
    ///   - message: The message to serialise.  File regions are currently not supported.
    ///   - buffer: Destination buffer to serialise into.
    public func serialize(_ message: Message, into buffer: inout ByteBuffer) {
        switch message {
        case .request(.head(let requestHead)):
            Self.serializeRequestHead(requestHead, into: &buffer)
        case .response(.head(let responseHead)):
            Self.serializeResponseHead(responseHead, into: &buffer)
        case .request(.body(.byteBuffer(let body))), .response(.body(.byteBuffer(let body))):
            Self.serializeContentChunk(body, into: &buffer)
        case .request(.body(.fileRegion)), .response(.body(.fileRegion)):
            fatalError("fileregion unsupported")
        case .request(.end(.some(let trailers))), .response(.end(.some(let trailers))):
            // Send a 0 to terminate the body, then a field section.
            buffer.writeInteger(UInt8(0))
            Self.serializeIndeterminateLengthFieldSection(trailers, into: &buffer)
        case .request(.end(.none)), .response(.end(.none)):
            // We can omit the trailers in this context, but we will always send a zero
            // byte, either to communicate no trailers or no body.
            buffer.writeInteger(UInt8(0))
        }
    }

    private static func serializeRequestHead(_ head: HTTPRequestHead, into buffer: inout ByteBuffer) {
        // First, the framing indicator. 2 for indeterminate length request.
        buffer.writeVarint(2)

        let method = head.method
        let scheme = "https"  // Hardcoded for now, but not really the right option.
        let path = head.uri
        let authority = head.headers["Host"].first ?? ""

        buffer.writeVarintPrefixedString(method.rawValue)
        buffer.writeVarintPrefixedString(scheme)
        buffer.writeVarintPrefixedString(authority)
        buffer.writeVarintPrefixedString(path)

        Self.serializeIndeterminateLengthFieldSection(head.headers, into: &buffer)
    }

    private static func serializeResponseHead(_ head: HTTPResponseHead, into buffer: inout ByteBuffer) {
        // First, the framing indicator. 3 for indeterminate length response.
        buffer.writeVarint(3)
        buffer.writeVarint(Int(head.status.code))
        Self.serializeIndeterminateLengthFieldSection(head.headers, into: &buffer)
    }

    private static func serializeContentChunk(_ chunk: ByteBuffer, into buffer: inout ByteBuffer) {
        // Omit zero-length chunks.
        if chunk.readableBytes == 0 { return }
        buffer.writeVarintPrefixedImmutableBuffer(chunk)
    }

    private static func serializeIndeterminateLengthFieldSection(
        _ fields: HTTPHeaders,
        into buffer: inout ByteBuffer
    ) {
        for (name, value) in fields {
            buffer.writeVarintPrefixedString(name)
            buffer.writeVarintPrefixedString(value)
        }
        // This is technically a varint but we can skip the check there because we know it can always encode in one byte.
        buffer.writeInteger(UInt8(0))
    }

}

extension BHTTPSerializer {
    /// Types of message for binary http serilaisation
    public enum Message {
        /// Part of an HTTP request.
        case request(HTTPClientRequestPart)
        /// Part of an HTTP response.
        case response(HTTPServerResponsePart)
    }
}
