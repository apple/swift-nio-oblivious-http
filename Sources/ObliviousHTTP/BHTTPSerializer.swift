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

/// Binary HTTP serialiser as described in [RFC9292](https://www.rfc-editor.org/rfc/rfc9292).
public struct BHTTPSerializer {

    private var fsm: BHTTPSerializerFSM
    public var type: SerializerType
    private var chunkBuffer: ByteBuffer
    private var fieldSectionBuffer: ByteBuffer

    /// Initialise a Binary HTTP Serialiser.
    /// - Parameters:
    ///   - type: The type of BHTTPSerializer you want: either known or indeterminate length.
    ///   - allocator: Byte buffer allocator used.
    public init(
        type: SerializerType = .indeterminateLength,
        allocator: ByteBufferAllocator = ByteBufferAllocator()
    ) {
        self.type = type
        self.chunkBuffer = allocator.buffer(capacity: 0)
        self.fieldSectionBuffer = allocator.buffer(capacity: 0)
        self.fsm = BHTTPSerializerFSM(initialState: BHTTPSerializerState.start)
    }

    private var requestFramingIndicator: Int {
        switch self.type {
        case .knownLength:
            return FramingIndicator.requestKnownLength
        default:
            return FramingIndicator.requestIndeterminateLength
        }
    }

    private var responseFramingIndicator: Int {
        switch self.type {
        case .knownLength:
            return FramingIndicator.responseKnownLength
        default:
            return FramingIndicator.responseIndeterminateLength
        }
    }

    /// Serialise a message into a buffer using binary HTTP encoding.
    /// - Parameters:
    ///   - message: The message to serialise. File regions are currently not supported.
    ///   - buffer: Destination buffer to serialise into.
    public mutating func serialize(_ message: Message, into buffer: inout ByteBuffer) throws {
        switch message {
        case .request(.head(let requestHead)):
            try self.fsm.writeRequestHead(requestHead, into: &buffer, using: &self)

        case .response(.head(let responseHead)):
            try self.fsm.writeResponseHead(responseHead, into: &buffer, using: &self)

        case .request(.body(.byteBuffer(let body))), .response(.body(.byteBuffer(let body))):
            try self.fsm.writeBodyChunk(body, into: &buffer, using: &self)

        case .request(.body(.fileRegion)), .response(.body(.fileRegion)):
            throw ObliviousHTTPError.unsupportedOption(reason: "fileregion unsupported")

        case .request(.end(.some(let trailers))), .response(.end(.some(let trailers))):
            try self.fsm.writeTrailers(trailers, into: &buffer, using: &self)

        case .request(.end(.none)), .response(.end(.none)):
            try self.fsm.writeRequestEnd(into: &buffer, using: &self)
        }
    }

    private mutating func serializeRequestHead(_ head: HTTPRequestHead, into buffer: inout ByteBuffer) {
        // First, the framing indicator
        buffer.writeVarint(requestFramingIndicator)

        let method = head.method
        let scheme = "https"  // Hardcoded for now, but not really the right option.
        let path = head.uri
        let authority = head.headers["Host"].first ?? ""

        buffer.writeVarintPrefixedString(method.rawValue)
        buffer.writeVarintPrefixedString(scheme)
        buffer.writeVarintPrefixedString(authority)
        buffer.writeVarintPrefixedString(path)

        switch self.type {
        case .knownLength:
            self.stackKnownLengthFieldSection(head.headers)
            self.serializeKnownLengthFieldSection(into: &buffer)
            break
        default:
            Self.serializeIndeterminateLengthFieldSection(head.headers, into: &buffer)
        }
    }

    private mutating func serializeResponseHead(_ head: HTTPResponseHead, into buffer: inout ByteBuffer) {
        // First, the framing indicator
        buffer.writeVarint(responseFramingIndicator)

        buffer.writeVarint(Int(head.status.code))

        switch self.type {
        case .knownLength:
            self.stackKnownLengthFieldSection(head.headers)
            self.serializeKnownLengthFieldSection(into: &buffer)
            break
        default:
            Self.serializeIndeterminateLengthFieldSection(head.headers, into: &buffer)
        }
    }

    private mutating func serializeChunk(_ chunk: ByteBuffer, into buffer: inout ByteBuffer) {
        switch self.type {
        case .knownLength:
            self.stackContentChunk(chunk)
            break
        default:
            Self.serializeContentChunk(chunk, into: &buffer)
        }
    }

    private static func serializeContentChunk(_ chunk: ByteBuffer, into buffer: inout ByteBuffer) {
        if chunk.readableBytes == 0 { return }
        buffer.writeVarintPrefixedImmutableBuffer(chunk)
    }

    private mutating func serializeContent(into buffer: inout ByteBuffer) {
        if self.chunkBuffer.readableBytes == 0 { return }
        buffer.writeVarintPrefixedImmutableBuffer(self.chunkBuffer)
        self.chunkBuffer.clear()
    }

    private mutating func stackContentChunk(_ chunk: ByteBuffer) {
        self.chunkBuffer.writeImmutableBuffer(chunk)
    }

    private static func serializeIndeterminateLengthFieldSection(
        _ fields: HTTPHeaders,
        into buffer: inout ByteBuffer
    ) {
        for (name, value) in fields {
            buffer.writeVarintPrefixedString(name)
            buffer.writeVarintPrefixedString(value)
        }
        buffer.writeInteger(UInt8(0))  // End of field section
    }

    private mutating func serializeTrailers(_ trailers: HTTPHeaders, into buffer: inout ByteBuffer) {
        switch self.type {
        case .knownLength:
            self.serializeContent(into: &buffer)
            self.stackKnownLengthFieldSection(trailers)
            break
        default:
            // Send a 0 to terminate the body, then a field section.
            buffer.writeInteger(UInt8(0))
            Self.serializeIndeterminateLengthFieldSection(trailers, into: &buffer)
        }
    }

    private mutating func serializeKnownLengthFieldSection(into buffer: inout ByteBuffer) {
        buffer.writeVarintPrefixedImmutableBuffer(self.fieldSectionBuffer)
        self.fieldSectionBuffer.clear()
    }

    private mutating func stackKnownLengthFieldSection(_ fields: HTTPHeaders) {
        for (name, value) in fields {
            self.fieldSectionBuffer.writeVarintPrefixedString(name)
            self.fieldSectionBuffer.writeVarintPrefixedString(value)
        }
    }

    private mutating func endRequest(into buffer: inout ByteBuffer) {
        switch self.type {
        case .knownLength:
            self.serializeContent(into: &buffer)
            self.serializeKnownLengthFieldSection(into: &buffer)
            break
        default:
            buffer.writeInteger(UInt8(0))
        }
    }
}

// Enum definitions for message, states, and types.
extension BHTTPSerializer {
    // Finite State Machine for managing transitions in BHTTPSerializer.
    public class BHTTPSerializerFSM {
        private(set) var currentState: BHTTPSerializerState

        init(initialState: BHTTPSerializerState) {
            self.currentState = initialState
        }

        func writeRequestHead(
            _ requestHead: HTTPRequestHead,
            into buffer: inout ByteBuffer,
            using serializer: inout BHTTPSerializer
        ) throws {
            try self.transition(to: .header)
            serializer.serializeRequestHead(requestHead, into: &buffer)
        }

        func writeResponseHead(
            _ responseHead: HTTPResponseHead,
            into buffer: inout ByteBuffer,
            using serializer: inout BHTTPSerializer
        ) throws {
            try self.transition(to: .header)
            serializer.serializeResponseHead(responseHead, into: &buffer)
        }


        func writeRequestEnd(
            into buffer: inout ByteBuffer,
            using serializer: inout BHTTPSerializer
        ) throws {
            serializer.endRequest(into: &buffer)
            try self.transition(to: .end)
        }
        func writeBodyChunk(
            _ body: ByteBuffer,
            into buffer: inout ByteBuffer,
            using serializer: inout BHTTPSerializer
        ) throws {
            serializer.serializeChunk(body, into: &buffer)
            try self.transition(to: .chunk)
        }

        func writeTrailers(
            _ trailers: HTTPHeaders,
            into buffer: inout ByteBuffer,
            using serializer: inout BHTTPSerializer
        ) throws {
            serializer.serializeTrailers(trailers, into: &buffer)
            try self.transition(to: .trailers)
        }

        func transition(to state: BHTTPSerializerState) throws {
            let allowedNextStates: Set<BHTTPSerializerState>
            switch currentState {
            case .start:
                allowedNextStates = [.header]
            case .header:
                allowedNextStates = [.chunk, .trailers, .end]
            case .chunk:
                allowedNextStates = [.trailers, .end, .chunk]
            case .trailers:
                allowedNextStates = [.trailers, .end]
            case .end:
                allowedNextStates = []
            }
            guard allowedNextStates.contains(state) else {
                throw ObliviousHTTPError.unexpectedHTTPMessageSection()
            }
            currentState = state
        }
    }

    public enum Message {
        case request(HTTPClientRequestPart)
        case response(HTTPServerResponsePart)
    }

    public struct SerializerType: Equatable {
        private enum InternalType: Equatable {
            case knownLength
            case indeterminateLength
        }

        private let type: InternalType

        public static let knownLength = SerializerType(type: .knownLength)
        public static let indeterminateLength = SerializerType(type: .indeterminateLength)

        private init(type: InternalType) {
            self.type = type
        }

        public static func == (lop: SerializerType, rop: SerializerType) -> Bool {
            lop.type == rop.type
        }
    }

    internal struct FramingIndicator {
        static var requestKnownLength: Int { 0 }
        static var responseKnownLength: Int { 1 }
        static var requestIndeterminateLength: Int { 2 }
        static var responseIndeterminateLength: Int { 3 }
    }

    public enum BHTTPSerializerState {
        case start
        case header
        case chunk
        case trailers
        case end
    }
}
