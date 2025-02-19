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
    private var context: SerializerContext

    /// Initialise a Binary HTTP Serialiser.
    /// - Parameters:
    ///   - type: The type of BHTTPSerializer you want: either known or indeterminate length.
    ///   - allocator: Byte buffer allocator used.
    public init(
        type: SerializerType = .indeterminateLength,
        allocator: ByteBufferAllocator = ByteBufferAllocator()
    ) {
        self.fsm = BHTTPSerializerFSM(initialState: BHTTPSerializerState.start)
        self.context = SerializerContext(type: type, allocator: allocator)
    }

    /// Serialise a message into a buffer using binary HTTP encoding.
    /// - Parameters:
    ///   - message: The message to serialise. File regions are currently not supported.
    ///   - buffer: Destination buffer to serialise into.
    public mutating func serialize(_ message: Message, into buffer: inout ByteBuffer) throws {
        switch message {
        case .request(.head(let requestHead)):
            try self.fsm.writeRequestHead(requestHead, into: &buffer, using: &self.context)

        case .response(.head(let responseHead)):
            try self.fsm.writeResponseHead(responseHead, into: &buffer, using: &self.context)

        case .request(.body(.byteBuffer(let body))), .response(.body(.byteBuffer(let body))):
            try self.fsm.writeBodyChunk(body, into: &buffer, using: &self.context)

        case .request(.body(.fileRegion)), .response(.body(.fileRegion)):
            throw ObliviousHTTPError.unsupportedOption(reason: "fileregion unsupported")

        case .request(.end(.some(let trailers))), .response(.end(.some(let trailers))):
            try self.fsm.writeTrailers(trailers, into: &buffer, using: &self.context)

        case .request(.end(.none)), .response(.end(.none)):
            try self.fsm.writeRequestEnd(into: &buffer, using: &self.context)
        }
    }


}

// Enum definitions for message, states, and types.
extension BHTTPSerializer {
    
    private struct SerializerContext {
        private var chunkBuffer: ByteBuffer
        private var fieldSectionBuffer: ByteBuffer
        private var type: SerializerType
        
        
        public init(
            type: SerializerType,
            allocator: ByteBufferAllocator = ByteBufferAllocator()
        ) {
            self.chunkBuffer = allocator.buffer(capacity: 0)
            self.fieldSectionBuffer = allocator.buffer(capacity: 0)
            self.type = type
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
        
        
        mutating func serializeRequestHead(_ head: HTTPRequestHead, into buffer: inout ByteBuffer) {
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
            case .indeterminateLength:
                Self.serializeIndeterminateLengthFieldSection(head.headers, into: &buffer)
            default: break
            }
        }

        mutating func serializeResponseHead(_ head: HTTPResponseHead, into buffer: inout ByteBuffer) {
            // First, the framing indicator
            buffer.writeVarint(responseFramingIndicator)

            buffer.writeVarint(Int(head.status.code))

            switch self.type {
            case .knownLength:
                self.stackKnownLengthFieldSection(head.headers)
                self.serializeKnownLengthFieldSection(into: &buffer)
            case .indeterminateLength:
                Self.serializeIndeterminateLengthFieldSection(head.headers, into: &buffer)
            default: break
            }
        }

        mutating func serializeChunk(_ chunk: ByteBuffer, into buffer: inout ByteBuffer) {
            switch self.type {
            case .knownLength:
                self.stackContentChunk(chunk)
            case .indeterminateLength:
                Self.serializeContentChunk(chunk, into: &buffer)
            default: break
            }
        }

        static func serializeContentChunk(_ chunk: ByteBuffer, into buffer: inout ByteBuffer) {
            if chunk.readableBytes == 0 { return }
            buffer.writeVarintPrefixedImmutableBuffer(chunk)
        }

        mutating func serializeStackedContent(into buffer: inout ByteBuffer) {
            if self.chunkBuffer.readableBytes == 0 { return }
            buffer.writeVarintPrefixedImmutableBuffer(self.chunkBuffer)
            self.chunkBuffer.clear()
        }

        mutating func stackContentChunk(_ chunk: ByteBuffer) {
            self.chunkBuffer.writeImmutableBuffer(chunk)
        }

        static func serializeIndeterminateLengthFieldSection(
            _ fields: HTTPHeaders,
            into buffer: inout ByteBuffer
        ) {
            for (name, value) in fields {
                buffer.writeVarintPrefixedString(name)
                buffer.writeVarintPrefixedString(value)
            }
            buffer.writeInteger(UInt8(0))  // End of field section
        }

        mutating func serializeTrailers(_ trailers: HTTPHeaders, into buffer: inout ByteBuffer) {
            switch self.type {
            case .knownLength:
                self.serializeStackedContent(into: &buffer)
                self.stackKnownLengthFieldSection(trailers)
            case .indeterminateLength:
                // Send a 0 to terminate the body, then a field section.
                buffer.writeInteger(UInt8(0))
                Self.serializeIndeterminateLengthFieldSection(trailers, into: &buffer)
            default: break
            }
        }


        mutating func endRequest(into buffer: inout ByteBuffer) {
            switch self.type {
            case .knownLength:
                self.serializeStackedContent(into: &buffer)
                self.serializeKnownLengthFieldSection(into: &buffer)
            case .indeterminateLength:
                buffer.writeInteger(UInt8(0))
            default: break
            }
        }
        
        mutating func stackKnownLengthFieldSection(_ fields: HTTPHeaders) {
            for (name, value) in fields {
                self.fieldSectionBuffer.writeVarintPrefixedString(name)
                self.fieldSectionBuffer.writeVarintPrefixedString(value)
            }
        }
        
        
        mutating func serializeKnownLengthFieldSection(into buffer: inout ByteBuffer) {
            buffer.writeVarintPrefixedImmutableBuffer(self.fieldSectionBuffer)
            self.fieldSectionBuffer.clear()
        }
    }
    
    // Finite State Machine for managing transitions in BHTTPSerializer.
    private struct BHTTPSerializerFSM {
        private var currentState: BHTTPSerializerState

        init(initialState: BHTTPSerializerState) {
            self.currentState = initialState
        }

        mutating func writeRequestHead(
            _ requestHead: HTTPRequestHead,
            into buffer: inout ByteBuffer,
            using context: inout SerializerContext
        ) throws {
            try self.transition(to: .header)
            context.serializeRequestHead(requestHead, into: &buffer)
        }

        mutating func writeResponseHead(
            _ responseHead: HTTPResponseHead,
            into buffer: inout ByteBuffer,
            using context: inout SerializerContext
        ) throws {
            try self.transition(to: .header)
            context.serializeResponseHead(responseHead, into: &buffer)
        }

        mutating func writeRequestEnd(
            into buffer: inout ByteBuffer,
            using context: inout SerializerContext
        ) throws {
            context.endRequest(into: &buffer)
            try self.transition(to: .end)
        }
        mutating func writeBodyChunk(
            _ body: ByteBuffer,
            into buffer: inout ByteBuffer,
            using context: inout SerializerContext
        ) throws {
            context.serializeChunk(body, into: &buffer)
            try self.transition(to: .chunk)
        }

        mutating func writeTrailers(
            _ trailers: HTTPHeaders,
            into buffer: inout ByteBuffer,
            using context: inout SerializerContext
        ) throws {
            context.serializeTrailers(trailers, into: &buffer)
            try self.transition(to: .trailers)
        }

        private mutating func transition(to state: BHTTPSerializerState) throws {
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

    public struct SerializerType: Hashable, Sendable {
        private enum InternalType: Hashable {
            case knownLength
            case indeterminateLength
        }

        private let type: InternalType

        public static let knownLength = SerializerType(type: .knownLength)
        public static let indeterminateLength = SerializerType(type: .indeterminateLength)

        private init(type: InternalType) {
            self.type = type
        }

    }

    internal struct FramingIndicator {
        static var requestKnownLength: Int { 0 }
        static var responseKnownLength: Int { 1 }
        static var requestIndeterminateLength: Int { 2 }
        static var responseIndeterminateLength: Int { 3 }
    }

    internal enum BHTTPSerializerState {
        case start
        case header
        case chunk
        case trailers
        case end
    }
}
