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
    private var type: BHTTPSerializerType
    private var chunkBuffer: ByteBuffer
    private var fieldSectionBuffer: ByteBuffer

    /// Initialise a Binary HTTP Serialiser.
    /// - Parameters:
    ///   - type: The type of BHTTPSerializer you want: either known or indeterminate length.
    ///   - allocator: Byte buffer allocator used.
    public init(
        type: BHTTPSerializerType = .indeterminateLength,
        allocator: ByteBufferAllocator = ByteBufferAllocator()
    ) {
        self.type = type
        self.chunkBuffer = allocator.buffer(capacity: 0)
        self.fieldSectionBuffer = allocator.buffer(capacity: 0)
        self.fsm = BHTTPSerializerFSM(initialState: BHTTPSerializerState.HEADER)
    }

    /// Serialise a message into a buffer using binary HTTP encoding.
    /// - Parameters:
    ///   - message: The message to serialise. File regions are currently not supported.
    ///   - buffer: Destination buffer to serialise into.
    public mutating func serialize(_ message: Message, into buffer: inout ByteBuffer) throws {
        switch message {
        case .request(.head(let requestHead)):
            try self.fsm.ensureState([BHTTPSerializerState.HEADER])
            self.serializeRequestHead(requestHead, into: &buffer)
            try self.fsm.transition(to: BHTTPSerializerState.CHUNK)

        case .response(.head(let responseHead)):
            try self.fsm.ensureState([BHTTPSerializerState.HEADER])
            self.serializeResponseHead(responseHead, into: &buffer)
            try self.fsm.transition(to: BHTTPSerializerState.CHUNK)

        case .request(.body(.byteBuffer(let body))), .response(.body(.byteBuffer(let body))):
            try self.fsm.ensureState([BHTTPSerializerState.CHUNK])
            switch self.type {
            case .indeterminateLength:
                Self.serializeContentChunk(body, into: &buffer)
            case .knownLength:
                self.stackContentChunk(body)
            }

        case .request(.body(.fileRegion)), .response(.body(.fileRegion)):
            throw ObliviousHTTPError.unsupportedOption(reason: "fileregion unsupported")

        case .request(.end(.some(let trailers))), .response(.end(.some(let trailers))):
            try self.fsm.ensureState([BHTTPSerializerState.CHUNK, BHTTPSerializerState.HEADER])
            switch self.type {
            case .indeterminateLength:
                // Send a 0 to terminate the body, then a field section.
                buffer.writeInteger(UInt8(0))
                Self.serializeIndeterminateLengthFieldSection(trailers, into: &buffer)
            case .knownLength:
                self.serializeContent(into: &buffer)
                self.stackKnownLengthFieldSection(trailers)
            }
            try self.fsm.transition(to: BHTTPSerializerState.TRAILERS)

        case .request(.end(.none)), .response(.end(.none)):
            try self.fsm.ensureState([BHTTPSerializerState.CHUNK, BHTTPSerializerState.TRAILERS])
            switch self.type {
            case .indeterminateLength:
                buffer.writeInteger(UInt8(0))
            case .knownLength:
                self.serializeContent(into: &buffer)
                self.serializeKnownLengthFieldSection(into: &buffer)
            }
            try self.fsm.transition(to: BHTTPSerializerState.END)
        }
    }

    private mutating func serializeRequestHead(_ head: HTTPRequestHead, into buffer: inout ByteBuffer) {
        // First, the framing indicator
        buffer.writeVarint(
            self.type == .indeterminateLength
                ? BHTTPFramingIndicator.requestIndeterminateLength.rawValue
                : BHTTPFramingIndicator.requestKnownLength.rawValue
        )

        let method = head.method
        let scheme = "https"  // Hardcoded for now, but not really the right option.
        let path = head.uri
        let authority = head.headers["Host"].first ?? ""

        buffer.writeVarintPrefixedString(method.rawValue)
        buffer.writeVarintPrefixedString(scheme)
        buffer.writeVarintPrefixedString(authority)
        buffer.writeVarintPrefixedString(path)

        switch self.type {
        case .indeterminateLength:
            Self.serializeIndeterminateLengthFieldSection(head.headers, into: &buffer)
        case .knownLength:
            self.stackKnownLengthFieldSection(head.headers)
            self.serializeKnownLengthFieldSection(into: &buffer)
        }
    }

    private mutating func serializeResponseHead(_ head: HTTPResponseHead, into buffer: inout ByteBuffer) {
        // First, the framing indicator
        buffer.writeVarint(
            self.type == .indeterminateLength
                ? BHTTPFramingIndicator.responseInderterminateLength.rawValue
                : BHTTPFramingIndicator.responseKnownLength.rawValue
        )

        buffer.writeVarint(Int(head.status.code))

        switch self.type {
        case .indeterminateLength:
            Self.serializeIndeterminateLengthFieldSection(head.headers, into: &buffer)
        case .knownLength:
            self.stackKnownLengthFieldSection(head.headers)
            self.serializeKnownLengthFieldSection(into: &buffer)
        }
    }

    @inline(__always)
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
}

// Enum definitions for message, states, and types.
extension BHTTPSerializer {
    // Finite State Machine for managing transitions in BHTTPSerializer.
    private class BHTTPSerializerFSM {
        var currentState: BHTTPSerializerState

        init(initialState: BHTTPSerializerState) {
            self.currentState = initialState
        }

        // Transition to a new state, respecting the state machine constraints.
        func transition(to state: BHTTPSerializerState) throws {
            guard let allowedTransitions = Self.validTransitions[currentState] else {
                throw ObliviousHTTPError.unexpectedHTTPMessageSection(state: currentState.rawValue)
            }

            guard allowedTransitions.contains(state) else {
                throw ObliviousHTTPError.unexpectedHTTPMessageSection(state: currentState.rawValue)
            }

            currentState = state
        }

        // Define a dictionary to map current states to allowed transitions
        private static let validTransitions: [BHTTPSerializerState: Set<BHTTPSerializerState>] = [
            .HEADER: [.CHUNK, .TRAILERS],
            .CHUNK: [.TRAILERS, .END],
            .TRAILERS: [.END],
            .END: [],
        ]

        // Ensure that the current state is one of the allowed states.
        func ensureState(_ allowedStates: [BHTTPSerializerState]) throws {
            if !allowedStates.contains(self.currentState) {
                throw ObliviousHTTPError.unexpectedHTTPMessageSection(state: self.currentState.rawValue)
            }
        }
    }

    public enum Message {
        case request(HTTPClientRequestPart)
        case response(HTTPServerResponsePart)
    }

    public enum BHTTPSerializerType {
        case knownLength
        case indeterminateLength
    }

    public enum BHTTPFramingIndicator: Int {
        case requestKnownLength = 0
        case responseKnownLength = 1
        case requestIndeterminateLength = 2
        case responseInderterminateLength = 3
    }

    public enum BHTTPSerializerState: String {
        case HEADER = "Header"
        case CHUNK = "Chunk"
        case TRAILERS = "Trailers"
        case END = "End"
    }
}
