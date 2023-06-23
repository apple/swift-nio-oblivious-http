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

struct BHTTPParser {
    private var buffer: ByteBuffer?
    private var state: State
    private var role: Role
    private var readEOF: Bool

    init(role: Role) {
        self.buffer = nil
        self.state = .idle
        self.role = role
        self.readEOF = false
    }

    mutating func append(_ buffer: ByteBuffer) {
        self.buffer.setOrWriteImmutableBuffer(buffer)
    }

    mutating func completeBodyReceived() {
        self.readEOF = true
    }

    mutating func nextMessage() throws -> Message? {
        while true {
            let parseResult: ParseResult
            
            // Take a copy we can modify. This won't CoW: we only move the reader index.
            guard var buffer = self.buffer else {
                // No buffered bytes left.
                return nil
            }
            
            switch self.state {
            case .idle:
                parseResult = try Self.parseFramingIndicator(&buffer, role: self.role)
            case .awaitingRequestHead(knownLength: let knownLength):
                parseResult = try Self.parseRequestHead(&buffer, knownLength: knownLength, completeBodyReceived: self.readEOF)
            case .awaitingResponseHead(knownLength: let knownLength):
                parseResult = try Self.parseResponseHead(&buffer, knownLength: knownLength, completeBodyReceived: self.readEOF)
            case .awaitingContent(let content):
                parseResult = try Self.parseContent(&buffer, content: content, completeBodyReceived: self.readEOF, role: self.role)
            case .awaitingTrailers(knownLength: let knownLength):
                parseResult = try Self.parseTrailers(&buffer, knownLength: knownLength, completeBodyReceived: self.readEOF, role: self.role)
            case .complete:
                parseResult = .needMoreBytes
            }
            
            switch parseResult {
            case .complete(let result, let nextState):
                self.state = nextState
                self.buffer = buffer
                return result
            case .continue(let nextState):
                self.state = nextState
                self.buffer = buffer
            case .needMoreBytes:
                return nil
            }
        }
    }

    static func parseFramingIndicator(_ buffer: inout ByteBuffer, role: Role) throws -> ParseResult {
        guard let framingIndicator = buffer.readVarint() else {
            return .needMoreBytes
        }

        switch (framingIndicator, role) {
        case (0, .server):
            // Known-length request
            return .continue(nextState: .awaitingRequestHead(knownLength: true))
        case (1, .client):
            // Known-length response
            return .continue(nextState: .awaitingResponseHead(knownLength: true))
        case (2, .server):
            // Indeterminate-length request
            return .continue(nextState: .awaitingRequestHead(knownLength: false))
        case (3, .client):
            // Indeterminate length response
            return .continue(nextState: .awaitingResponseHead(knownLength: false))
        case (let indicator, _):
            throw ObliviousHTTPError.invalidFramingIndicator(indicator)
        }
    }

    static func parseRequestHead(_ buffer: inout ByteBuffer, knownLength: Bool, completeBodyReceived: Bool) throws -> ParseResult {
        // First, parse request control data. We do not need to reset the reader index when we don't have enough bytes, the outer code
        // will handle that for us.
        guard let method = buffer.readVarintLengthPrefixedSlice(),
              let _ = buffer.readVarintLengthPrefixedSlice(), // This is :scheme:, which we can't support in the HTTP1 type.
              let authority = buffer.readVarintLengthPrefixedSlice(),
              let path = buffer.readVarintLengthPrefixedSlice() else {
            return .needMoreBytes
        }

        // TBD: Should we support more incremental parsing here?
        let possibleFieldSection: ByteBuffer?

        if knownLength {
            possibleFieldSection = buffer.readVarintLengthPrefixedSlice()
        } else {
            // We don't do streaming decode here yet, so for now we can just
            // slice the whole thing out.
            possibleFieldSection = try buffer.readIndeterminateFieldSectionSlice()
        }

        switch (possibleFieldSection, completeBodyReceived) {
        case (.none, true) where buffer.readableBytes > 0:
            // This is an error.
            throw ObliviousHTTPError.truncatedEncoding(reason: "Cannot parse field section")
        case (.none, false):
            // We're still waiting for a field section.
            return .needMoreBytes
        case (.none, true), (.some, _):
            // We can fallthrough here, we either got a field section _or_ we have EOF.
            break
        }

        var headers = HTTPHeaders()

        if var fieldSection = possibleFieldSection {
            try Self.parseFieldSection(&fieldSection, into: &headers)
        }

        if authority.readableBytes > 0 && !headers.contains(name: "host") {
            headers.add(name: "host", value: String(buffer: authority))
        }

        let head = HTTPRequestHead(
            version: .http1_1,
            method: .init(rawValue: String(buffer: method)),
            uri: String(buffer: path),
            headers: headers
        )
        return .complete(.request(.head(head)), nextState: .awaitingContent(.init(knownLength: knownLength)))
    }

    static func parseResponseHead(_ buffer: inout ByteBuffer, knownLength: Bool, completeBodyReceived: Bool) throws -> ParseResult {
        // First, parse response control data. We do not need to reset the reader index when we don't have enough bytes, the outer code
        // will handle that for us.
        guard let statusCode = buffer.readVarint() else {
            return .needMoreBytes
        }

        // TBD: Should we support more incremental parsing here?
        let possibleFieldSection: ByteBuffer?

        if knownLength {
            possibleFieldSection = buffer.readVarintLengthPrefixedSlice()
        } else {
            // We don't do streaming decode here yet, so for now we can just
            // slice the whole thing out.
            possibleFieldSection = try buffer.readIndeterminateFieldSectionSlice()
        }

        switch (possibleFieldSection, completeBodyReceived) {
        case (.none, true) where buffer.readableBytes > 0:
            // This is an error.
            throw ObliviousHTTPError.truncatedEncoding(reason: "Cannot parse field section")
        case (.none, false):
            // We're still waiting for a field section.
            return .needMoreBytes
        case (.none, true), (.some, _):
            // We can fallthrough here, we either got a field section _or_ we have EOF.
            break
        }

        var headers = HTTPHeaders()
        if var fieldSection = possibleFieldSection {
            try Self.parseFieldSection(&fieldSection, into: &headers)
        }

        guard (100..<600).contains(statusCode) else {
            throw ObliviousHTTPError.invalidStatus(status: statusCode)
        }

        let head = HTTPResponseHead(
            version: .http1_1,
            status: HTTPResponseStatus(statusCode: statusCode),
            headers: headers
        )

        let nextState: State
        if head.isInformational {
            nextState = .awaitingResponseHead(knownLength: knownLength)
        } else {
            nextState = .awaitingContent(.init(knownLength: knownLength))
        }
        return .complete(.response(.head(head)), nextState: nextState)
    }

    static func parseContent(_ buffer: inout ByteBuffer, content: State.Content, completeBodyReceived: Bool, role: Role) throws -> ParseResult {
        switch content {
        case .knownLengthBeforeFirstChunk:
            // First chunk, we don't know what the length is.
            if let length = buffer.readVarint() {
                let nextState: State
                if length > 0 {
                    nextState = .awaitingContent(.knownLength(remainingBytes: length))
                } else {
                    nextState = .awaitingTrailers(knownLength: true)
                }
                return .continue(nextState: nextState)
            } else if completeBodyReceived {
                guard buffer.readableBytes == 0 else {
                    throw ObliviousHTTPError.truncatedEncoding(reason: "unexpected EOF when parsing body")
                }
                // Content section is missing, that's fine.
                return .continue(nextState: .awaitingTrailers(knownLength: true))
            } else {
                return .needMoreBytes
            }

        case .knownLength(remainingBytes: let remainingBytes):
            // Ok, we know the length. Read either that much, or whatever is in the buffer.
            // We can force-unwrap because we account for readable bytes here.
            let bytesToRead = min(remainingBytes, buffer.readableBytes)
            if bytesToRead == 0 {
                return .needMoreBytes
            }

            let slice = buffer.readSlice(length: bytesToRead)!

            let newRemainingBytes = remainingBytes - bytesToRead

            let nextState: State
            if newRemainingBytes > 0 {
                nextState = .awaitingContent(.knownLength(remainingBytes: newRemainingBytes))
            } else {
                nextState = .awaitingTrailers(knownLength: true)
            }

            return .complete(role.bodyForRole(payload: slice), nextState: nextState)

        case .indeterminateLengthBeforeFirstChunk:
            // First chunk, we don't know what the length is.
            if let length = buffer.readVarint() {
                let nextState: State
                if length > 0 {
                    nextState = .awaitingContent(.indeterminateLength(remainingChunkBytes: length))
                } else {
                    nextState = .awaitingTrailers(knownLength: false)
                }

                return .continue(nextState: nextState)
            } else if completeBodyReceived {
                guard buffer.readableBytes == 0 else {
                    throw ObliviousHTTPError.truncatedEncoding(reason: "unexpected EOF when parsing body")
                }
                // Content section is missing, that's fine.
                return .continue(nextState: .awaitingTrailers(knownLength: true))
            } else {
                return .needMoreBytes
            }

        case .indeterminateLength(remainingChunkBytes: let remainingBytes):
            // Remaining bytes is a remaining chunk length, we have
            // a partial chunk here. Read up to remaining bytes from
            // the buffer, as much as possible.
            // We can force-unwrap because we account for readable bytes here.
            let bytesToRead = min(remainingBytes, buffer.readableBytes)
            if bytesToRead == 0 {
                return .needMoreBytes
            }

            let slice = buffer.readSlice(length: bytesToRead)!

            let newRemainingBytes = remainingBytes - bytesToRead
            let nextState: State

            if newRemainingBytes > 0 {
                nextState = .awaitingContent(
                    .indeterminateLength(remainingChunkBytes: newRemainingBytes)
                )
            } else {
                nextState = .awaitingContent(.indeterminateLengthWaitingForChunkLength)
            }

            return .complete(role.bodyForRole(payload: slice), nextState: nextState)

        case .indeterminateLengthWaitingForChunkLength:
            // Not first chunk, we don't know what the length is. If the length is 0,
            // we're at the end.
            if let length = buffer.readVarint() {
                let nextState: State
                if length > 0 {
                    nextState = .awaitingContent(.indeterminateLength(remainingChunkBytes: length))
                } else {
                    nextState = .awaitingTrailers(knownLength: false)
                }

                return .continue(nextState: nextState)
            } else {
                return .needMoreBytes
            }
        }
    }

    static func parseTrailers(_ buffer: inout ByteBuffer, knownLength: Bool, completeBodyReceived: Bool, role: Role) throws -> ParseResult {
        // Trailers are just a field section.
        let possibleFieldSection: ByteBuffer?

        if knownLength {
            possibleFieldSection = buffer.readVarintLengthPrefixedSlice()
        } else {
            // We don't do streaming decode here yet, so for now we can just
            // slice the whole thing out.
            possibleFieldSection = try buffer.readIndeterminateFieldSectionSlice()
        }

        switch (possibleFieldSection, completeBodyReceived) {
        case (.none, true) where buffer.readableBytes > 0:
            // This is an error.
            throw ObliviousHTTPError.truncatedEncoding(reason: "Cannot parse field section")
        case (.none, false):
            // We're still waiting for a field section.
            return .needMoreBytes
        case (.none, true):
            // This is a fun case! We have no trailers.
            return .complete(role.trailersForRole(nil), nextState: .complete)
        case(.some, _):
            // We can fallthrough here, we either got a field section _or_ we have EOF.
            break
        }

        var headers = HTTPHeaders()
        if var fieldSection = possibleFieldSection {
            try Self.parseFieldSection(&fieldSection, into: &headers)
        }

        if headers.isEmpty {
            return .complete(role.trailersForRole(nil), nextState: .complete)
        } else {
            return .complete(role.trailersForRole(headers), nextState: .complete)
        }
    }

    static func parseFieldSection(_ fieldSection: inout ByteBuffer, into headers: inout HTTPHeaders) throws {
        while fieldSection.readableBytes > 0 {
            guard let fieldName = fieldSection.readVarintLengthPrefixedSlice(),
                  let fieldValue = fieldSection.readVarintLengthPrefixedSlice() else {
                // Uh-oh, framing error!
                throw ObliviousHTTPError.invalidFieldSection(reason: "Truncated field name or value")
            }

            guard fieldName.readableBytes > 0 else {
                throw ObliviousHTTPError.invalidFieldSection(reason: "Zero-length field name")
            }

            headers.add(name: String(buffer: fieldName), value: String(buffer: fieldValue))
        }
    }
}

extension BHTTPParser {
    enum State {
        case idle
        case awaitingResponseHead(knownLength: Bool)
        case awaitingRequestHead(knownLength: Bool)
        case awaitingContent(Content)
        case awaitingTrailers(knownLength: Bool)
        case complete

        enum Content {
            case knownLengthBeforeFirstChunk
            case knownLength(remainingBytes: Int)
            case indeterminateLengthBeforeFirstChunk
            case indeterminateLengthWaitingForChunkLength
            case indeterminateLength(remainingChunkBytes: Int)

            init(knownLength: Bool) {
                if knownLength {
                    self = .knownLengthBeforeFirstChunk
                } else {
                    self = .indeterminateLengthBeforeFirstChunk
                }
            }
        }
    }

    enum Role {
        case client
        case server

        func bodyForRole(payload: ByteBuffer) -> Message {
            switch self {
            case .client:
                return .response(.body(payload))
            case .server:
                return .request(.body(payload))
            }
        }

        func trailersForRole(_ payload: HTTPHeaders?) -> Message {
            switch self {
            case .client:
                return .response(.end(payload))
            case .server:
                return .request(.end(payload))
            }
        }
    }

    enum Message {
        case request(HTTPServerRequestPart)
        case response(HTTPClientResponsePart)
    }

    enum ParseResult {
        case complete(Message, nextState: State)
        case `continue`(nextState: State)
        case needMoreBytes
    }
}

extension ByteBuffer {
    mutating func readIndeterminateFieldSectionSlice() throws -> ByteBuffer? {
        // We have to search for the termination marker, which is a 0 stored in a
        // varint.
        var localCopy = self
        var endIndex = localCopy.readerIndex
        guard var nameLength = localCopy.readVarint() else {
            return nil
        }

        while localCopy.readableBytes >= nameLength {
            if nameLength == 0 {
                // Found the termination marker! We can now slice out the field section.
                // Force-unwrap is safe: we know we have this many bytes available.
                let fieldSectionLength = endIndex - self.readerIndex
                let fieldSection = self.readSlice(length: fieldSectionLength)!

                // This is a bit weird: we need to drop the varint too because it's
                // not interesting.
                self = localCopy
                return fieldSection
            }

            // Skip field name.
            localCopy.moveReaderIndex(forwardBy: nameLength)

            // Skip field value
            guard let valueLength = localCopy.readVarint(), localCopy.readableBytes > valueLength else {
                // No termination marker.
                return nil
            }
            localCopy.moveReaderIndex(forwardBy: valueLength)

            endIndex = localCopy.readerIndex
            guard let possibleMarker = localCopy.readVarint() else {
                // No termination marker
                return nil
            }
            nameLength = possibleMarker
        }

        // Ran out of bytes.
        return nil
    }
}

extension HTTPResponseHead {
    var isInformational: Bool {
        100 <= self.status.code && self.status.code < 200 && self.status.code != 101
    }
}

