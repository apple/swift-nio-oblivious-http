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
import Foundation
import NIOCore
import NIOHTTP1
import XCTest

@testable import ObliviousHTTP

final class BHTTPSerializerTests: XCTestCase {
    func testSimpleGetRequestRoundTrips() throws {
        let expectedHeaders = HTTPHeaders([
            ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
            ("host", "www.example.com"),
            ("accept-language", "en, mi"),
        ])
        let request: [HTTPClientRequestPart] = [
            .head(.init(version: .http1_1, method: .GET, uri: "/example", headers: expectedHeaders)),
            .end(nil),
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer()
        var parser = BHTTPParser(role: .server)

        for message in request {
            try serializer.serialize(.request(message), into: &buffer)
        }

        parser.append(buffer)
        parser.completeBodyReceived()
        var received: [HTTPServerRequestPart] = []

        while let next = try parser.nextMessage(), case .request(let request) = next {
            received.append(request)
        }

        let expectedRequest: [HTTPServerRequestPart] = [
            .head(.init(version: .http1_1, method: .GET, uri: "/example", headers: expectedHeaders)),
            .end(nil),
        ]
        XCTAssertEqual(expectedRequest, received)
    }

    func testSimpleGetRequestRoundTripsWithKnownLengthSerializer() throws {
        let expectedHeaders = HTTPHeaders([
            ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
            ("host", "www.example.com"),
            ("accept-language", "en, mi"),
        ])
        let request: [HTTPClientRequestPart] = [
            .head(.init(version: .http1_1, method: .GET, uri: "/example", headers: expectedHeaders)),
            .end(nil),
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer(type: .knownLength)
        var parser = BHTTPParser(role: .server)

        for message in request {
            try serializer.serialize(.request(message), into: &buffer)
        }

        parser.append(buffer)
        parser.completeBodyReceived()
        var received: [HTTPServerRequestPart] = []

        while let next = try parser.nextMessage(), case .request(let request) = next {
            received.append(request)
        }

        let expectedRequest: [HTTPServerRequestPart] = [
            .head(.init(version: .http1_1, method: .GET, uri: "/example", headers: expectedHeaders)),
            .end(nil),
        ]
        XCTAssertEqual(expectedRequest, received)
    }

    func testSerializerThrowsForMultipleHeadPartsInRequest() throws {
        let expectedHeaders = HTTPHeaders([
            ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
            ("host", "www.example.com"),
            ("accept-language", "en, mi"),
        ])
        let request: [HTTPClientRequestPart] = [
            .head(.init(version: .http1_1, method: .GET, uri: "/example", headers: expectedHeaders)),
            .head(.init(version: .http1_1, method: .GET, uri: "/example", headers: expectedHeaders)),
            .end(nil),
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer()

        var didThrowError = false

        for message in request {
            do {
                try serializer.serialize(.request(message), into: &buffer)
            } catch {
                didThrowError = true
                XCTAssertNotNil(error, "Chunk section was not expected.")
                break
            }
        }

        XCTAssertTrue(didThrowError, "Expected serializer to throw an error because the request has 2 heads part.")
    }

    func testSerializerThrowsForOutOfOrderRequestParts() throws {
        let expectedHeaders = HTTPHeaders([
            ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
            ("host", "www.example.com"),
            ("accept-language", "en, mi"),
            ("content-length", "5"),
        ])
        let request: [HTTPClientRequestPart] = [
            .body(.byteBuffer(.init(string: "he"))),
            .head(.init(version: .http1_1, method: .POST, uri: "/example", headers: expectedHeaders)),
            .body(.byteBuffer(.init(string: "llo"))),
            .end(nil),
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer()

        var didThrowError = false

        for message in request {
            do {
                try serializer.serialize(.request(message), into: &buffer)
            } catch {
                didThrowError = true
                XCTAssertNotNil(error, "Header section was not expected.")
                break
            }
        }

        XCTAssertTrue(
            didThrowError,
            "Expected serializer to throw an error because the request has out of order parts."
        )
    }

    func testSimplePOSTRequestRoundTrips() throws {
        let expectedHeaders = HTTPHeaders([
            ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
            ("host", "www.example.com"),
            ("accept-language", "en, mi"),
            ("content-length", "5"),
        ])
        let request: [HTTPClientRequestPart] = [
            .head(.init(version: .http1_1, method: .POST, uri: "/example", headers: expectedHeaders)),
            .body(.byteBuffer(.init(string: "he"))),
            .body(.byteBuffer(.init(string: "llo"))),
            .end(nil),
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer()
        var parser = BHTTPParser(role: .server)

        for message in request {
            try serializer.serialize(.request(message), into: &buffer)
        }

        parser.append(buffer)
        parser.completeBodyReceived()
        var received: [HTTPServerRequestPart] = []

        while let next = try parser.nextMessage(), case .request(let request) = next {
            received.append(request)
        }

        let expectedRequest: [HTTPServerRequestPart] = [
            .head(.init(version: .http1_1, method: .POST, uri: "/example", headers: expectedHeaders)),
            .body(.init(string: "he")),
            .body(.init(string: "llo")),
            .end(nil),
        ]
        XCTAssertEqual(expectedRequest, received)
    }

    func testSimplePOSTRequestRoundTripsWithKnownLengthSerialiser() throws {
        let expectedHeaders = HTTPHeaders([
            ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
            ("host", "www.example.com"),
            ("accept-language", "en, mi"),
            ("content-length", "5"),
        ])
        let request: [HTTPClientRequestPart] = [
            .head(.init(version: .http1_1, method: .POST, uri: "/example", headers: expectedHeaders)),
            .body(.byteBuffer(.init(string: "he"))),
            .body(.byteBuffer(.init(string: "llo"))),
            .end(nil),
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer(type: .knownLength)
        var parser = BHTTPParser(role: .server)

        for message in request {
            try serializer.serialize(.request(message), into: &buffer)
        }

        parser.append(buffer)
        parser.completeBodyReceived()
        var received: [HTTPServerRequestPart] = []

        while let next = try parser.nextMessage(), case .request(let request) = next {
            received.append(request)
        }

        let expectedRequest: [HTTPServerRequestPart] = [
            .head(.init(version: .http1_1, method: .POST, uri: "/example", headers: expectedHeaders)),
            .body(.init(string: "hello")),
            .end(nil),
        ]
        XCTAssertEqual(expectedRequest, received)
    }

    func testSimplePOSTRequestWithTrailersRoundTrips() throws {
        let expectedHeaders = HTTPHeaders([
            ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
            ("host", "www.example.com"),
            ("accept-language", "en, mi"),
            ("content-length", "5"),
        ])
        let expectedTrailers = HTTPHeaders([
            ("foo", "bar"),
            ("froo", "brar"),
        ])
        let request: [HTTPClientRequestPart] = [
            .head(.init(version: .http1_1, method: .POST, uri: "/example", headers: expectedHeaders)),
            .body(.byteBuffer(.init(string: "he"))),
            .body(.byteBuffer(.init(string: "llo"))),
            .end(expectedTrailers),
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer()
        var parser = BHTTPParser(role: .server)

        for message in request {
            try serializer.serialize(.request(message), into: &buffer)
        }

        parser.append(buffer)
        parser.completeBodyReceived()
        var received: [HTTPServerRequestPart] = []

        while let next = try parser.nextMessage(), case .request(let request) = next {
            received.append(request)
        }

        let expectedRequest: [HTTPServerRequestPart] = [
            .head(.init(version: .http1_1, method: .POST, uri: "/example", headers: expectedHeaders)),
            .body(.init(string: "he")),
            .body(.init(string: "llo")),
            .end(expectedTrailers),
        ]
        XCTAssertEqual(expectedRequest, received)
    }

    func testSimplePOSTRequestWithTrailersRoundTripsAndKnownLengthSerializer() throws {
        let expectedHeaders = HTTPHeaders([
            ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
            ("host", "www.example.com"),
            ("accept-language", "en, mi"),
            ("content-length", "5"),
        ])
        let expectedTrailers = HTTPHeaders([
            ("foo", "bar"),
            ("froo", "brar"),
        ])
        let request: [HTTPClientRequestPart] = [
            .head(.init(version: .http1_1, method: .POST, uri: "/example", headers: expectedHeaders)),
            .body(.byteBuffer(.init(string: "he"))),
            .body(.byteBuffer(.init(string: "llo"))),
            .end(expectedTrailers),
            .end(nil),
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer(type: .knownLength)
        var parser = BHTTPParser(role: .server)

        for message in request {
            try serializer.serialize(.request(message), into: &buffer)
        }

        parser.append(buffer)
        parser.completeBodyReceived()
        var received: [HTTPServerRequestPart] = []

        while let next = try parser.nextMessage(), case .request(let request) = next {
            received.append(request)
        }

        let expectedRequest: [HTTPServerRequestPart] = [
            .head(.init(version: .http1_1, method: .POST, uri: "/example", headers: expectedHeaders)),
            .body(.init(string: "hello")),
            .end(expectedTrailers)
        ]
        XCTAssertEqual(expectedRequest, received)
    }

    func testSimple201ResponseRoundTrips() throws {
        let expectedHeaders = HTTPHeaders([
            ("server", "apache"),
            ("other-header", "its value"),
        ])
        let response: [HTTPServerResponsePart] = [
            .head(.init(version: .http1_1, status: .noContent, headers: expectedHeaders)),
            .end(nil),
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer()
        var parser = BHTTPParser(role: .client)

        for message in response {
            try serializer.serialize(.response(message), into: &buffer)
        }

        parser.append(buffer)
        parser.completeBodyReceived()
        var received: [HTTPClientResponsePart] = []

        while let next = try parser.nextMessage(), case .response(let response) = next {
            received.append(response)
        }

        let expectedResponse: [HTTPClientResponsePart] = [
            .head(.init(version: .http1_1, status: .noContent, headers: expectedHeaders)),
            .end(nil),
        ]
        XCTAssertEqual(expectedResponse, received)
    }

    func testSimple200ResponseWithBodyRoundTrips() throws {
        let expectedHeaders = HTTPHeaders([
            ("server", "apache"),
            ("other-header", "its value"),
            ("content-length", "5"),
        ])
        let response: [HTTPServerResponsePart] = [
            .head(.init(version: .http1_1, status: .noContent, headers: expectedHeaders)),
            .body(.byteBuffer(ByteBuffer(string: "hello"))),
            .end(nil),
        ]
        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer()
        var parser = BHTTPParser(role: .client)

        for message in response {
            try serializer.serialize(.response(message), into: &buffer)
        }

        parser.append(buffer)
        parser.completeBodyReceived()
        var received: [HTTPClientResponsePart] = []

        while let next = try parser.nextMessage(), case .response(let response) = next {
            received.append(response)
        }

        let expectedResponse: [HTTPClientResponsePart] = [
            .head(.init(version: .http1_1, status: .noContent, headers: expectedHeaders)),
            .body(ByteBuffer(string: "hello")),
            .end(nil),
        ]
        XCTAssertEqual(expectedResponse, received)
    }

    func testSimple200ResponseWithBodyAndTrailersRoundTrips() throws {
        let expectedHeaders = HTTPHeaders([
            ("server", "apache"),
            ("other-header", "its value"),
            ("content-length", "5"),
        ])
        let expectedTrailers = HTTPHeaders([
            ("foo", "bar"),
            ("froo", "brar"),
        ])
        let response: [HTTPServerResponsePart] = [
            .head(.init(version: .http1_1, status: .noContent, headers: expectedHeaders)),
            .body(.byteBuffer(ByteBuffer(string: "hello"))),
            .end(expectedTrailers),
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer()
        var parser = BHTTPParser(role: .client)

        for message in response {
            try serializer.serialize(.response(message), into: &buffer)
        }

        parser.append(buffer)
        parser.completeBodyReceived()
        var received: [HTTPClientResponsePart] = []

        while let next = try parser.nextMessage(), case .response(let response) = next {
            received.append(response)
        }

        let expectedResponse: [HTTPClientResponsePart] = [
            .head(.init(version: .http1_1, status: .noContent, headers: expectedHeaders)),
            .body(ByteBuffer(string: "hello")),
            .end(expectedTrailers),
        ]
        XCTAssertEqual(expectedResponse, received)
    }


    func testSimple200ResponseWithBodyAndTrailersRoundTripsAndKnownLengthSerializer() throws {
        let expectedHeaders = HTTPHeaders([
            ("server", "apache"),
            ("other-header", "its value"),
            ("content-length", "5"),
        ])
        let expectedTrailers = HTTPHeaders([
            ("foo", "bar"),
            ("froo", "brar"),
        ])
        let response: [HTTPServerResponsePart] = [
            .head(.init(version: .http1_1, status: .noContent, headers: expectedHeaders)),
            .body(.byteBuffer(ByteBuffer(string: "hello"))),
            .end(expectedTrailers),
            .end(nil)
        ]

        var buffer = ByteBuffer()
        var serializer = BHTTPSerializer(type: .knownLength)
        var parser = BHTTPParser(role: .client)

        for message in response {
            try serializer.serialize(.response(message), into: &buffer)
        }

        parser.append(buffer)
        parser.completeBodyReceived()
        var received: [HTTPClientResponsePart] = []

        while let next = try parser.nextMessage(), case .response(let response) = next {
            received.append(response)
        }

        let expectedResponse: [HTTPClientResponsePart] = [
            .head(.init(version: .http1_1, status: .noContent, headers: expectedHeaders)),
            .body(ByteBuffer(string: "hello")),
            .end(expectedTrailers),
        ]
        XCTAssertEqual(expectedResponse, received)
    }
}
