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

final class BHTTPParserTests: XCTestCase {
  func testExampleRequestKnownLength() throws {
    let exampleRequestB64 = """
      AANHRVQFaHR0cHMACi9oZWxsby50eHRAbAp1c2VyLWFnZW50NGN1cmwvNy4xNi4z
      IGxpYmN1cmwvNy4xNi4zIE9wZW5TU0wvMC45LjdsIHpsaWIvMS4yLjMEaG9zdA93
      d3cuZXhhbXBsZS5jb20PYWNjZXB0LWxhbmd1YWdlBmVuLCBtaQAA
      """
    let exampleRequest = ByteBuffer(
      bytes: Data(base64Encoded: exampleRequestB64, options: .ignoreUnknownCharacters)!)
    var parser = BHTTPParser(role: .server)
    parser.append(exampleRequest)

    var results: [HTTPServerRequestPart] = []
    while let next = try parser.nextMessage(), case .request(let part) = next {
      results.append(part)
    }

    let expectedHeaders = HTTPHeaders([
      ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
      ("host", "www.example.com"),
      ("accept-language", "en, mi"),
    ])

    XCTAssertEqual(
      results,
      [
        .head(.init(version: .http1_1, method: .GET, uri: "/hello.txt", headers: expectedHeaders)),
        .end(nil),
      ]
    )
  }

  func testExampleRequestKnownLengthExplicitEOF() throws {
    let exampleRequestB64 = """
      AANHRVQFaHR0cHMACi9oZWxsby50eHRAbAp1c2VyLWFnZW50NGN1cmwvNy4xNi4z
      IGxpYmN1cmwvNy4xNi4zIE9wZW5TU0wvMC45LjdsIHpsaWIvMS4yLjMEaG9zdA93
      d3cuZXhhbXBsZS5jb20PYWNjZXB0LWxhbmd1YWdlBmVuLCBtaQAA
      """
    let exampleRequest = ByteBuffer(
      bytes: Data(base64Encoded: exampleRequestB64, options: .ignoreUnknownCharacters)!)
    var parser = BHTTPParser(role: .server)
    parser.append(exampleRequest)
    parser.completeBodyReceived()

    var results: [HTTPServerRequestPart] = []
    while let next = try parser.nextMessage(), case .request(let part) = next {
      results.append(part)
    }

    let expectedHeaders = HTTPHeaders([
      ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
      ("host", "www.example.com"),
      ("accept-language", "en, mi"),
    ])

    XCTAssertEqual(
      results,
      [
        .head(.init(version: .http1_1, method: .GET, uri: "/hello.txt", headers: expectedHeaders)),
        .end(nil),
      ]
    )
  }

  func testExampleRequestKnownLengthDripFed() throws {
    let exampleRequestB64 = """
      AANHRVQFaHR0cHMACi9oZWxsby50eHRAbAp1c2VyLWFnZW50NGN1cmwvNy4xNi4z
      IGxpYmN1cmwvNy4xNi4zIE9wZW5TU0wvMC45LjdsIHpsaWIvMS4yLjMEaG9zdA93
      d3cuZXhhbXBsZS5jb20PYWNjZXB0LWxhbmd1YWdlBmVuLCBtaQAA
      """
    var exampleRequest = Data(base64Encoded: exampleRequestB64, options: .ignoreUnknownCharacters)!
    var parser = BHTTPParser(role: .server)

    var results: [HTTPServerRequestPart] = []
    for byte in exampleRequest {
      parser.append(ByteBuffer(integer: byte))
      exampleRequest = exampleRequest.dropFirst()

      while let next = try parser.nextMessage(), case .request(let part) = next {
        results.append(part)
      }
    }

    let expectedHeaders = HTTPHeaders([
      ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
      ("host", "www.example.com"),
      ("accept-language", "en, mi"),
    ])

    XCTAssertEqual(
      results,
      [
        .head(.init(version: .http1_1, method: .GET, uri: "/hello.txt", headers: expectedHeaders)),
        .end(nil),
      ]
    )
  }

  func testExampleRequestIndeterminateLength() throws {
    let exampleRequestB64 = """
      AgNHRVQFaHR0cHMACi9oZWxsby50eHQKdXNlci1hZ2VudDRjdXJsLzcuMTYuMyBs
      aWJjdXJsLzcuMTYuMyBPcGVuU1NMLzAuOS43bCB6bGliLzEuMi4zBGhvc3QPd3d3
      LmV4YW1wbGUuY29tD2FjY2VwdC1sYW5ndWFnZQZlbiwgbWkAAAAAAAAAAAAAAAAA
      """
    let exampleRequest = ByteBuffer(
      bytes: Data(base64Encoded: exampleRequestB64, options: .ignoreUnknownCharacters)!)
    var parser = BHTTPParser(role: .server)
    parser.append(exampleRequest)

    var results: [HTTPServerRequestPart] = []
    while let next = try parser.nextMessage(), case .request(let part) = next {
      results.append(part)
    }

    let expectedHeaders = HTTPHeaders([
      ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
      ("host", "www.example.com"),
      ("accept-language", "en, mi"),
    ])

    XCTAssertEqual(
      results,
      [
        .head(.init(version: .http1_1, method: .GET, uri: "/hello.txt", headers: expectedHeaders)),
        .end(nil),
      ]
    )
  }

  func testExampleRequestIndeterminateLengthExplicitEOF() throws {
    let exampleRequestB64 = """
      AgNHRVQFaHR0cHMACi9oZWxsby50eHQKdXNlci1hZ2VudDRjdXJsLzcuMTYuMyBs
      aWJjdXJsLzcuMTYuMyBPcGVuU1NMLzAuOS43bCB6bGliLzEuMi4zBGhvc3QPd3d3
      LmV4YW1wbGUuY29tD2FjY2VwdC1sYW5ndWFnZQZlbiwgbWkAAAAAAAAAAAAAAAAA
      """
    let exampleRequest = ByteBuffer(
      bytes: Data(base64Encoded: exampleRequestB64, options: .ignoreUnknownCharacters)!)
    var parser = BHTTPParser(role: .server)
    parser.append(exampleRequest)
    parser.completeBodyReceived()

    var results: [HTTPServerRequestPart] = []
    while let next = try parser.nextMessage(), case .request(let part) = next {
      results.append(part)
    }

    let expectedHeaders = HTTPHeaders([
      ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
      ("host", "www.example.com"),
      ("accept-language", "en, mi"),
    ])

    XCTAssertEqual(
      results,
      [
        .head(.init(version: .http1_1, method: .GET, uri: "/hello.txt", headers: expectedHeaders)),
        .end(nil),
      ]
    )
  }

  func testExampleRequestIndeterminateLengthDripFed() throws {
    let exampleRequestB64 = """
      AgNHRVQFaHR0cHMACi9oZWxsby50eHQKdXNlci1hZ2VudDRjdXJsLzcuMTYuMyBs
      aWJjdXJsLzcuMTYuMyBPcGVuU1NMLzAuOS43bCB6bGliLzEuMi4zBGhvc3QPd3d3
      LmV4YW1wbGUuY29tD2FjY2VwdC1sYW5ndWFnZQZlbiwgbWkAAAAAAAAAAAAAAAAA
      """
    var exampleRequest = Data(base64Encoded: exampleRequestB64, options: .ignoreUnknownCharacters)!
    var parser = BHTTPParser(role: .server)

    var results: [HTTPServerRequestPart] = []
    for byte in exampleRequest {
      parser.append(ByteBuffer(integer: byte))
      exampleRequest = exampleRequest.dropFirst()

      while let next = try parser.nextMessage(), case .request(let part) = next {
        results.append(part)
      }
    }

    let expectedHeaders = HTTPHeaders([
      ("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"),
      ("host", "www.example.com"),
      ("accept-language", "en, mi"),
    ])

    XCTAssertEqual(
      results,
      [
        .head(.init(version: .http1_1, method: .GET, uri: "/hello.txt", headers: expectedHeaders)),
        .end(nil),
      ]
    )
  }

  func testExampleResponseIndeterminateLength() throws {
    let exampleResponseB64 = """
      A0BmB3J1bm5pbmcKInNsZWVwIDE1IgBAZwRsaW5rIzwvc3R5bGUuY3NzPjsgcmVs
      PXByZWxvYWQ7IGFzPXN0eWxlBGxpbmskPC9zY3JpcHQuanM+OyByZWw9cHJlbG9h
      ZDsgYXM9c2NyaXB0AEDIBGRhdGUdTW9uLCAyNyBKdWwgMjAwOSAxMjoyODo1MyBH
      TVQGc2VydmVyBkFwYWNoZQ1sYXN0LW1vZGlmaWVkHVdlZCwgMjIgSnVsIDIwMDkg
      MTk6MTU6NTYgR01UBGV0YWcUIjM0YWEzODctZC0xNTY4ZWIwMCINYWNjZXB0LXJh
      bmdlcwVieXRlcw5jb250ZW50LWxlbmd0aAI1MQR2YXJ5D0FjY2VwdC1FbmNvZGlu
      Zwxjb250ZW50LXR5cGUKdGV4dC9wbGFpbgAzSGVsbG8gV29ybGQhIE15IGNvbnRl
      bnQgaW5jbHVkZXMgYSB0cmFpbGluZyBDUkxGLg0KAAA=
      """
    let exampleResponse = ByteBuffer(
      bytes: Data(base64Encoded: exampleResponseB64, options: .ignoreUnknownCharacters)!)
    var parser = BHTTPParser(role: .client)
    parser.append(exampleResponse)

    var results: [HTTPClientResponsePart] = []
    while let next = try parser.nextMessage(), case .response(let part) = next {
      results.append(part)
    }

    let expectedFinalHeaders = HTTPHeaders([
      ("date", "Mon, 27 Jul 2009 12:28:53 GMT"),
      ("server", "Apache"),
      ("last-modified", "Wed, 22 Jul 2009 19:15:56 GMT"),
      ("etag", "\"34aa387-d-1568eb00\""),
      ("accept-ranges", "bytes"),
      ("content-length", "51"),
      ("vary", "Accept-Encoding"),
      ("content-type", "text/plain"),
    ])

    XCTAssertEqual(
      results,
      [
        .head(
          .init(
            version: .http1_1,
            status: .processing,
            headers: HTTPHeaders([("running", "\"sleep 15\"")])
          )
        ),
        .head(
          .init(
            version: .http1_1,
            status: .custom(code: 103, reasonPhrase: ""),
            headers: HTTPHeaders([
              ("link", "</style.css>; rel=preload; as=style"),
              ("link", "</script.js>; rel=preload; as=script"),
            ])
          )
        ),
        .head(
          .init(
            version: .http1_1,
            status: .ok,
            headers: expectedFinalHeaders
          )
        ),
        .body(ByteBuffer(string: "Hello World! My content includes a trailing CRLF.\r\n")),
        .end(nil),
      ]
    )
  }

  func testExampleResponseIndeterminateLengthExplicitEOF() throws {
    let exampleResponseB64 = """
      A0BmB3J1bm5pbmcKInNsZWVwIDE1IgBAZwRsaW5rIzwvc3R5bGUuY3NzPjsgcmVs
      PXByZWxvYWQ7IGFzPXN0eWxlBGxpbmskPC9zY3JpcHQuanM+OyByZWw9cHJlbG9h
      ZDsgYXM9c2NyaXB0AEDIBGRhdGUdTW9uLCAyNyBKdWwgMjAwOSAxMjoyODo1MyBH
      TVQGc2VydmVyBkFwYWNoZQ1sYXN0LW1vZGlmaWVkHVdlZCwgMjIgSnVsIDIwMDkg
      MTk6MTU6NTYgR01UBGV0YWcUIjM0YWEzODctZC0xNTY4ZWIwMCINYWNjZXB0LXJh
      bmdlcwVieXRlcw5jb250ZW50LWxlbmd0aAI1MQR2YXJ5D0FjY2VwdC1FbmNvZGlu
      Zwxjb250ZW50LXR5cGUKdGV4dC9wbGFpbgAzSGVsbG8gV29ybGQhIE15IGNvbnRl
      bnQgaW5jbHVkZXMgYSB0cmFpbGluZyBDUkxGLg0KAAA=
      """
    let exampleResponse = ByteBuffer(
      bytes: Data(base64Encoded: exampleResponseB64, options: .ignoreUnknownCharacters)!)
    var parser = BHTTPParser(role: .client)
    parser.append(exampleResponse)
    parser.completeBodyReceived()

    var results: [HTTPClientResponsePart] = []
    while let next = try parser.nextMessage(), case .response(let part) = next {
      results.append(part)
    }

    let expectedFinalHeaders = HTTPHeaders([
      ("date", "Mon, 27 Jul 2009 12:28:53 GMT"),
      ("server", "Apache"),
      ("last-modified", "Wed, 22 Jul 2009 19:15:56 GMT"),
      ("etag", "\"34aa387-d-1568eb00\""),
      ("accept-ranges", "bytes"),
      ("content-length", "51"),
      ("vary", "Accept-Encoding"),
      ("content-type", "text/plain"),
    ])

    XCTAssertEqual(
      results,
      [
        .head(
          .init(
            version: .http1_1,
            status: .processing,
            headers: HTTPHeaders([("running", "\"sleep 15\"")])
          )
        ),
        .head(
          .init(
            version: .http1_1,
            status: .custom(code: 103, reasonPhrase: ""),
            headers: HTTPHeaders([
              ("link", "</style.css>; rel=preload; as=style"),
              ("link", "</script.js>; rel=preload; as=script"),
            ])
          )
        ),
        .head(
          .init(
            version: .http1_1,
            status: .ok,
            headers: expectedFinalHeaders
          )
        ),
        .body(ByteBuffer(string: "Hello World! My content includes a trailing CRLF.\r\n")),
        .end(nil),
      ]
    )
  }

  func testExampleResponseIndeterminateLengthDripFed() throws {
    let exampleResponseB64 = """
      A0BmB3J1bm5pbmcKInNsZWVwIDE1IgBAZwRsaW5rIzwvc3R5bGUuY3NzPjsgcmVs
      PXByZWxvYWQ7IGFzPXN0eWxlBGxpbmskPC9zY3JpcHQuanM+OyByZWw9cHJlbG9h
      ZDsgYXM9c2NyaXB0AEDIBGRhdGUdTW9uLCAyNyBKdWwgMjAwOSAxMjoyODo1MyBH
      TVQGc2VydmVyBkFwYWNoZQ1sYXN0LW1vZGlmaWVkHVdlZCwgMjIgSnVsIDIwMDkg
      MTk6MTU6NTYgR01UBGV0YWcUIjM0YWEzODctZC0xNTY4ZWIwMCINYWNjZXB0LXJh
      bmdlcwVieXRlcw5jb250ZW50LWxlbmd0aAI1MQR2YXJ5D0FjY2VwdC1FbmNvZGlu
      Zwxjb250ZW50LXR5cGUKdGV4dC9wbGFpbgAzSGVsbG8gV29ybGQhIE15IGNvbnRl
      bnQgaW5jbHVkZXMgYSB0cmFpbGluZyBDUkxGLg0KAAA=
      """
    var exampleResponse = Data(
      base64Encoded: exampleResponseB64, options: .ignoreUnknownCharacters)!
    var parser = BHTTPParser(role: .client)

    var results: [HTTPClientResponsePart] = []
    for byte in exampleResponse {
      parser.append(ByteBuffer(integer: byte))
      exampleResponse = exampleResponse.dropFirst()

      while let next = try parser.nextMessage(), case .response(let part) = next {
        results.append(part)
      }
    }

    let expectedFinalHeaders = HTTPHeaders([
      ("date", "Mon, 27 Jul 2009 12:28:53 GMT"),
      ("server", "Apache"),
      ("last-modified", "Wed, 22 Jul 2009 19:15:56 GMT"),
      ("etag", "\"34aa387-d-1568eb00\""),
      ("accept-ranges", "bytes"),
      ("content-length", "51"),
      ("vary", "Accept-Encoding"),
      ("content-type", "text/plain"),
    ])

    var expectedResults: [HTTPClientResponsePart] = [
      .head(
        .init(
          version: .http1_1,
          status: .processing,
          headers: HTTPHeaders([("running", "\"sleep 15\"")])
        )
      ),
      .head(
        .init(
          version: .http1_1,
          status: .custom(code: 103, reasonPhrase: ""),
          headers: HTTPHeaders([
            ("link", "</style.css>; rel=preload; as=style"),
            ("link", "</script.js>; rel=preload; as=script"),
          ])
        )
      ),
      .head(
        .init(
          version: .http1_1,
          status: .ok,
          headers: expectedFinalHeaders
        )
      ),
    ]

    for byte in "Hello World! My content includes a trailing CRLF.\r\n".utf8 {
      expectedResults.append(.body(ByteBuffer(integer: byte)))
    }
    expectedResults.append(.end(nil))

    XCTAssertEqual(
      results,
      expectedResults
    )
  }
}
