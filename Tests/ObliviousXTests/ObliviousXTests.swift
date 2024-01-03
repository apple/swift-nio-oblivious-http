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
import Crypto
import Foundation
import ObliviousX
import XCTest

final class ObliviousXTests: XCTestCase {
    func testObliviousStringRoundTrip() throws {
        let request = "Hello world!"
        let response = "Hello from ObliviousX"
        let mediaType = "text/plain"

        let serverKey = P256.KeyAgreement.PrivateKey()

        let (encapsulated, sender) = try OHTTPEncapsulation.encapsulateRequest(
            keyID: 66,
            publicKey: serverKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            mediaType: mediaType,
            content: Data(request.utf8)
        )
        let (parsed, consumedBytes) = OHTTPEncapsulation.parseRequestHeader(
            encapsulatedRequest: encapsulated
        )!
        XCTAssertEqual(parsed.keyID, 66)
        XCTAssertEqual(parsed.kem, .P256_HKDF_SHA256)
        XCTAssertEqual(parsed.kdf, .HKDF_SHA256)
        XCTAssertEqual(parsed.aead, .AES_GCM_256)

        let decapsulator = OHTTPEncapsulation.RequestDecapsulator(
            requestHeader: parsed,
            message: encapsulated.dropFirst(consumedBytes)
        )
        let (deEncapsulated, context) = try decapsulator.decapsulate(
            mediaType: mediaType,
            privateKey: serverKey
        )
        XCTAssertEqual(String(decoding: deEncapsulated, as: UTF8.self), request)

        let encapsulatedResponse = try OHTTPEncapsulation.encapsulateResponse(
            context: context,
            encapsulatedKey: parsed.encapsulatedKey,
            mediaType: mediaType,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            content: Data(response.utf8)
        )

        let decapsulatedResponse = try OHTTPEncapsulation.decapsulateResponse(
            responsePayload: encapsulatedResponse,
            mediaType: mediaType,
            context: sender,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )
        XCTAssertEqual(String(decoding: decapsulatedResponse, as: UTF8.self), response)
    }

    func testSimpleStreamingHappyPath() throws {
        let request = "Counter"
        let mediaType = "text/plain"

        let serverKey = P256.KeyAgreement.PrivateKey()

        let (encapsulated, sender) = try OHTTPEncapsulation.encapsulateRequest(
            keyID: 66,
            publicKey: serverKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            mediaType: mediaType,
            content: Data(request.utf8)
        )
        let (parsed, consumedBytes) = OHTTPEncapsulation.parseRequestHeader(
            encapsulatedRequest: encapsulated
        )!
        XCTAssertEqual(parsed.keyID, 66)
        XCTAssertEqual(parsed.kem, .P256_HKDF_SHA256)
        XCTAssertEqual(parsed.kdf, .HKDF_SHA256)
        XCTAssertEqual(parsed.aead, .AES_GCM_256)

        let decapsulator = OHTTPEncapsulation.RequestDecapsulator(
            requestHeader: parsed,
            message: encapsulated.dropFirst(consumedBytes)
        )
        let (deEncapsulated, context) = try decapsulator.decapsulate(
            mediaType: mediaType,
            privateKey: serverKey
        )
        XCTAssertEqual(String(decoding: deEncapsulated, as: UTF8.self), request)

        var responseEncapsulator = try OHTTPEncapsulation.StreamingResponse(
            context: context,
            encapsulatedKey: parsed.encapsulatedKey,
            mediaType: mediaType,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )
        var responseDecapsulator = OHTTPEncapsulation.StreamingResponseDecapsulator(
            mediaType: mediaType,
            context: sender,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )

        for count in 1...12 {
            let message = "At the sound of the bell, the time will be \(count) PM."
            let encapsulated = try responseEncapsulator.encapsulate(
                Data(message.utf8),
                final: count == 12
            )
            let decapsulated = try responseDecapsulator.decapsulate(encapsulated, final: count == 12)!
            XCTAssertEqual(String(decoding: decapsulated, as: UTF8.self), message)
        }
    }

    func testStreamingIsOrderDependent() throws {
        let request = "Counter"
        let mediaType = "text/plain"

        let serverKey = P256.KeyAgreement.PrivateKey()

        let (encapsulated, sender) = try OHTTPEncapsulation.encapsulateRequest(
            keyID: 66,
            publicKey: serverKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            mediaType: mediaType,
            content: Data(request.utf8)
        )
        let (parsed, consumedBytes) = OHTTPEncapsulation.parseRequestHeader(
            encapsulatedRequest: encapsulated
        )!
        XCTAssertEqual(parsed.keyID, 66)
        XCTAssertEqual(parsed.kem, .P256_HKDF_SHA256)
        XCTAssertEqual(parsed.kdf, .HKDF_SHA256)
        XCTAssertEqual(parsed.aead, .AES_GCM_256)

        let decapsulator = OHTTPEncapsulation.RequestDecapsulator(
            requestHeader: parsed,
            message: encapsulated.dropFirst(consumedBytes)
        )
        let (deEncapsulated, context) = try decapsulator.decapsulate(
            mediaType: mediaType,
            privateKey: serverKey
        )
        XCTAssertEqual(String(decoding: deEncapsulated, as: UTF8.self), request)

        var responseEncapsulator = try OHTTPEncapsulation.StreamingResponse(
            context: context,
            encapsulatedKey: parsed.encapsulatedKey,
            mediaType: mediaType,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )
        var responseDecapsulator = OHTTPEncapsulation.StreamingResponseDecapsulator(
            mediaType: mediaType,
            context: sender,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )

        let encapsulatedMessages: [Data] = try (1...2).map { count in
            let message = "At the sound of the bell, the time will be \(count) PM."
            return try responseEncapsulator.encapsulate(Data(message.utf8), final: false)
        }

        // Try to decrypt the second message first. It won't work!
        XCTAssertThrowsError(
            try responseDecapsulator.decapsulate(encapsulatedMessages.last!, final: false)
        )
    }

    func testStreamingRequestIsOrderDependent() throws {
        let messages: [Data] = (1...12).map { count in
            Data("At the sound of the bell, the time will be \(count) PM.".utf8)
        }
        let mediaType = "text/plain"

        let serverKey = P256.KeyAgreement.PrivateKey()

        var encapsulator = try OHTTPEncapsulation.StreamingRequest(
            keyID: 66,
            publicKey: serverKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            mediaType: mediaType
        )

        let encapsulatedMessages = try messages.map {
            try encapsulator.encapsulate(content: $0, final: false)
        }

        let (parsed, consumedBytes) = OHTTPEncapsulation.parseRequestHeader(
            encapsulatedRequest: encapsulator.header
        )!
        XCTAssertEqual(parsed.keyID, 66)
        XCTAssertEqual(parsed.kem, .P256_HKDF_SHA256)
        XCTAssertEqual(parsed.kdf, .HKDF_SHA256)
        XCTAssertEqual(parsed.aead, .AES_GCM_256)
        XCTAssertEqual(consumedBytes, encapsulator.header.count)

        var decapsulator = try OHTTPEncapsulation.StreamingRequestDecapsulator(
            requestHeader: parsed,
            mediaType: mediaType,
            privateKey: serverKey
        )

        let decapsulated: [Data] = try encapsulatedMessages.map { message in
            try decapsulator.decapsulate(content: message, final: false)
        }

        XCTAssertEqual(messages, decapsulated)
    }

    func testAgreeingOnFinalityWorks_request() throws {
        let messages: [Data] = (1...12).map { count in
            Data("At the sound of the bell, the time will be \(count) PM.".utf8)
        }
        let mediaType = "text/plain"

        let serverKey = P256.KeyAgreement.PrivateKey()

        var encapsulator = try OHTTPEncapsulation.StreamingRequest(
            keyID: 66,
            publicKey: serverKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            mediaType: mediaType
        )

        var encapsulatedMessages = try messages.dropLast().map {
            try encapsulator.encapsulate(content: $0, final: false)
        }
        encapsulatedMessages.append(try encapsulator.encapsulate(content: messages.last!, final: true))

        let (parsed, consumedBytes) = OHTTPEncapsulation.parseRequestHeader(
            encapsulatedRequest: encapsulator.header
        )!
        XCTAssertEqual(parsed.keyID, 66)
        XCTAssertEqual(parsed.kem, .P256_HKDF_SHA256)
        XCTAssertEqual(parsed.kdf, .HKDF_SHA256)
        XCTAssertEqual(parsed.aead, .AES_GCM_256)
        XCTAssertEqual(consumedBytes, encapsulator.header.count)

        var decapsulator = try OHTTPEncapsulation.StreamingRequestDecapsulator(
            requestHeader: parsed,
            mediaType: mediaType,
            privateKey: serverKey
        )

        var decapsulated: [Data] = try encapsulatedMessages.dropLast().map { message in
            try decapsulator.decapsulate(content: message, final: false)
        }
        decapsulated.append(
            try decapsulator.decapsulate(content: encapsulatedMessages.last!, final: true)
        )

        XCTAssertEqual(messages, decapsulated)
    }

    func testAgreeingOnFinalityWorks_response() throws {
        let request = "Counter"
        let mediaType = "text/plain"

        let serverKey = P256.KeyAgreement.PrivateKey()

        let (encapsulated, sender) = try OHTTPEncapsulation.encapsulateRequest(
            keyID: 66,
            publicKey: serverKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            mediaType: mediaType,
            content: Data(request.utf8)
        )
        let (parsed, consumedBytes) = OHTTPEncapsulation.parseRequestHeader(
            encapsulatedRequest: encapsulated
        )!

        let decapsulator = OHTTPEncapsulation.RequestDecapsulator(
            requestHeader: parsed,
            message: encapsulated.dropFirst(consumedBytes)
        )
        let (deEncapsulated, context) = try decapsulator.decapsulate(
            mediaType: mediaType,
            privateKey: serverKey
        )
        XCTAssertEqual(String(decoding: deEncapsulated, as: UTF8.self), request)

        var responseEncapsulator = try OHTTPEncapsulation.StreamingResponse(
            context: context,
            encapsulatedKey: parsed.encapsulatedKey,
            mediaType: mediaType,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )
        var responseDecapsulator = OHTTPEncapsulation.StreamingResponseDecapsulator(
            mediaType: mediaType,
            context: sender,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )

        let messages: [Data] = (1...12).map { count in
            Data("At the sound of the bell, the time will be \(count) PM.".utf8)
        }
        var encapsulatedMessages: [Data] = try messages.dropLast().map { message in
            return try responseEncapsulator.encapsulate(message, final: false)
        }
        encapsulatedMessages.append(try responseEncapsulator.encapsulate(messages.last!, final: true))

        var decapsulated: [Data] = try encapsulatedMessages.dropLast().map { message in
            try responseDecapsulator.decapsulate(message, final: false)!
        }
        decapsulated.append(
            try responseDecapsulator.decapsulate(encapsulatedMessages.last!, final: true)!
        )

        XCTAssertEqual(messages, decapsulated)
    }

    func testDisagreeingOnFinalityIsAnError_request_recipientMissing() throws {
        let messages: [Data] = (1...12).map { count in
            Data("At the sound of the bell, the time will be \(count) PM.".utf8)
        }
        let mediaType = "text/plain"

        let serverKey = P256.KeyAgreement.PrivateKey()

        var encapsulator = try OHTTPEncapsulation.StreamingRequest(
            keyID: 66,
            publicKey: serverKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            mediaType: mediaType
        )

        var encapsulatedMessages = try messages.dropLast().map {
            try encapsulator.encapsulate(content: $0, final: false)
        }
        encapsulatedMessages.append(try encapsulator.encapsulate(content: messages.last!, final: true))

        let (parsed, consumedBytes) = OHTTPEncapsulation.parseRequestHeader(
            encapsulatedRequest: encapsulator.header
        )!
        XCTAssertEqual(parsed.keyID, 66)
        XCTAssertEqual(parsed.kem, .P256_HKDF_SHA256)
        XCTAssertEqual(parsed.kdf, .HKDF_SHA256)
        XCTAssertEqual(parsed.aead, .AES_GCM_256)
        XCTAssertEqual(consumedBytes, encapsulator.header.count)

        var decapsulator = try OHTTPEncapsulation.StreamingRequestDecapsulator(
            requestHeader: parsed,
            mediaType: mediaType,
            privateKey: serverKey
        )

        let decapsulated: [Data] = try encapsulatedMessages.dropLast().map { message in
            try decapsulator.decapsulate(content: message, final: false)
        }

        XCTAssertEqual(messages.dropLast(), decapsulated)

        XCTAssertThrowsError(
            try decapsulator.decapsulate(content: encapsulatedMessages.last!, final: false)
        )
    }

    func testDisagreeingOnFinalityIsAnError_request_senderMissing() throws {
        let messages: [Data] = (1...12).map { count in
            Data("At the sound of the bell, the time will be \(count) PM.".utf8)
        }
        let mediaType = "text/plain"

        let serverKey = P256.KeyAgreement.PrivateKey()

        var encapsulator = try OHTTPEncapsulation.StreamingRequest(
            keyID: 66,
            publicKey: serverKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            mediaType: mediaType
        )

        let encapsulatedMessages = try messages.map {
            try encapsulator.encapsulate(content: $0, final: false)
        }

        let (parsed, consumedBytes) = OHTTPEncapsulation.parseRequestHeader(
            encapsulatedRequest: encapsulator.header
        )!
        XCTAssertEqual(parsed.keyID, 66)
        XCTAssertEqual(parsed.kem, .P256_HKDF_SHA256)
        XCTAssertEqual(parsed.kdf, .HKDF_SHA256)
        XCTAssertEqual(parsed.aead, .AES_GCM_256)
        XCTAssertEqual(consumedBytes, encapsulator.header.count)

        var decapsulator = try OHTTPEncapsulation.StreamingRequestDecapsulator(
            requestHeader: parsed,
            mediaType: mediaType,
            privateKey: serverKey
        )

        let decapsulated: [Data] = try encapsulatedMessages.dropLast().map { message in
            try decapsulator.decapsulate(content: message, final: false)
        }

        XCTAssertEqual(messages.dropLast(), decapsulated)

        XCTAssertThrowsError(
            try decapsulator.decapsulate(content: encapsulatedMessages.last!, final: true)
        )
    }

    func testDisagreeingOnFinalityIsAnError_response_recipientMissing() throws {
        let request = "Counter"
        let mediaType = "text/plain"

        let serverKey = P256.KeyAgreement.PrivateKey()

        let (encapsulated, sender) = try OHTTPEncapsulation.encapsulateRequest(
            keyID: 66,
            publicKey: serverKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            mediaType: mediaType,
            content: Data(request.utf8)
        )
        let (parsed, consumedBytes) = OHTTPEncapsulation.parseRequestHeader(
            encapsulatedRequest: encapsulated
        )!

        let decapsulator = OHTTPEncapsulation.RequestDecapsulator(
            requestHeader: parsed,
            message: encapsulated.dropFirst(consumedBytes)
        )
        let (deEncapsulated, context) = try decapsulator.decapsulate(
            mediaType: mediaType,
            privateKey: serverKey
        )
        XCTAssertEqual(String(decoding: deEncapsulated, as: UTF8.self), request)

        var responseEncapsulator = try OHTTPEncapsulation.StreamingResponse(
            context: context,
            encapsulatedKey: parsed.encapsulatedKey,
            mediaType: mediaType,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )
        var responseDecapsulator = OHTTPEncapsulation.StreamingResponseDecapsulator(
            mediaType: mediaType,
            context: sender,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )

        let messages: [Data] = (1...12).map { count in
            Data("At the sound of the bell, the time will be \(count) PM.".utf8)
        }
        var encapsulatedMessages: [Data] = try messages.dropLast().map { message in
            return try responseEncapsulator.encapsulate(message, final: false)
        }
        encapsulatedMessages.append(try responseEncapsulator.encapsulate(messages.last!, final: true))

        let decapsulated: [Data] = try encapsulatedMessages.dropLast().map { message in
            try responseDecapsulator.decapsulate(message, final: false)!
        }

        XCTAssertEqual(messages.dropLast(), decapsulated)
        XCTAssertThrowsError(
            try responseDecapsulator.decapsulate(encapsulatedMessages.last!, final: false)
        )
    }

    func testDisagreeingOnFinalityIsAnError_response_senderMissing() throws {
        let request = "Counter"
        let mediaType = "text/plain"

        let serverKey = P256.KeyAgreement.PrivateKey()

        let (encapsulated, sender) = try OHTTPEncapsulation.encapsulateRequest(
            keyID: 66,
            publicKey: serverKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            mediaType: mediaType,
            content: Data(request.utf8)
        )
        let (parsed, consumedBytes) = OHTTPEncapsulation.parseRequestHeader(
            encapsulatedRequest: encapsulated
        )!

        let decapsulator = OHTTPEncapsulation.RequestDecapsulator(
            requestHeader: parsed,
            message: encapsulated.dropFirst(consumedBytes)
        )
        let (deEncapsulated, context) = try decapsulator.decapsulate(
            mediaType: mediaType,
            privateKey: serverKey
        )
        XCTAssertEqual(String(decoding: deEncapsulated, as: UTF8.self), request)

        var responseEncapsulator = try OHTTPEncapsulation.StreamingResponse(
            context: context,
            encapsulatedKey: parsed.encapsulatedKey,
            mediaType: mediaType,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )
        var responseDecapsulator = OHTTPEncapsulation.StreamingResponseDecapsulator(
            mediaType: mediaType,
            context: sender,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )

        let messages: [Data] = (1...12).map { count in
            Data("At the sound of the bell, the time will be \(count) PM.".utf8)
        }
        let encapsulatedMessages: [Data] = try messages.map { message in
            return try responseEncapsulator.encapsulate(message, final: false)
        }

        let decapsulated: [Data] = try encapsulatedMessages.dropLast().map { message in
            try responseDecapsulator.decapsulate(message, final: false)!
        }

        XCTAssertEqual(messages.dropLast(), decapsulated)
        XCTAssertThrowsError(
            try responseDecapsulator.decapsulate(encapsulatedMessages.last!, final: true)
        )
    }
}
