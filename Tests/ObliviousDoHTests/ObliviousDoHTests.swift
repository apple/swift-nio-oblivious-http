//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftNIO project authors
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
import XCTest

@testable import ObliviousDoH

final class ObliviousDoHTests: XCTestCase {
    func testConfigurationsParsing() throws {
        // Configuration grabbed from odoh.cloudflare-dns.com/.well-known/odohconfigs
        var configurationsData = Data([
            0x00, 0x2C, 0x00, 0x01, 0x00, 0x28, 0x00, 0x20, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x20, 0x8B, 0x70, 0xFE, 0xDD, 0x79, 0xBA,
            0x68, 0x55, 0xDB, 0x1D, 0x01, 0x25, 0xBF, 0x2D, 0xEA, 0xC0,
            0xE6, 0x88, 0x3B, 0x4F, 0xC0, 0x41, 0xD0, 0xB6, 0xA3, 0x34,
            0x71, 0x36, 0x33, 0xCF, 0x36, 0x4C,
        ])

        let configurations = [ODoH.Configuration].decodeWithDetails(decoding: &configurationsData)
        XCTAssert(configurations.hasValidConfigurations)
        XCTAssert(configurations.failedConfigurations.isEmpty)
    }

    func testConfigurationParsingWithMalformedData() throws {
        // Test truncated data
        var truncatedData = Data([0x00, 0x10])  // Claims 16 bytes but only has 2
        let result = [ODoH.Configuration].decodeWithDetails(decoding: &truncatedData)
        XCTAssertFalse(result.hasValidConfigurations)
        XCTAssertEqual(result.failedConfigurations.count, 1)
    }

    func testConfigurationParsingWithUnsupportedVersion() throws {
        // Create config with version 0x0002 (unsupported)
        var data = Data([0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04])
        let result = [ODoH.Configuration].decodeWithDetails(decoding: &data)
        XCTAssertFalse(result.hasValidConfigurations)
        XCTAssertEqual(result.failedConfigurations.count, 1)
    }

    func testConfigurationContentsExtraBytes() throws {
        // Valid config data + extra trailing bytes
        var data = Data([
            0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,  // valid key data
            0xFF, 0xFF,  // extra bytes that should cause failure
        ])
        let result = ODoH.ConfigurationContents.decodeWithDetails(decoding: &data)
        XCTAssertEqual(result, .failure(.invalidODoHData))
    }

    func testConfigurationWithInvalidPublicKey() throws {
        // Create config with invalid key for Curve25519 (wrong length)
        var data = Data([
            0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,  // Invalid 4-byte key (should be 32 bytes for Curve25519)
        ])
        let result = ODoH.ConfigurationContents.decodeWithDetails(decoding: &data)
        if case .failure(let error) = result {
            // Check that it's an invalidPublicKey error
            guard case .invalidPublicKey(kemID: 0x0020, key: Data([0x01, 0x02, 0x03, 0x04])) = error else {
                XCTFail("Expected invalidPublicKey error, got: \(error)")
                return
            }
        } else {
            XCTFail("Expected failure")
        }
    }

    func testMessageWithEmptyKeyID() throws {
        var data = Data([
            0x01,  // query type
            0x00, 0x00,  // zero length key ID
            0x00, 0x04,  // encrypted message length
            0x01, 0x02, 0x03, 0x04,  // encrypted message
        ])
        guard let message = try? ODoH.Message(decoding: &data) else {
            XCTFail()
            return
        }

        XCTAssertEqual(message.keyID, Data())
    }

    func testMessagePlaintextWithInvalidPadding() throws {
        // Create message with non-zero padding
        var data = Data([
            0x00, 0x05,  // DNS length: 5
            0x48, 0x65, 0x6C, 0x6C, 0x6F,  // "Hello"
            0x00, 0x03,  // Padding length: 3
            0x00, 0xFF, 0x00,  // Padding with non-zero byte (should fail)
        ])

        let result = try? ODoH.MessagePlaintext(decoding: &data)
        XCTAssertNil(result)  // Should fail due to invalid padding
    }

    func testMessagePlaintextWithValidPadding() throws {
        var data = Data([
            0x00, 0x05,  // DNS length: 5
            0x48, 0x65, 0x6C, 0x6C, 0x6F,  // "Hello"
            0x00, 0x03,  // Padding length: 3
            0x00, 0x00, 0x00,  // Valid zero padding
        ])

        let result = try? ODoH.MessagePlaintext(decoding: &data)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.paddingLength, 3)
    }

    func testObliviousDoHRoundtrip() throws {
        let request = "Hello world!"
        let responseText = "Hello from ObliviousX"

        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey.init()
        let configuration = try ODoH.Configuration.v1(privateKey: serverPrivateKey)

        let routine = try ODoH.Routine(configuration: configuration)

        let query = ODoH.MessagePlaintext(dnsMessage: Data(request.utf8), paddingLength: 128)
        let queryEncryptResult = try routine.encryptQuery(
            queryPlain: query
        )

        XCTAssertNotEqual(query.encode(), queryEncryptResult.encryptedQuery)

        let queryDecryptResult = try routine.decryptQuery(
            queryData: queryEncryptResult.encryptedQuery,
            privateKey: serverPrivateKey
        )

        XCTAssertEqual(query, queryDecryptResult.plaintextQuery)

        let response = ODoH.MessagePlaintext(dnsMessage: Data(responseText.utf8), paddingLength: 64)
        let encryptedResponse = try routine.encryptResponse(
            queryDecryptionResult: queryDecryptResult,
            responsePlain: response
        )

        XCTAssertNotEqual(response.encode(), encryptedResponse)

        // 4. Client decrypts response
        let decryptedResponse = try routine.decryptResponse(
            queryEncryptionResult: queryEncryptResult,
            queryPlain: query,
            responseData: encryptedResponse
        )
        XCTAssertEqual(response, decryptedResponse)
    }
}
