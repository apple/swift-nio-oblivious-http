import Crypto
import Foundation
import XCTest

@testable import ObliviousX

final class ObliviousDoHTests: XCTestCase {
    func testObliviousDoHRoundtrip() throws {
        let request = "Hello world!"
        let responseText = "Hello from ObliviousX"

        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey.init()
        let configuration = try ODoH.Configuration.v1(privateKey: serverPrivateKey)

        let routine = try ODoH.Routine(configuration: configuration)

        let query = ODoH.MessagePlaintext(dnsMessage: Data(request.utf8), paddingLength: 128)
        let (encryptedQuery, clientContext) = try routine.encryptQuery(
            queryPlain: query
        )

        XCTAssertNotEqual(query.encode(), encryptedQuery)

        let (decryptedQuery, serverContext) = try routine.decryptQuery(
            queryData: encryptedQuery,
            privateKey: serverPrivateKey
        )

        XCTAssertEqual(query, decryptedQuery)

        let response = ODoH.MessagePlaintext(dnsMessage: Data(responseText.utf8), paddingLength: 64)
        let encryptedResponse = try routine.encryptResponse(
            recepient: serverContext,
            queryPlain: query,  // Need original query for key derivation
            responsePlain: response
        )

        XCTAssertNotEqual(response.encode(), encryptedResponse)

        // 4. Client decrypts response
        let decryptedResponse = try routine.decryptResponse(
            context: clientContext,
            queryPlain: query,
            responseData: encryptedResponse
        )
        XCTAssertEqual(response, decryptedResponse)
    }

    func testConfigurationsParsing() throws {
        // Configuration grabbed from odoh.cloudflare-dns.com/.well-known/odohconfigs
        let configurationsBytes: [UInt8] = [
            0x00, 0x2C, 0x00, 0x01, 0x00, 0x28, 0x00, 0x20, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x20, 0x8B, 0x70, 0xFE, 0xDD, 0x79, 0xBA,
            0x68, 0x55, 0xDB, 0x1D, 0x01, 0x25, 0xBF, 0x2D, 0xEA, 0xC0,
            0xE6, 0x88, 0x3B, 0x4F, 0xC0, 0x41, 0xD0, 0xB6, 0xA3, 0x34,
            0x71, 0x36, 0x33, 0xCF, 0x36, 0x4C,
        ]
        var configurationsData = Data(configurationsBytes)

        let configurations = ODoH.Configurations.parseWithDetails(&configurationsData)
        XCTAssert(configurations.hasValidConfigurations)
        XCTAssert(configurations.failedConfigurations.isEmpty)
    }
}
