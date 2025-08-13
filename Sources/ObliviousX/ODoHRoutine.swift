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
@preconcurrency import Crypto
import Foundation

/// Context strings used in HPKE key derivation for different purposes in ODoH protocol.
/// These strings provide domain separation to ensure keys derived for different purposes
/// are cryptographically independent, as required by RFC 9230 Section 6.2.

/// Used to derive the key identifier from the target's public key configuration
let ODoHKeyIDInfo = Data("odoh key id".utf8)

/// Used as HPKE info parameter when setting up encryption context for DNS queries
let ODoHQueryInfo = Data("odoh query".utf8)

/// Used when exporting secrets from HPKE context for response encryption
let ODoHResponseInfo = Data("odoh response".utf8)

/// Used to derive the AEAD key for encrypting/decrypting DNS responses
let ODoHKeyInfo = Data("odoh key".utf8)

/// Used to derive the AEAD nonce for encrypting/decrypting DNS responses
let ODoHNonceInfo = Data("odoh nonce".utf8)

public struct ODoH: Sendable {
    public struct Routine {
        public private(set) var ct: HPKE.Ciphersuite
        public private(set) var pkR: any HPKEDiffieHellmanPublicKey
        public private(set) var keyID: Data

        /// Initialize ODoH encryption with target server configuration.
        ///
        /// Extracts the HPKE ciphersuite parameters and derives the key identifier
        /// from the provided configuration. The key identifier is computed using
        /// HKDF as specified in RFC 9230 Section 6.2.
        ///
        /// - Parameter configuration: Target server's ODoH configuration
        /// - Throws: `CryptoKitError` if public key format is invalid
        public init(configuration: Configuration) throws {
            precondition(configuration.contents.aead != .exportOnly)
            self.ct = HPKE.Ciphersuite(
                kem: configuration.contents.kem,
                kdf: configuration.contents.kdf,
                aead: configuration.contents.aead
            )
            self.pkR = try self.ct.kem.getPublicKey(data: configuration.contents.publicKey)
            self.keyID = configuration.contents.identifier
        }
    }

    /// Result of parsing a collection of ODoH configurations.
    ///
    /// Contains both successfully parsed configurations and detailed information
    /// about configurations that failed to parse, allowing clients to understand
    /// which configurations are supported.
    public struct ConfigurationParsingResult: Sendable {
        public let validConfigurations: ODoH.Configurations
        public let failedConfigurations: [(rawData: Data, error: ObliviousXError)]
        public var hasValidConfigurations: Bool { !validConfigurations.isEmpty }

        internal init(
            validConfigurations: ODoH.Configurations,
            failedConfigurations: [(rawData: Data, error: ObliviousXError)]
        ) {
            self.validConfigurations = validConfigurations
            self.failedConfigurations = failedConfigurations
        }
    }

    /// Collection of ODoH configurations published by servers.
    /// Contains multiple configurations in decreasing order of preference.
    /// Served at /.well-known/odohconfigs for client discovery.
    public typealias Configurations = [Configuration]

    /// Configuration for ODoH operations containing the target resolver's public key and cryptographic parameters.
    ///
    /// This configuration is typically obtained from the target resolver's well-known endpoint (/.well-known/odohconfigs)
    /// and contains all necessary parameters to encrypt DNS queries that only the target resolver can decrypt.
    /// Multiple configurations may be provided by servers to support different algorithm suites or key rotation.
    public struct Configuration: Sendable {
        public private(set) var version: UInt16
        // length prefix (UInt16)
        public private(set) var contents: ConfigurationContents

        /// Creates a new ODoH configuration with specified version and contents.
        ///
        /// - Parameters:
        ///   - version: Protocol version number (0x0001 for RFC 9230)
        ///   - contents: Configuration contents with algorithms and public key
        internal init(version: UInt16, contents: ConfigurationContents) {
            self.version = version
            self.contents = contents
        }

        /// Create ODoH v1 configuration with standard algorithm suite.
        ///
        /// Constructs a version 1 ODoH configuration using the recommended algorithm
        /// combination from RFC 9230: X25519 + HKDF-SHA256 + AES-128-GCM.
        ///
        /// - Parameter privateKey: Private key of the server
        /// - Returns: Complete ODoH configuration ready for use
        /// - Throws: `CryptoKitError` if key serialization fails
        public static func v1(privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Self {
            let kem: HPKE.KEM = .Curve25519_HKDF_SHA256
            return .init(
                version: 0x0001,
                contents: .init(
                    kem: kem,
                    kdf: .HKDF_SHA256,
                    aead: .AES_GCM_128,
                    publicKey: try privateKey.publicKey.hpkeRepresentation(kem: kem)
                )
            )
        }
    }

    /// Configuration contents specifying cryptographic algorithms and public key.
    ///
    /// Contains the essential parameters needed for ODoH operations: the HPKE algorithm
    /// identifiers and the target server's public key. This structure is embedded within
    /// the versioned Configuration wrapper for wire format transmission.
    public struct ConfigurationContents: Sendable {
        public private(set) var kem: HPKE.KEM
        public private(set) var kdf: HPKE.KDF
        public private(set) var aead: HPKE.AEAD
        // length prefix (UInt16)
        public private(set) var publicKey: Data

        internal init(kem: HPKE.KEM, kdf: HPKE.KDF, aead: HPKE.AEAD, publicKey: Data) {
            self.kem = kem
            self.kdf = kdf
            self.aead = aead
            self.publicKey = publicKey
        }

        /// Total byte length of this configuration when encoded to wire format.
        ///
        /// Calculates the sum of all field sizes: KEM ID (2) + KDF ID (2) +
        /// AEAD ID (2) + public key length field (2) + public key data length.
        var length: Int {
            2 + 2 + 2 + 2 + publicKey.count
        }

        /// Derive key identifier from public key using HKDF.
        ///
        /// Computes a unique identifier for this configuration by applying HKDF
        /// to the public key data with domain separation. This identifier is used
        /// in protocol messages to reference the specific key configuration.
        ///
        /// Formula: Expand(Extract("", contents), "odoh key id", Nh)
        var identifier: Data {
            Data(
                self.kdf.expand(
                    prk: self.kdf.extract(salt: Data(), ikm: .init(data: self.encode())),
                    info: ODoHKeyIDInfo,
                    outputByteCount: self.kdf.hashByteCount
                )
            )
        }
    }

    /// Represents a plaintext DNS message before encryption or after decryption in ODoH.
    ///
    /// This structure contains the DNS query or response data along with padding information
    /// to help obscure the actual message size and improve privacy by preventing traffic analysis.
    /// The padding consists of zero bytes that are validated during decryption to ensure integrity.
    public struct MessagePlaintext: Equatable, Sendable {
        // length prefix (UInt16)
        public private(set) var dnsMessage: Data
        // length prefix (UInt16)
        public private(set) var padding: [UInt8]

        /// Create plaintext message with DNS data and padding.
        ///
        /// Constructs an ODoH plaintext message containing a DNS query or response
        /// along with zero-filled padding. Padding helps obscure the true size of
        /// DNS messages to improve privacy by making traffic analysis more difficult.
        /// The total message size (DNS data + padding) is limited by the wire format.
        ///
        /// - Parameters:
        ///   - dnsMessage: The DNS message in wire format (standard DNS packet)
        ///   - paddingLength: Number of zero bytes to append as padding (0-65535)
        public init(dnsMessage: Data, paddingLength: Int = 0) {
            self.dnsMessage = dnsMessage
            self.padding = .init(repeating: 0, count: paddingLength)
        }

        public var size: Int {
            self.dnsMessage.count + self.padding.count
        }
    }

    /// Complete ODoH message with type, key/nonce, and encrypted payload.
    ///
    /// Represents a complete ODoH message as transmitted over the network. The structure
    /// is used for both queries (client to server) and responses (server to client).
    /// The keyID field serves dual purposes depending on message type.
    ///
    /// Servers can use this to parse incoming messages and extract the keyID to determine
    /// which private key should be used for decryption.
    public struct Message: Sendable {
        /// ODoH message types as defined in RFC 9230 Section 6.1.
        ///
        /// Distinguishes between client queries and server responses in the protocol.
        /// The message type affects how certain fields are interpreted and which
        /// cryptographic operations are applied.
        enum MessageType: UInt8, Sendable {
            /// Client DNS query encrypted for the target server
            case query = 1
            /// Server DNS response encrypted for the client
            case response = 2
        }

        let messageType: MessageType
        public internal(set) var keyID: Data
        public internal(set) var encryptedMessage: Data

        /// Create ODoH message with type, key/nonce, and encrypted payload.
        ///
        /// Constructs a complete ODoH message ready for network transmission.
        /// The keyID field serves dual purposes: for queries it holds the target's
        /// key identifier, for responses it holds the server-generated nonce.
        ///
        /// - Parameters:
        ///   - messageType: Whether this is a query or response
        ///   - keyID: Key identifier (queries) or response nonce (responses)
        ///   - encryptedMessage: The HPKE or AEAD encrypted payload
        init(messageType: MessageType, keyID: Data, encryptedMessage: Data) {
            self.messageType = messageType
            self.keyID = keyID
            self.encryptedMessage = encryptedMessage
        }

        public var isResponse: Bool {
            self.messageType == .response
        }
    }
}
