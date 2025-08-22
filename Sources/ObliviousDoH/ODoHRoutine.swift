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
import ObliviousXHelpers

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif


public enum ODoH: Sendable {
    // - MARK: Protocol Types

    /// Result of encrypting a DNS query for transmission through a proxy.
    ///
    /// Contains the encrypted query data and the HPKE sender context needed
    /// for decrypting the corresponding response from the server.
    public struct QueryEncryptionResult: Sendable {
        /// The encrypted query message ready for network transmission
        public let encryptedQuery: Data
        /// HPKE sender context required for response decryption
        public let context: HPKE.Sender

        internal init(encryptedQuery: Data, context: HPKE.Sender) {
            self.encryptedQuery = encryptedQuery
            self.context = context
        }
    }

    /// Result of decrypting a DNS query received from a proxy.
    ///
    /// Contains the decrypted query plaintext and the HPKE recipient context
    /// needed for encrypting the corresponding response back to the client.
    public struct QueryDecryptionResult: Sendable {
        /// The decrypted DNS query message
        public let plaintextQuery: MessagePlaintext
        /// HPKE recipient context required for response encryption
        public let context: HPKE.Recipient

        internal init(plaintextQuery: MessagePlaintext, context: HPKE.Recipient) {
            self.plaintextQuery = plaintextQuery
            self.context = context
        }
    }

    /// Result of parsing a collection of ODoH configurations.
    ///
    /// Contains both successfully parsed configurations and detailed information
    /// about configurations that failed to parse, allowing clients to understand
    /// which configurations are supported.
    public struct ConfigurationParsingResult: Sendable {
        public let validConfigurations: ODoH.Configurations
        public let failedConfigurations: [(rawData: Data, error: ObliviousDoHError)]
        public var hasValidConfigurations: Bool { !validConfigurations.isEmpty }

        internal init(
            validConfigurations: ODoH.Configurations,
            failedConfigurations: [(rawData: Data, error: ObliviousDoHError)]
        ) {
            self.validConfigurations = validConfigurations
            self.failedConfigurations = failedConfigurations
        }
    }

    /// Protocol for types that can be serialized to and from ODoH wire format.
    ///
    /// Provides bidirectional conversion between Swift types and their network representation
    /// as specified in RFC 9230. All ODoH message types implement this protocol to enable
    /// consistent serialization and parsing across the protocol stack.
    public protocol Codable {
        /// Initialize from wire format bytes, consuming data as it parses
        /// - Parameter bytes: The raw network data to parse (consumed during parsing)
        /// - Returns: `nil` if parsing fails or data is invalid
        init?(_ bytes: inout Data)

        /// Serialize to wire format bytes
        /// - Returns: The encoded data ready for network transmission
        func encode() throws -> Data
    }

    /// Collection of ODoH configurations published by servers.
    /// Contains multiple configurations in decreasing order of preference.
    /// Served at /.well-known/odohconfigs for client discovery.
    public typealias Configurations = [Configuration]

    /// Protocol for configuration contents that can vary by version
    /// Guarantees HPKE-required properties that should be stable across versions
    public protocol ConfigurationContentsProtocol: Sendable, Equatable, Hashable, ODoH.Codable {
        var kem: HPKE.KEM { get }
        var kdf: HPKE.KDF { get }
        var aead: HPKE.AEAD { get }
        var publicKey: Data { get }

        var length: Int { get }
        var identifier: Data { get }

        /// Parse configuration contents with detailed error information.
        ///
        /// This method provides comprehensive error information when configuration contents parsing fails,
        /// allowing callers to understand exactly what went wrong during parsing.
        ///
        /// - Parameter bytes: The wire format data to parse
        /// - Returns: Result containing either valid configuration contents or detailed error information
        static func parseWithDetails(_ bytes: inout Data) -> Result<Self, ObliviousDoHError>
    }

    /// Configuration for ODoH operations containing the target resolver's public key and cryptographic parameters.
    ///
    /// This configuration is typically obtained from the target resolver's well-known endpoint (/.well-known/odohconfigs)
    /// and contains all necessary parameters to encrypt DNS queries that only the target resolver can decrypt.
    /// Multiple configurations may be provided by servers to support different algorithm suites or key rotation.
    public struct Configuration: Sendable {
        internal enum ContentsBacking: Equatable, Hashable, Sendable {
            case v1(ConfigurationContents)

            var version: Int {
                switch self {
                case .v1:
                    return 0x0001
                }
            }
        }
        internal private(set) var contentsBacking: ContentsBacking

        public var version: Int {
            contentsBacking.version
        }
        // length prefix (UInt16)
        public var contents: any ConfigurationContentsProtocol {
            switch contentsBacking {
            case .v1(let contents):
                return contents
            }
        }

        /// Creates a new ODoH configuration with the specified contents backing.
        ///
        /// - Parameter contentsBacking: The version-specific contents backing
        internal init(contentsBacking: ContentsBacking) {
            self.contentsBacking = contentsBacking
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
            let contents = ConfigurationContents(
                kem: kem,
                kdf: .HKDF_SHA256,
                aead: .AES_GCM_128,
                publicKey: try privateKey.publicKey.hpkeRepresentation(kem: kem)
            )
            return .init(contentsBacking: .v1(contents))
        }
    }

    /// Configuration contents specifying cryptographic algorithms and public key.
    ///
    /// Contains the essential parameters needed for ODoH operations: the HPKE algorithm
    /// identifiers and the target server's public key. This structure is embedded within
    /// the versioned Configuration wrapper for wire format transmission.
    public struct ConfigurationContents: ConfigurationContentsProtocol {
        public let kem: HPKE.KEM
        public let kdf: HPKE.KDF
        public let aead: HPKE.AEAD
        // length prefix (UInt16)
        public let publicKey: Data

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
        public var length: Int {
            2 + 2 + 2 + 2 + publicKey.count
        }

        /// Derive key identifier from public key using HKDF.
        ///
        /// Computes a unique identifier for this configuration by applying HKDF
        /// to the public key data with domain separation. This identifier is used
        /// in protocol messages to reference the specific key configuration.
        ///
        /// Formula: Expand(Extract("", contents), "odoh key id", Nh)
        public var identifier: Data {
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
        public var dnsMessage: Data
        // length prefix (UInt16)
        public var paddingLength: Int

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
            self.paddingLength = paddingLength
        }

        public var size: Int {
            self.dnsMessage.count + self.paddingLength
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
        public struct MessageType: Equatable, Hashable, Sendable {
            public let rawValue: UInt8

            public static func query() -> Self {
                Self(rawValue: 1)
            }

            public static func response() -> Self {
                Self(rawValue: 2)
            }

            public static func other(_ rawValue: UInt8) -> Self {
                Self(rawValue: rawValue)
            }

            init(rawValue: UInt8) {
                self.rawValue = rawValue
            }
        }

        public var messageType: MessageType
        public var keyID: Data
        public var encryptedMessage: Data

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
        public init(messageType: MessageType, keyID: Data, encryptedMessage: Data) {
            self.messageType = messageType
            self.keyID = keyID
            self.encryptedMessage = encryptedMessage
        }

        public var isResponse: Bool {
            self.messageType == .response()
        }
    }
}

// MARK: - ODoH.Codable Implementations

extension ODoH.Configurations: ODoH.Codable {
    /// Deserialize configurations collection from wire format bytes.
    ///
    /// **Wire Format:**
    /// - total_length (2 bytes): Total length of all configurations
    /// - configs (variable): Concatenated Configuration structures
    ///
    /// This method attempts to parse all configurations and returns successfully
    /// parsed ones while discarding unsupported configurations. Use `parseWithDetails`
    /// to get information about failed configurations.
    ///
    /// - Parameter bytes: The wire format data to parse
    /// - Returns: `nil` if no configurations could be parsed successfully
    public init?(_ bytes: inout Data) {
        let result = Self.parseWithDetails(&bytes)
        guard result.hasValidConfigurations else {
            return nil
        }
        self = result.validConfigurations
    }

    /// Parse configurations with detailed error information for failed configurations.
    ///
    /// This method provides comprehensive information about both successful and failed
    /// configuration parsing attempts, allowing clients to understand which configurations
    /// are supported and why others failed.
    ///
    /// **Wire Format:**
    /// - total_length (2 bytes): Total length of all configurations
    /// - configs (variable): Concatenated Configuration structures
    ///
    /// - Parameter bytes: The wire format data to parse
    /// - Returns: Complete parsing result with valid configurations and error details
    public static func parseWithDetails(_ data: inout Data) -> ODoH.ConfigurationParsingResult {
        // Pop the entire structure from memory. To see if there was any errors structure of the Data first.
        let fullData = data
        guard
            let totalLength = data.popUInt16(),
            var configsData = data.popFirst(Int(totalLength))
        else {
            return ODoH.ConfigurationParsingResult(
                validConfigurations: [],
                failedConfigurations: [(fullData, .invalidODoHData())]
            )
        }

        var validConfigs: ODoH.Configurations = []
        var failedConfigs: [(rawData: Data, error: ObliviousDoHError)] = []

        while !configsData.isEmpty {
            let beforeByteCount = configsData.count
            let originalData = configsData

            let parseResult = ODoH.Configuration.parseWithDetails(&configsData)
            switch parseResult {
            case .success(let config):
                validConfigs.append(config)
            case .failure(let error):
                if error == ObliviousDoHError.invalidODoHData() {
                    break
                }

                let consumedBytes = beforeByteCount - configsData.count
                let failedConfigData = originalData.prefix(consumedBytes)
                failedConfigs.append((Data(failedConfigData), error))
            }
        }

        return ODoH.ConfigurationParsingResult(
            validConfigurations: validConfigs,
            failedConfigurations: failedConfigs
        )
    }

    /// Serialize configurations collection to wire format bytes.
    ///
    /// - Returns: The encoded configurations ready for network transmission
    public func encode() throws -> Data {
        var length = 0
        for config in self {
            length += 4 + config.contents.length
        }

        guard let configsLength = UInt16(exactly: length) else {
            throw ObliviousDoHError.invalidODoHLength(length: length)
        }

        var data = Data()
        data.reserveCapacity(2 + length)
        data.append(bigEndianBytes: configsLength)  // 2 bytes: total length

        for config in self {
            data.append(try config.encode())
        }

        return data
    }

    /// Find the first configuration matching the specified version.
    ///
    /// Searches through the configurations collection and returns the first configuration
    /// that matches the requested version.
    ///
    /// - Parameter version: The version to search for
    /// - Returns: The first matching configuration, or `nil` if no configuration with that version exists
    public func first(version: Int) -> ODoH.Configuration? {
        self.first { $0.version == version }
    }

    /// Find the first configuration matching the specified key identifier.
    ///
    /// Searches through the configurations collection and returns the first configuration
    /// that matches the requested key identifier.
    ///
    /// - Parameter keyID: The key identifier to search for
    /// - Returns: The first matching configuration, or `nil` if no configuration with that key ID exists
    public func first(keyID: Data) -> ODoH.Configuration? {
        self.first { $0.contents.identifier == keyID }
    }
}

extension ODoH.Configuration: ODoH.Codable {
    /// Deserialize complete ODoH configuration from wire format bytes.
    ///
    /// **Wire Format:**
    /// - version (2 bytes): Protocol version (0x0001 for RFC 9230)
    /// - length (2 bytes): Length of contents field
    /// - contents (variable): The configuration contents
    ///
    /// - Parameter bytes: The wire format data to parse
    /// - Returns: `nil` if parsing fails or version is unsupported
    public init?(_ bytes: inout Data) {
        switch Self.parseWithDetails(&bytes) {
        case .success(let config):
            self = config
        case .failure:
            return nil
        }
    }

    /// Parse configuration with detailed error information.
    ///
    /// This method provides comprehensive error information when configuration parsing fails,
    /// allowing callers to understand exactly what went wrong during parsing.
    ///
    /// - Parameter bytes: The wire format data to parse
    /// - Returns: Result containing either a valid configuration or detailed error information
    public static func parseWithDetails(
        _ bytes: inout Data
    ) -> Result<
        ODoH.Configuration, ObliviousDoHError
    > {
        // Pop the entire structure from memory. To see if there was any errors structure of the Data first.
        guard
            let version = bytes.popUInt16(),
            let length = bytes.popUInt16(),
            var contentsBytes = bytes.popFirst(Int(length))  // Pop the entire object
        else {
            return .failure(.invalidODoHData())
        }

        // Check version first before trying to parse contents
        let contentsBacking: ODoH.Configuration.ContentsBacking
        switch Int(version) {
        case 0x0001:
            let contentsResult = ODoH.ConfigurationContents.parseWithDetails(&contentsBytes)
            switch contentsResult {
            case .success(let contents):
                contentsBacking = .v1(contents)
            case .failure(let error):
                return .failure(error)
            }
        default:
            return .failure(.unsupportedHPKEParameters())
        }

        let config = ODoH.Configuration(contentsBacking: contentsBacking)
        return .success(config)
    }

    /// Serialize complete configuration to wire format bytes.
    ///
    /// - Returns: The encoded configuration ready for network transmission
    public func encode() throws -> Data {
        guard let version = UInt16(exactly: self.version) else {
            throw ObliviousDoHError.invalidODoHVersion(version: self.version)
        }

        var data = Data()
        let contentsData = try self.contents.encode()
        data.reserveCapacity(4 + contentsData.count)
        data.append(bigEndianBytes: version)  // 2 bytes: version
        data.append(bigEndianBytes: UInt16(contentsData.count))  // 2 bytes: contents length
        data.append(contentsData)  // Variable: contents
        return data
    }
}

extension ODoH.ConfigurationContents: ODoH.Codable {
    /// Deserialize configuration contents from wire format bytes.
    ///
    /// **Wire Format:**
    /// - kem_id (2 bytes): Key Encapsulation Mechanism identifier
    /// - kdf_id (2 bytes): Key Derivation Function identifier
    /// - aead_id (2 bytes): AEAD algorithm identifier
    /// - public_key_length (2 bytes): Length of public key
    /// - public_key (variable): The public key bytes
    ///
    /// - Parameter bytes: The wire format data to parse
    /// - Returns: `nil` if parsing fails or unsupported algorithms are encountered
    public init?(_ bytes: inout Data) {
        switch Self.parseWithDetails(&bytes) {
        case .success(let contents):
            self = contents
        case .failure:
            return nil
        }
    }

    /// Parse configuration contents with detailed error information.
    ///
    /// This method provides comprehensive error information when configuration contents parsing fails,
    /// allowing callers to understand exactly what went wrong during parsing.
    ///
    /// - Parameter bytes: The wire format data to parse
    /// - Returns: Result containing either valid configuration contents or detailed error information
    public static func parseWithDetails(
        _ bytes: inout Data
    ) -> Result<
        ODoH.ConfigurationContents, ObliviousDoHError
    > {
        // As we have already popped the entirety of the configuration
        // contents we don't have to fail with .invalidODoHData.
        guard
            let kemID = bytes.popUInt16(),
            let kdfID = bytes.popUInt16(),
            let aeadID = bytes.popUInt16(),
            let keyLength = bytes.popUInt16(),
            let key = bytes.popFirst(Int(keyLength)),
            let kem = HPKE.KEM(networkIdentifier: kemID),
            let kdf = HPKE.KDF(networkIdentifier: kdfID),
            let aead = HPKE.AEAD(networkIdentifier: aeadID),
            aead != .exportOnly
        else {
            return .failure(.unsupportedHPKEParameters())
        }

        // Ensure all bytes were consumed
        guard bytes.isEmpty else {
            return .failure(.invalidODoHData())
        }

        // Try to validate the public key by attempting to create a key instance
        do {
            _ = try kem.getPublicKey(data: key)
        } catch {
            return .failure(.invalidPublicKey(kemID: kemID, key: key))
        }

        let contents = ODoH.ConfigurationContents(kem: kem, kdf: kdf, aead: aead, publicKey: key)
        return .success(contents)
    }

    /// Serialize configuration contents to wire format bytes.
    ///
    /// - Returns: The encoded configuration contents ready for network transmission
    public func encode() -> Data {
        var data = Data()
        data.reserveCapacity(8 + self.publicKey.count)
        data.append(self.kem.identifier)  // 2 bytes: KEM ID
        data.append(self.kdf.identifier)  // 2 bytes: KDF ID
        data.append(self.aead.identifier)  // 2 bytes: AEAD ID
        data.append(bigEndianBytes: UInt16(self.publicKey.count))  // 2 bytes: key length
        data.append(self.publicKey)  // Variable: key data
        return data
    }
}

extension ODoH.MessagePlaintext: ODoH.Codable {
    /// Deserialize plaintext message from wire format bytes.
    ///
    /// **Wire Format:**
    /// - dns_message_length (2 bytes): Length of DNS message
    /// - dns_message (variable): The DNS message in wire format
    /// - padding_length (2 bytes): Length of padding
    /// - padding (variable): Zero-filled padding bytes
    ///
    /// - Parameter bytes: The wire format data to parse
    /// - Returns: `nil` if parsing fails or insufficient data
    public init?(_ bytes: inout Data) {
        guard
            let dnsLength = bytes.popUInt16(),
            let dns = bytes.popFirst(Int(dnsLength)),
            let paddingLength = bytes.popUInt16(),
            let padding = bytes.popFirst(Int(paddingLength)),
            // Clients MUST validate R_plain.padding (as all zeros) before using R_plain.dns_message.
            padding.allSatisfy({ $0 == 0 })
        else { return nil }

        self.dnsMessage = dns
        self.paddingLength = Int(paddingLength)
    }

    /// Serialize plaintext message to wire format bytes.
    ///
    /// - Returns: The encoded message ready for encryption
    public func encode() -> Data {
        var data = Data()
        data.reserveCapacity(4 + self.dnsMessage.count + self.paddingLength)
        data.append(bigEndianBytes: UInt16(self.dnsMessage.count))  // 2 bytes: DNS length
        data.append(self.dnsMessage)  // Variable: DNS data
        data.append(bigEndianBytes: UInt16(self.paddingLength))  // 2 bytes: padding length
        data.append(contentsOf: .init(repeating: 0, count: self.paddingLength))
        return data
    }
}

extension ODoH.Message: ODoH.Codable {
    /// Deserialize ODoH message from wire format bytes.
    ///
    /// **Wire Format:**
    /// - message_type (1 byte): 0x01 for query, 0x02 for response
    /// - key_id_length (2 bytes): Length of key ID field
    /// - key_id (variable): Key identifier (queries) or nonce (responses)
    /// - encrypted_message_length (2 bytes): Length of encrypted content
    /// - encrypted_message (variable): The encrypted payload
    ///
    /// - Parameter bytes: The wire format data to parse
    /// - Returns: `nil` if parsing fails or invalid message type
    public init?(_ bytes: inout Data) {
        guard
            let typeRaw = bytes.popUInt8(),
            let keyIDLength = bytes.popUInt16(),
            let keyID = bytes.popFirst(Int(keyIDLength)),
            let encryptedLength = bytes.popUInt16(),
            let encrypted = bytes.popFirst(Int(encryptedLength))
        else { return nil }

        self.messageType = MessageType(rawValue: typeRaw)
        self.keyID = keyID
        self.encryptedMessage = encrypted
    }

    /// Serialize ODoH message to wire format bytes.
    ///
    /// - Returns: The encoded message ready for network transmission
    public func encode() -> Data {
        var data = Data()
        data.reserveCapacity(5 + self.keyID.count + self.encryptedMessage.count)
        data.append(self.messageType.rawValue)  // 1 byte: message type
        data.append(bigEndianBytes: UInt16(self.keyID.count))  // 2 bytes: key ID length
        data.append(self.keyID)  // Variable: key ID/nonce
        data.append(bigEndianBytes: UInt16(self.encryptedMessage.count))  // 2 bytes: encrypted length
        data.append(self.encryptedMessage)  // Variable: encrypted data
        return data
    }
}

/// Context strings used in HPKE key derivation for different purposes in ODoH protocol.
/// These strings provide domain separation to ensure keys derived for different purposes
/// are cryptographically independent, as required by RFC 9230 Section 6.2.

/// Used to derive the key identifier from the target's public key configuration
private let ODoHKeyIDInfo = Data("odoh key id".utf8)

/// Used as HPKE info parameter when setting up encryption context for DNS queries
private let ODoHQueryInfo = Data("odoh query".utf8)

/// Used when exporting secrets from HPKE context for response encryption
private let ODoHResponseInfo = Data("odoh response".utf8)

/// Used to derive the AEAD key for encrypting/decrypting DNS responses
private let ODoHKeyInfo = Data("odoh key".utf8)

/// Used to derive the AEAD nonce for encrypting/decrypting DNS responses
private let ODoHNonceInfo = Data("odoh nonce".utf8)