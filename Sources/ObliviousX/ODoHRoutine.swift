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

/// Protocol for types that can be serialized to and from ODoH wire format.
///
/// Provides bidirectional conversion between Swift types and their network representation
/// as specified in RFC 9230. All ODoH message types implement this protocol to enable
/// consistent serialization and parsing across the protocol stack.
private protocol ODoHCodable {
    /// Initialize from wire format bytes, consuming data as it parses
    /// - Parameter bytes: The raw network data to parse (consumed during parsing)
    /// - Returns: `nil` if parsing fails or data is invalid
    init?(_ bytes: inout Data)

    /// Serialize to wire format bytes
    /// - Returns: The encoded data ready for network transmission
    func encode() -> Data
}

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

        /// Encrypt DNS query using HPKE for transmission through proxy.
        ///
        /// Returns encrypted message and sender context needed for response decryption.
        ///
        /// - Parameter queryPlain: DNS query with padding
        /// - Returns: Encrypted query data and HPKE sender context
        /// - Precondition: Encrypted message size (plaintext + AEAD tag)
        ///     must not exceed 65535 bytes due to wire format limitation
        public func encryptQuery(
            queryPlain: MessagePlaintext
        ) throws -> (
            encryptedQuery: Data, context: HPKE.Sender
        ) {
            var context = try HPKE.Sender(
                recipientKey: self.pkR,
                ciphersuite: self.ct,
                info: ODoHQueryInfo
            )

            let sealedData = try context.seal(
                queryPlain.encode(),
                authenticating: self.aad(.query, key: self.keyID)
            )
            let encapsulatedKey = context.encapsulatedKey

            var encryptedMessage = Data()
            encryptedMessage.append(encapsulatedKey)
            encryptedMessage.append(sealedData)

            precondition(
                encryptedMessage.count <= UInt16.max,
                """
                Encrypted message size (encapsulatedKey + plaintext + AEAD tag) must not exceed 65535 bytes.
                This limit is imposed by the ODoH wire format which uses UInt16 length fields
                for the encrypted_message field in the Message structure.
                """
            )

            let message = Message(
                messageType: .query,
                keyID: self.keyID,
                encryptedMessage: encryptedMessage
            )

            return (message.encode(), context)
        }

        /// Decrypt DNS response using HPKE context and derived keys.
        ///
        /// Uses HPKE secret export and HKDF to derive response decryption keys.
        ///
        /// - Parameters:
        ///   - context: HPKE sender context from query encryption
        ///   - queryPlain: Original query plaintext (used in key derivation)
        ///   - responseData: Encrypted response from server
        /// - Returns: Decrypted DNS response
        public func decryptResponse(
            context: HPKE.Sender,
            queryPlain: MessagePlaintext,
            responseData: Data
        ) throws -> MessagePlaintext {
            // Parse the response message
            var responseData = responseData
            guard let response = Message(&responseData) else {
                throw ObliviousXError.invalidODoHData()
            }

            return try decryptResponse(context: context, queryPlain: queryPlain, response: response)
        }

        /// Decrypt DNS response using HPKE context and derived keys.
        ///
        /// Uses HPKE secret export and HKDF to derive response decryption keys.
        ///
        /// - Parameters:
        ///   - context: HPKE sender context from query encryption
        ///   - queryPlain: Original query plaintext (used in key derivation)
        ///   - response: Encrypted response from server (in Message format)
        /// - Returns: Decrypted DNS response
        public func decryptResponse(
            context: HPKE.Sender,
            queryPlain: MessagePlaintext,
            response: Message
        ) throws -> MessagePlaintext {
            guard response.messageType == .response else {
                throw ObliviousXError.invalidMessageType(
                    expected: Message.MessageType.response.rawValue,
                    actual: response.messageType.rawValue
                )
            }

            let responseNonce = response.keyID  // For responses, keyID field contains the nonce
            let responseEncrypted = response.encryptedMessage

            // Derive secrets according to RFC
            let (aeadKey, aeadNonce) = try deriveSecrets(
                secret: context.exportSecret(
                    context: ODoHResponseInfo,
                    outputByteCount: self.ct.aead.keyByteCount
                ),
                queryPlain: queryPlain.encode(),
                responseNonce: responseNonce
            )

            // Build AAD for response
            let aad = self.aad(.response, key: responseNonce)

            // Decrypt using derived key/nonce (regular AEAD, not HPKE)
            var plaintext = try self.ct.aead.open(
                responseEncrypted,
                nonce: aeadNonce,
                authenticating: aad,
                using: aeadKey
            )

            guard let messagePlaintext = MessagePlaintext(&plaintext) else {
                throw ObliviousXError.invalidODoHData()
            }
            return messagePlaintext
        }

        /// Decrypt DNS query using server's private key.
        ///
        /// Establishes HPKE recipient context needed for response encryption.
        ///
        /// - Parameters:
        ///   - queryData: Encrypted query from proxy
        ///   - privateKey: Server's private key
        /// - Returns: Decrypted query and HPKE recipient context
        public func decryptQuery<PrivateKey: HPKEDiffieHellmanPrivateKey>(
            queryData: Data,
            privateKey: PrivateKey
        ) throws -> (plaintext: MessagePlaintext, context: HPKE.Recipient) {
            // Parse the query message
            var queryData = queryData
            guard let query = Message(&queryData) else {
                throw ObliviousXError.invalidODoHData()
            }

            return try decryptQuery(query: query, privateKey: privateKey)
        }

        /// Decrypt DNS query using server's private key.
        ///
        /// Establishes HPKE recipient context needed for response encryption.
        ///
        /// - Parameters:
        ///   - query: Encrypted query from proxy
        ///   - privateKey: Server's private key
        /// - Returns: Decrypted query and HPKE recipient context
        public func decryptQuery<PrivateKey: HPKEDiffieHellmanPrivateKey>(
            query: Message,
            privateKey: PrivateKey
        ) throws -> (plaintext: MessagePlaintext, context: HPKE.Recipient) {
            guard query.messageType == .query else {
                throw ObliviousXError.invalidMessageType(
                    expected: Message.MessageType.query.rawValue,
                    actual: query.messageType.rawValue
                )
            }

            var ciphertext = query.encryptedMessage
            guard let enc = ciphertext.popFirst(self.ct.kem.encapsulatedKeySize) else {
                throw CryptoKitError.incorrectParameterSize
            }

            // Setup HPKE recipient context
            var context = try HPKE.Recipient(
                privateKey: privateKey,
                ciphersuite: self.ct,
                info: ODoHQueryInfo,
                encapsulatedKey: enc
            )

            // Decrypt query
            var plaintext = try context.open(
                ciphertext,
                authenticating: self.aad(.query, key: self.keyID)
            )

            guard let messagePlaintext = MessagePlaintext(&plaintext) else {
                throw ObliviousXError.invalidODoHData()
            }
            return (messagePlaintext, context)
        }

        /// Encrypt DNS response using derived keys from HPKE context.
        ///
        /// Uses HPKE secret export and random nonce for stateless operation.
        ///
        /// - Parameters:
        ///   - recepient: HPKE recipient context from query decryption
        ///   - queryPlain: Original query (used in key derivation)
        ///   - responsePlain: DNS response to encrypt
        /// - Returns: Encrypted response message
        public func encryptResponse(
            recepient: HPKE.Recipient,
            queryPlain: MessagePlaintext,
            responsePlain: MessagePlaintext
        ) throws -> Data {
            // Generate response nonce: random(max(Nn, Nk))
            let nonceSize = self.ct.aead.nonceByteCount
            let keySize = self.ct.aead.keyByteCount
            let responseNonceSize = max(nonceSize, keySize)
            let responseNonce = Data((0..<responseNonceSize).map { _ in UInt8.random(in: 0...255) })

            // Derive secrets
            let (aeadKey, aeadNonce) = try deriveSecrets(
                secret: recepient.exportSecret(
                    context: ODoHResponseInfo,
                    outputByteCount: self.ct.aead.keyByteCount
                ),
                queryPlain: queryPlain.encode(),
                responseNonce: responseNonce
            )

            // Encrypt response using derived keys (regular AEAD)
            let encrypted = try self.ct.aead.seal(
                responsePlain.encode(),
                authenticating: self.aad(.response, key: responseNonce),
                nonce: aeadNonce,
                using: aeadKey
            )

            precondition(
                encrypted.count <= UInt16.max,
                """
                Encrypted message size (encapsulatedKey + plaintext + AEAD tag) must not exceed 65535 bytes.
                This limit is imposed by the ODoH wire format which uses UInt16 length fields
                for the encrypted_message field in the Message structure.
                """
            )

            // Build response message (reusing Message structure, keyID holds nonce for responses)
            let message = Message(
                messageType: .response,
                keyID: responseNonce,
                encryptedMessage: encrypted
            )

            return message.encode()
        }

        /// Derive AEAD key and nonce for response encryption.
        ///
        /// Uses HKDF Extract-and-Expand with query plaintext and response nonce as salt.
        /// Formula: Extract(Q_plain || len(nonce) || nonce, secret) → Expand for key/nonce.
        ///
        /// - Parameters:
        ///   - secret: Exported secret from HPKE context
        ///   - queryPlain: Original query plaintext
        ///   - responseNonce: Server-generated nonce
        /// - Returns: Derived AEAD key and nonce
        private func deriveSecrets(
            secret: SymmetricKey,
            queryPlain: Data,
            responseNonce: Data
        ) throws -> (key: SymmetricKey, nonce: Data) {
            // Build salt: Q_plain || len(resp_nonce) || resp_nonce
            var salt = Data()
            salt.append(queryPlain)
            salt.append(bigEndianBytes: UInt16(responseNonce.count))
            salt.append(responseNonce)

            // Extract PRK
            let prk = self.ct.kdf.extract(salt: salt, ikm: secret)

            // Expand to get key and nonce
            let key = self.ct.kdf.expand(
                prk: prk,
                info: ODoHKeyInfo,
                outputByteCount: self.ct.aead.keyByteCount
            )
            let nonce = self.ct.kdf.expand(
                prk: prk,
                info: ODoHNonceInfo,
                outputByteCount: self.ct.aead.nonceByteCount
            )

            return (key, Data(nonce))
        }

        /// Construct Additional Authenticated Data (AAD) for AEAD operations.
        ///
        /// Format: message_type (1 byte) || key_length (2 bytes) || key_data
        ///
        /// - Parameters:
        ///   - type: Message type (query or response)
        ///   - key: Key identifier or response nonce
        /// - Returns: AAD bytes for AEAD operations
        private func aad(_ type: Message.MessageType, key: Data) -> Data {
            var aad = Data([type.rawValue])
            let keyLength = UInt16(key.count)
            aad.append(bigEndianBytes: keyLength)
            aad.append(key)
            return aad
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

// MARK: - ODoHCodable Implementations

extension ODoH.Configurations: ODoHCodable {
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
    public static func parseWithDetails(_ bytes: inout Data) -> ODoH.ConfigurationParsingResult {
        // Pop the entire structure from memory. To see if there was any errors structure of the Data first.
        guard
            let totalLength = bytes.popUInt16(),
            var configsData = bytes.popFirst(Int(totalLength))
        else {
            return ODoH.ConfigurationParsingResult(
                validConfigurations: [],
                failedConfigurations: [(bytes, .invalidODoHData())]
            )
        }

        var validConfigs: ODoH.Configurations = []
        var failedConfigs: [(rawData: Data, error: ObliviousXError)] = []

        while !configsData.isEmpty {
            let beforeByteCount = configsData.count
            let originalData = configsData

            let parseResult = ODoH.Configuration.parseWithDetails(&configsData)
            switch parseResult {
            case .success(let config):
                validConfigs.append(config)
            case .failure(let error):
                if error == ObliviousXError.invalidODoHData() {
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
    public func encode() -> Data {
        var configsData = Data()
        for config in self {
            configsData.append(config.encode())
        }

        var data = Data()
        data.append(bigEndianBytes: UInt16(configsData.count))  // 2 bytes: total length
        data.append(configsData)  // Variable: concatenated configs
        return data
    }

    /// Find the first configuration matching the specified version.
    ///
    /// Searches through the configurations collection and returns the first configuration
    /// that matches the requested version. This is useful for version negotiation where
    /// clients need to find a compatible configuration version.
    ///
    /// - Parameter version: The version to search for
    /// - Returns: The first matching configuration, or `nil` if no configuration with that version exists
    public func first(version: UInt16) -> ODoH.Configuration? {
        self.first { $0.version == version }
    }

    /// Find the first configuration matching the specified key identifier.
    ///
    /// Searches through the configurations collection and returns the first configuration
    /// that matches the requested key identifier. This is useful for selecting a specific
    /// configuration when the client knows which key should be used for encryption.
    ///
    /// - Parameter keyID: The key identifier to search for
    /// - Returns: The first matching configuration, or `nil` if no configuration with that key ID exists
    public func first(keyID: Data) -> ODoH.Configuration? {
        self.first { $0.contents.identifier == keyID }
    }
}

extension ODoH.Configuration: ODoHCodable {
    /// Deserialize complete ODoH configuration from wire format bytes.
    ///
    /// **Wire Format:**
    /// - version (2 bytes): Protocol version (0x0001 for RFC 9230)
    /// - length (2 bytes): Length of contents field
    /// - contents (variable): The configuration contents
    ///
    /// - Parameter bytes: The wire format data to parse
    /// - Returns: `nil` if parsing fails or version is unsupported
    internal init?(_ bytes: inout Data) {
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
    internal static func parseWithDetails(
        _ bytes: inout Data
    ) -> Result<
        ODoH.Configuration, ObliviousXError
    > {
        // Pop the entire structure from memory. To see if there was any errors structure of the Data first.
        guard
            let version = bytes.popUInt16(),
            let length = bytes.popUInt16(),
            var contentsBytes = bytes.popFirst(Int(length))  // Pop the entire object
        else {
            return .failure(.invalidODoHData())
        }

        let contentsResult = ODoH.ConfigurationContents.parseWithDetails(&contentsBytes)
        switch contentsResult {
        case .success(let contents):
            let config = ODoH.Configuration(version: version, contents: contents)
            return .success(config)
        case .failure(let error):
            return .failure(error)
        }
    }

    /// Serialize complete configuration to wire format bytes.
    ///
    /// - Returns: The encoded configuration ready for network transmission
    internal func encode() -> Data {
        var data = Data()
        let contentsData = self.contents.encode()
        data.append(bigEndianBytes: self.version)  // 2 bytes: version
        data.append(bigEndianBytes: UInt16(contentsData.count))  // 2 bytes: contents length
        data.append(contentsData)  // Variable: contents
        return data
    }
}

extension ODoH.ConfigurationContents: ODoHCodable {
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
    internal init?(_ bytes: inout Data) {
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
    internal static func parseWithDetails(
        _ bytes: inout Data
    ) -> Result<
        ODoH.ConfigurationContents, ObliviousXError
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
    internal func encode() -> Data {
        var data = Data()
        data.append(self.kem.identifier)  // 2 bytes: KEM ID
        data.append(self.kdf.identifier)  // 2 bytes: KDF ID
        data.append(self.aead.identifier)  // 2 bytes: AEAD ID
        data.append(bigEndianBytes: UInt16(self.publicKey.count))  // 2 bytes: key length
        data.append(self.publicKey)  // Variable: key data
        return data
    }
}

extension ODoH.MessagePlaintext: ODoHCodable {
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
    internal init?(_ bytes: inout Data) {
        guard
            let dnsLength = bytes.popUInt16(),
            let dns = bytes.popFirst(Int(dnsLength)),
            let paddingLength = bytes.popUInt16(),
            let padding = bytes.popFirst(Int(paddingLength)),
            // Clients MUST validate R_plain.padding (as all zeros) before using R_plain.dns_message.
            padding.allSatisfy({ $0 == 0 })
        else { return nil }

        self.dnsMessage = dns
        self.padding = Array(padding)
    }

    /// Serialize plaintext message to wire format bytes.
    ///
    /// - Returns: The encoded message ready for encryption
    internal func encode() -> Data {
        var data = Data()
        data.append(bigEndianBytes: UInt16(self.dnsMessage.count))  // 2 bytes: DNS length
        data.append(self.dnsMessage)  // Variable: DNS data
        data.append(bigEndianBytes: UInt16(self.padding.count))  // 2 bytes: padding length
        data.append(contentsOf: self.padding)  // Variable: padding
        return data
    }
}

extension ODoH.Message: ODoHCodable {
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
            let type = MessageType(rawValue: typeRaw),
            let keyIDLength = bytes.popUInt16(),
            let keyID = bytes.popFirst(Int(keyIDLength)),
            let encryptedLength = bytes.popUInt16(),
            let encrypted = bytes.popFirst(Int(encryptedLength))
        else { return nil }

        self.messageType = type
        self.keyID = keyID
        self.encryptedMessage = encrypted
    }

    /// Serialize ODoH message to wire format bytes.
    ///
    /// - Returns: The encoded message ready for network transmission
    public func encode() -> Data {
        var data = Data()
        data.append(self.messageType.rawValue)  // 1 byte: message type
        data.append(bigEndianBytes: UInt16(self.keyID.count))  // 2 bytes: key ID length
        data.append(self.keyID)  // Variable: key ID/nonce
        data.append(bigEndianBytes: UInt16(self.encryptedMessage.count))  // 2 bytes: encrypted length
        data.append(self.encryptedMessage)  // Variable: encrypted data
        return data
    }
}

extension HPKE.KEM {
    /// Create a public key instance from raw bytes for the specified KEM algorithm.
    ///
    /// This method handles the different public key formats used by various elliptic curves:
    /// - **P-256, P-384, P-521**: Uncompressed point format (0x04 prefix + coordinates)
    /// - **X25519**: Raw coordinate bytes (32 bytes)
    ///
    /// - Parameter data: The raw public key bytes in the appropriate format for this KEM
    /// - Returns: A public key instance implementing `HPKEDiffieHellmanPublicKey`
    /// - Throws: `CryptoKitError` if the key data is invalid for the chosen curve
    internal func getPublicKey(data: Data) throws -> any HPKEDiffieHellmanPublicKey {
        switch self {
        case .P256_HKDF_SHA256:
            return try P256.KeyAgreement.PublicKey(rawRepresentation: data)
        case .P384_HKDF_SHA384:
            return try P384.KeyAgreement.PublicKey(rawRepresentation: data)
        case .P521_HKDF_SHA512:
            return try P521.KeyAgreement.PublicKey(rawRepresentation: data)
        case .Curve25519_HKDF_SHA256:
            return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data)
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported KEM")
        #endif
        }
    }
}

extension HPKE.KDF {
    /// Get the hash output length in bytes for this KDF.
    ///
    /// These values correspond to the output lengths of the underlying hash functions:
    /// - **SHA-256**: 32 bytes (256 bits)
    /// - **SHA-384**: 48 bytes (384 bits)
    /// - **SHA-512**: 64 bytes (512 bits)
    ///
    /// Used for key identifier derivation and other protocol operations requiring hash length.
    var hashByteCount: Int {
        switch self {
        case .HKDF_SHA256:
            return 32
        case .HKDF_SHA384:
            return 48
        case .HKDF_SHA512:
            return 64
        @unknown default:
            fatalError("Unsupported KDF")
        }
    }
}
