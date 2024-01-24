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

/// Functionality to add oblivious HTTP style encapsulation to data messages.
@available(macOS 14, iOS 17, *)
public enum OHTTPEncapsulation {
    /// Encapsulate a request messge.
    /// - Parameters:
    ///   - keyID: Key Id to send.
    ///   - publicKey: Public key for the recipient.
    ///   - ciphersuite: Details of encryption to use.
    ///   - mediaType: Media type of the request.
    ///   - content: The request message itself.
    /// - Returns: Pair of encapsualted message including headers and sender for additional message encryption.
    public static func encapsulateRequest<
        PublicKey: HPKEDiffieHellmanPublicKey,
        Message: DataProtocol
    >(
        keyID: UInt8,
        publicKey: PublicKey,
        ciphersuite: HPKE.Ciphersuite,
        mediaType: String,
        content: Message
    ) throws -> (Data, HPKE.Sender) {
        var streamer = try StreamingRequest(
            keyID: keyID,
            publicKey: publicKey,
            ciphersuite: ciphersuite,
            mediaType: mediaType
        )
        var payload = streamer.header
        try payload.append(streamer.encapsulate(content: content, final: false))
        return (payload, streamer.sender)
    }

    /// Stream a request in multiple chunks.
    public struct StreamingRequest {
        /// Bytes representation of header.
        public let header: Data
        /// Sender used to seal messages.
        public private(set) var sender: HPKE.Sender

        /// Initialise
        /// - Parameters:
        ///   - keyID: Key Id specified.
        ///   - publicKey: Recepients public key
        ///   - ciphersuite: Details of encryption to use.
        ///   - mediaType: Media type of the request.
        public init<PublicKey: HPKEDiffieHellmanPublicKey>(
            keyID: UInt8,
            publicKey: PublicKey,
            ciphersuite: HPKE.Ciphersuite,
            mediaType: String
        ) throws {
            var header = OHTTPEncapsulation.buildHeader(keyID: keyID, ciphersuite: ciphersuite)
            self.sender = try HPKE.Sender(
                recipientKey: publicKey,
                ciphersuite: ciphersuite,
                info: OHTTPEncapsulation.buildInfo(header: header, mediaType: mediaType)
            )
            header.append(self.sender.encapsulatedKey)
            self.header = header
        }

        /// Encapsulate a message chunk
        /// - Parameters:
        ///   - content: The message chunk to encapsulate.
        ///   - final: Is this the last chunk.
        ///   - includeEncapsulationWrapper: Must currently be false.
        /// - Returns: The sealed message chunk.
        public mutating func encapsulate<Message: DataProtocol>(
            content: Message,
            final: Bool,
            includeEncapsulationWrapper: Bool = false
        ) throws -> Data {
            // Right now we can't add the encapsulation wrapper because it is broken in the draft spec.
            precondition(includeEncapsulationWrapper == false)
            return try self.sender.seal(content, authenticating: final ? finalAAD : Data())
        }
    }

    /// Parse the encapsulated request header from the start of an encapsulated request into structured types.
    /// - Parameter encapsulatedRequest: At least enough of the encapsulated request to include the header.
    /// - Returns: A pair of RequestHeader structure and the number of consumed bytes.
    public static func parseRequestHeader<Bytes: RandomAccessCollection>(
        encapsulatedRequest: Bytes
    )
        -> (RequestHeader, Int)? where Bytes.Element == UInt8
    {
        guard encapsulatedRequest.count >= 7 else {
            return nil
        }

        let header = encapsulatedRequest.prefix(7)
        var bytes = encapsulatedRequest[...]
        guard let keyID = bytes.popUInt8(),
            let kem = bytes.popUInt16().flatMap({ HPKE.KEM(networkIdentifier: $0) }),
            let kdf = bytes.popUInt16().flatMap({ HPKE.KDF(networkIdentifier: $0) }),
            let aead = bytes.popUInt16().flatMap({ HPKE.AEAD(networkIdentifier: $0) }),
            let encapsulatedKey = bytes.popFirst(kem.encapsulatedKeySize)
        else {
            return nil
        }

        let decapsulator = RequestHeader(
            keyID: keyID,
            kem: kem,
            kdf: kdf,
            aead: aead,
            headerBytes: Data(header),
            encapsulatedKey: Data(encapsulatedKey)
        )
        return (decapsulator, 7 + kem.encapsulatedKeySize)
    }

    /// Encapsulated request header.
    public struct RequestHeader {
        /// Key Id specified.
        public private(set) var keyID: UInt8

        /// Key encapsulation mechanism
        public private(set) var kem: HPKE.KEM

        /// Key derivation function.
        public private(set) var kdf: HPKE.KDF

        /// The authenticated encryption with associated data (AEAD) algorithms to use.
        public private(set) var aead: HPKE.AEAD

        /// Bytes representation of header fields (not key)
        public private(set) var headerBytes: Data

        /// Bytes representation of the encapsulated key.
        public private(set) var encapsulatedKey: Data
    }

    /// Functionality to remove oblivious encapsulation from a series of request chunks.
    public struct StreamingRequestDecapsulator {
        /// The request header.
        public private(set) var header: RequestHeader

        /// Message recipient.
        public private(set) var recipient: HPKE.Recipient

        /// Initialise, preparing to remove oblivious encapsulation.
        /// - Parameters:
        ///   - requestHeader: Header of this request.
        ///   - mediaType: Media type specified for request.
        ///   - privateKey: Private key for removing encryption.
        public init<PrivateKey: HPKEDiffieHellmanPrivateKey>(
            requestHeader: RequestHeader,
            mediaType: String,
            privateKey: PrivateKey
        ) throws {
            self.header = requestHeader
            let info = OHTTPEncapsulation.buildInfo(header: self.header.headerBytes, mediaType: mediaType)
            self.recipient = try HPKE.Recipient(
                privateKey: privateKey,
                ciphersuite: HPKE.Ciphersuite(
                    kem: self.header.kem,
                    kdf: self.header.kdf,
                    aead: self.header.aead
                ),
                info: info,
                encapsulatedKey: self.header.encapsulatedKey
            )
        }

        /// Remove encapsulation from a message
        /// - Parameters:
        ///   - content: The message chunk to remove encapsulation from.
        ///   - final: Is this the final chunk.
        ///   - includeEncapsulationWrapper: Currently must be false.
        /// - Returns: Decrypted content.
        public mutating func decapsulate<Message: DataProtocol>(
            content: Message,
            final: Bool,
            includeEncapsulationWrapper: Bool = false
        ) throws -> Data {
            // Right now we can't add the encapsulation wrapper because it is broken in the draft spec.
            precondition(includeEncapsulationWrapper == false)

            return try self.recipient.open(content, authenticating: final ? finalAAD : Data())
        }
    }

    /// Add oblivious encapsulation to a response message.
    /// - Parameters:
    ///   - context: The recipient for this message.
    ///   - encapsulatedKey: Encapsulated key from messge header.
    ///   - mediaType: Media type for the content.
    ///   - ciphersuite: Details of encryption to use.
    ///   - content: Message content.
    /// - Returns: The encapsulated content
    public static func encapsulateResponse<
        Message: DataProtocol,
        EncapsulatedKey: RandomAccessCollection
    >(
        context: HPKE.Recipient,
        encapsulatedKey: EncapsulatedKey,
        mediaType: String,
        ciphersuite: HPKE.Ciphersuite,
        content: Message
    ) throws -> Data where EncapsulatedKey.Element == UInt8 {
        var streamingResponse = try StreamingResponse(
            context: context,
            encapsulatedKey: encapsulatedKey,
            mediaType: mediaType,
            ciphersuite: ciphersuite
        )
        return try streamingResponse.encapsulate(content, final: false)
    }

    /// Remove encapsulation from a response message.
    /// - Parameters:
    ///   - responsePayload: The payload to decrypt
    ///   - mediaType: Payload media type
    ///   - context: The sender of this payload
    ///   - ciphersuite: Details of encryption used.
    /// - Returns: Decrypted payload.
    public static func decapsulateResponse<ResponsePayload: DataProtocol>(
        responsePayload: ResponsePayload,
        mediaType: String,
        context: HPKE.Sender,
        ciphersuite: HPKE.Ciphersuite
    ) throws -> Data {
        var streamingDecapsulator = StreamingResponseDecapsulator(
            mediaType: mediaType,
            context: context,
            ciphersuite: ciphersuite
        )

        // Currently this cannot return nil, as it does no internal buffering.
        return try streamingDecapsulator.decapsulate(responsePayload, final: false)!
    }

    /// Removes oblivious encapsulation from a request message.
    public struct RequestDecapsulator<Bytes: RandomAccessCollection & DataProtocol>
    where Bytes.Element == UInt8, Bytes.SubSequence == Bytes {
        /// The header for this request.
        public private(set) var header: RequestHeader

        /// The encapsulated request.
        public private(set) var message: Bytes

        /// Initialise a new request decapsulator
        /// - Parameters:
        ///   - requestHeader: The header for the request.
        ///   - message: The request itself
        public init(requestHeader: RequestHeader, message: Bytes) {
            self.header = requestHeader
            self.message = message
        }

        /// Remove oblivious encapsulation
        /// - Parameters:
        ///   - mediaType: Media type that was specified when encapsulating
        ///   - privateKey: Private key for removing encryption.
        /// - Returns: Decrypted message data and recipient details.
        public func decapsulate<PrivateKey: HPKEDiffieHellmanPrivateKey>(
            mediaType: String,
            privateKey: PrivateKey
        ) throws -> (Data, HPKE.Recipient) {
            var decapsulator = try StreamingRequestDecapsulator(
                requestHeader: self.header,
                mediaType: mediaType,
                privateKey: privateKey
            )
            let decrypted = try decapsulator.decapsulate(content: self.message, final: false)
            return (decrypted, decapsulator.recipient)
        }
    }

    /// Processor for a series of response chunks.
    public struct StreamingResponse {
        private let responseNonce: Data

        private var aeadNonce: Data

        private let aeadKey: SymmetricKey

        private let aead: HPKE.AEAD

        private var counter: UInt64

        /// Initialiser.
        /// - Parameters:
        ///   - context: The message recipient.
        ///   - encapsulatedKey:  Encapsulated key for cypher
        ///   - mediaType: Media type
        ///   - ciphersuite: Details of encryption to use.
        public init<EncapsulatedKey: RandomAccessCollection>(
            context: HPKE.Recipient,
            encapsulatedKey: EncapsulatedKey,
            mediaType: String,
            ciphersuite: HPKE.Ciphersuite
        ) throws where EncapsulatedKey.Element == UInt8 {
            let secret = try context.exportSecret(
                context: Array(mediaType.utf8),
                outputByteCount: ciphersuite.aead.keyByteCount
            )
            let nonceLength = max(ciphersuite.aead.keyByteCount, ciphersuite.aead.nonceByteCount)
            var responseNonce = Data(repeating: 0, count: nonceLength)
            responseNonce.withUnsafeMutableBytes { $0.initializeWithRandomBytes(count: nonceLength) }

            self.responseNonce = responseNonce

            var salt = Data(encapsulatedKey)
            salt.append(contentsOf: responseNonce)

            let prk = ciphersuite.kdf.extract(salt: salt, ikm: secret)
            self.aeadKey = ciphersuite.kdf.expand(
                prk: prk,
                info: Data("key".utf8),
                outputByteCount: ciphersuite.aead.keyByteCount
            )
            self.aeadNonce = Data(
                ciphersuite.kdf.expand(
                    prk: prk,
                    info: Data("nonce".utf8),
                    outputByteCount: ciphersuite.aead.nonceByteCount
                )
            )
            self.aead = ciphersuite.aead
            self.counter = 0
        }

        /// Encapsulate a message chunk
        /// - Parameters:
        ///   - message: The message chunk to encapsulate.
        ///   - final: Is this the final message chunk.
        ///   - includeEncapsulationWrapper: Must currently be false
        /// - Returns: The encapsulated message chunk.
        public mutating func encapsulate<Message: DataProtocol>(
            _ message: Message,
            final: Bool,
            includeEncapsulationWrapper: Bool = false
        ) throws -> Data {
            // Right now we can't add the encapsulation wrapper because it is broken in the draft spec.
            precondition(includeEncapsulationWrapper == false)

            // We temporarily mutate the AEAD nonce. To avoid intermediate allocations, we mutate in place and
            // return it back by xoring again.
            let counter = self.counter
            self.aeadNonce.xor(with: counter)
            defer {
                self.aeadNonce.xor(with: counter)
            }

            let ct = try self.aead.seal(
                message,
                authenticating: final ? finalAAD : Data(),
                nonce: self.aeadNonce,
                using: self.aeadKey
            )

            // This defer is here to avoid us doing it if we throw above.
            defer {
                self.counter += 1
            }

            guard counter == 0 else {
                return ct
            }
            return self.responseNonce + ct
        }
    }

    /// Decapsulator which can process a response as a series of chunks.
    public struct StreamingResponseDecapsulator {
        enum State {
            case awaitingResponseNonce(
                mediaType: String,
                context: HPKE.Sender,
                ciphersuite: HPKE.Ciphersuite
            )
            case responseNonceGenerated(
                aeadNonce: Data,
                aeadKey: SymmetricKey,
                aead: HPKE.AEAD,
                counter: UInt64
            )
        }

        private var state: State

        /// initialiser.
        /// - Parameters:
        ///   - mediaType: Media type of the response.
        ///   - context: The sender of the response.
        ///   - ciphersuite: Details of encryption used.
        public init(mediaType: String, context: HPKE.Sender, ciphersuite: HPKE.Ciphersuite) {
            self.state = .awaitingResponseNonce(
                mediaType: mediaType,
                context: context,
                ciphersuite: ciphersuite
            )
        }

        /// Decapsulate a message chunk
        /// - Parameters:
        ///   - message: The message chunk.
        ///   - final: Is this the final chunk of the sequence?
        ///   - expectEncapsulationWrapper: Must currently be false.
        /// - Returns: The decrypted payload data for this chunk.
        public mutating func decapsulate<Message: DataProtocol>(
            _ message: Message,
            final: Bool,
            expectEncapsulationWrapper: Bool = false
        ) throws -> Data? {
            // Right now we can't process the encapsulation wrapper because it is broken in the draft spec.
            precondition(expectEncapsulationWrapper == false)

            var aeadNonce: Data
            let aeadKey: SymmetricKey
            let aead: HPKE.AEAD
            let counter: UInt64
            let ciphertext: Message.SubSequence

            switch self.state {
            case .awaitingResponseNonce(let mediaType, let context, let ciphersuite):
                var payload = message[...]
                let nonceLength = max(ciphersuite.aead.keyByteCount, ciphersuite.aead.nonceByteCount)
                guard let responseNonce = payload.popFirst(nonceLength) else {
                    throw CryptoKitError.incorrectParameterSize
                }

                let secret = try context.exportSecret(
                    context: Array(mediaType.utf8),
                    outputByteCount: ciphersuite.aead.keyByteCount
                )

                var salt = Data(context.encapsulatedKey)
                salt.append(contentsOf: responseNonce)

                let prk = ciphersuite.kdf.extract(salt: salt, ikm: secret)
                aeadKey = ciphersuite.kdf.expand(
                    prk: prk,
                    info: Data("key".utf8),
                    outputByteCount: ciphersuite.aead.keyByteCount
                )
                aeadNonce = Data(
                    ciphersuite.kdf.expand(
                        prk: prk,
                        info: Data("nonce".utf8),
                        outputByteCount: ciphersuite.aead.nonceByteCount
                    )
                )
                aead = ciphersuite.aead
                counter = 0
                ciphertext = payload

                // Save the state. Counter is at 1 for the next run.
                self.state = .responseNonceGenerated(
                    aeadNonce: aeadNonce,
                    aeadKey: aeadKey,
                    aead: aead,
                    counter: 1
                )
            case .responseNonceGenerated(
                aeadNonce: let nonce,
                aeadKey: let key,
                aead: let cipher,
                counter: let c
            ):
                aeadNonce = nonce
                aeadKey = key
                aead = cipher
                counter = c
                ciphertext = message[...]

                self.state = .responseNonceGenerated(
                    aeadNonce: nonce,
                    aeadKey: key,
                    aead: cipher,
                    counter: c + 1
                )
            }

            aeadNonce.xor(with: counter)
            return try aead.open(
                ciphertext,
                nonce: aeadNonce,
                authenticating: final ? finalAAD : Data(),
                using: aeadKey
            )
        }
    }

    static func buildHeader(keyID: UInt8, ciphersuite: HPKE.Ciphersuite) -> Data {
        var d = Data()
        d.reserveCapacity(7)
        d.append(keyID)
        d.append(bigEndianBytes: UInt16(networkIdentifier: ciphersuite.kem))
        d.append(bigEndianBytes: UInt16(networkIdentifier: ciphersuite.kdf))
        d.append(bigEndianBytes: UInt16(networkIdentifier: ciphersuite.aead))
        return d
    }

    static func buildInfo(header: Data, mediaType: String) -> Data {
        var info = Data(mediaType.utf8)
        info.append(0)
        info.append(contentsOf: header)
        return info
    }
}

extension RandomAccessCollection where Element == UInt8, Self == Self.SubSequence {
    mutating func popUInt8() -> UInt8? {
        return self.popFirst()
    }

    mutating func popUInt16() -> UInt16? {
        guard self.count >= 2 else { return nil }
        return (UInt16(self.popUInt8()!) << 8 | UInt16(self.popUInt8()!))
    }

    mutating func popFirst(_ n: Int) -> Self? {
        guard self.count >= n else {
            return nil
        }

        let rvalue = self.prefix(n)
        self = self.dropFirst(n)
        return rvalue
    }
}

extension Data {
    mutating func append(bigEndianBytes: UInt16) {
        self.append(UInt8(truncatingIfNeeded: bigEndianBytes >> 8))
        self.append(UInt8(truncatingIfNeeded: bigEndianBytes))
    }
}

extension Data {
    mutating func xor(with value: UInt64) {
        // We handle value in network byte order.
        precondition(self.count >= 8)

        var index = self.endIndex
        for byteNumber in 0..<8 {
            // Unchecked math in here is all sound, byteNumber is between 0 and 8 and index is
            // always positive.
            let byte = UInt8(truncatingIfNeeded: (value >> (byteNumber &* 8)))
            index &-= 1
            self[index] ^= byte
        }
    }
}

extension UInt16 {
    init(networkIdentifier: HPKE.KEM) {
        switch networkIdentifier {
        case .P256_HKDF_SHA256:
            self = 0x0010
        case .P384_HKDF_SHA384:
            self = 0x0011
        case .P521_HKDF_SHA512:
            self = 0x0012
        case .Curve25519_HKDF_SHA256:
            self = 0x0020
        }
    }

    init(networkIdentifier: HPKE.KDF) {
        switch networkIdentifier {
        case .HKDF_SHA256:
            self = 0x0001
        case .HKDF_SHA384:
            self = 0x0002
        case .HKDF_SHA512:
            self = 0x0003
        }
    }

    init(networkIdentifier: HPKE.AEAD) {
        switch networkIdentifier {
        case .AES_GCM_128:
            self = 0x0001
        case .AES_GCM_256:
            self = 0x0002
        case .chaChaPoly:
            self = 0x0003
        case .exportOnly:
            self = 0xFFFF
        }
    }
}

extension HPKE.KEM {
    init?(networkIdentifier: UInt16) {
        switch networkIdentifier {
        case 0x0010:
            self = .P256_HKDF_SHA256
        case 0x0011:
            self = .P384_HKDF_SHA384
        case 0x0012:
            self = .P521_HKDF_SHA512
        case 0x0020:
            self = .Curve25519_HKDF_SHA256
        default:
            return nil
        }
    }

    var encapsulatedKeySize: Int {
        switch self {
        case .P256_HKDF_SHA256:
            return 65
        case .P384_HKDF_SHA384:
            return 97
        case .P521_HKDF_SHA512:
            return 133
        case .Curve25519_HKDF_SHA256:
            return 32
        }
    }
}

extension HPKE.KDF {
    init?(networkIdentifier: UInt16) {
        switch networkIdentifier {
        case 0x0001:
            self = .HKDF_SHA256
        case 0x0002:
            self = .HKDF_SHA384
        case 0x0003:
            self = .HKDF_SHA512
        default:
            return nil
        }
    }
}

extension HPKE.AEAD {
    init?(networkIdentifier: UInt16) {
        switch networkIdentifier {
        case 0x0001:
            self = .AES_GCM_128
        case 0x0002:
            self = .AES_GCM_256
        case 0x0003:
            self = .chaChaPoly
        case 0xFFFF:
            self = .exportOnly
        default:
            return nil
        }
    }

    var keyByteCount: Int {
        switch self {
        case .AES_GCM_128:
            return 16
        case .AES_GCM_256:
            return 32
        case .chaChaPoly:
            return 32
        case .exportOnly:
            fatalError("ExportOnly should not return a key size.")
        }
    }

    var nonceByteCount: Int {
        switch self {
        case .AES_GCM_128, .AES_GCM_256, .chaChaPoly:
            return 12
        case .exportOnly:
            fatalError("ExportOnly should not return a nonce size.")
        }
    }

    var tagByteCount: Int {
        switch self {
        case .AES_GCM_128, .AES_GCM_256, .chaChaPoly:
            return 16
        case .exportOnly:
            fatalError("ExportOnly should not return a tag size.")
        }
    }

    internal func seal<D: DataProtocol, AD: DataProtocol>(
        _ message: D,
        authenticating aad: AD,
        nonce: Data,
        using key: SymmetricKey
    ) throws -> Data {
        switch self {
        case .chaChaPoly:
            return try ChaChaPoly.seal(
                message,
                using: key,
                nonce: ChaChaPoly.Nonce(data: nonce),
                authenticating: aad
            ).combined.suffix(from: nonce.count)
        default:
            return try AES.GCM.seal(
                message,
                using: key,
                nonce: AES.GCM.Nonce(data: nonce),
                authenticating: aad
            ).combined!.suffix(from: nonce.count)
        }
    }

    internal func open<C: DataProtocol, AD: DataProtocol>(
        _ ct: C,
        nonce: Data,
        authenticating aad: AD,
        using key: SymmetricKey
    ) throws -> Data {
        guard ct.count >= self.tagByteCount else {
            throw HPKE.Errors.expectedPSK
        }

        switch self {
        case .AES_GCM_128, .AES_GCM_256:
            do {
                let nonce = try AES.GCM.Nonce(data: nonce)
                let sealedBox = try AES.GCM.SealedBox(
                    nonce: nonce,
                    ciphertext: ct.dropLast(16),
                    tag: ct.suffix(16)
                )
                return try AES.GCM.open(sealedBox, using: key, authenticating: aad)
            }
        case .chaChaPoly:
            do {
                let nonce = try ChaChaPoly.Nonce(data: nonce)
                let sealedBox = try ChaChaPoly.SealedBox(
                    nonce: nonce,
                    ciphertext: ct.dropLast(16),
                    tag: ct.suffix(16)
                )
                return try ChaChaPoly.open(sealedBox, using: key, authenticating: aad)
            }
        case .exportOnly:
            throw HPKE.Errors.exportOnlyMode
        }
    }
}

// MARK: Temporarily extracted from CryptoKit until API is available for extracting secrets
private let protocolLabel = Data("HPKE-v1".utf8)

extension HPKE.KEM {
    internal var identifier: Data {
        return I2OSP(value: Int(UInt16(networkIdentifier: self)), outputByteCount: 2)
    }
}

extension HPKE.KDF {
    internal var identifier: Data {
        return I2OSP(value: Int(UInt16(networkIdentifier: self)), outputByteCount: 2)
    }
}

extension HPKE.AEAD {
    internal var identifier: Data {
        return I2OSP(value: Int(UInt16(networkIdentifier: self)), outputByteCount: 2)
    }
}

extension HPKE.Ciphersuite {
    fileprivate static let ciphersuiteLabel = Data("HPKE".utf8)

    internal var identifier: Data {
        var identifier = Self.ciphersuiteLabel
        identifier.append(kem.identifier)
        identifier.append(kdf.identifier)
        identifier.append(aead.identifier)
        return identifier
    }
}

extension HPKE.KDF {
    func extract<S: DataProtocol>(salt: S, ikm: SymmetricKey) -> SymmetricKey {
        switch self {
        case .HKDF_SHA256:
            return SymmetricKey(data: HKDF<SHA256>.extract(inputKeyMaterial: ikm, salt: salt))
        case .HKDF_SHA384:
            return SymmetricKey(data: HKDF<SHA384>.extract(inputKeyMaterial: ikm, salt: salt))
        case .HKDF_SHA512:
            return SymmetricKey(data: HKDF<SHA512>.extract(inputKeyMaterial: ikm, salt: salt))
        }
    }

    func expand(prk: SymmetricKey, info: Data, outputByteCount: Int) -> SymmetricKey {
        switch self {
        case .HKDF_SHA256:
            return SymmetricKey(
                data: HKDF<SHA256>.expand(
                    pseudoRandomKey: prk,
                    info: info,
                    outputByteCount: outputByteCount
                )
            )
        case .HKDF_SHA384:
            return SymmetricKey(
                data: HKDF<SHA384>.expand(
                    pseudoRandomKey: prk,
                    info: info,
                    outputByteCount: outputByteCount
                )
            )
        case .HKDF_SHA512:
            return SymmetricKey(
                data: HKDF<SHA512>.expand(
                    pseudoRandomKey: prk,
                    info: info,
                    outputByteCount: outputByteCount
                )
            )
        }
    }
}

internal func I2OSP(value: Int, outputByteCount: Int) -> Data {
    precondition(outputByteCount > 0, "Cannot I2OSP with no output length.")
    precondition(value >= 0, "I2OSP requires a non-null value.")

    let requiredBytes = Int(ceil(log2(Double(max(value, 1) + 1)) / 8))
    precondition(outputByteCount >= requiredBytes)

    var data = Data(repeating: 0, count: outputByteCount)

    for i in (outputByteCount - requiredBytes)...(outputByteCount - 1) {
        data[i] = UInt8(truncatingIfNeeded: (value >> (8 * (outputByteCount - 1 - i))))
    }

    return data
}

extension UnsafeMutableRawBufferPointer {
    @inlinable
    func initializeWithRandomBytes(count: Int) {
        guard count > 0 else {
            return
        }

        precondition(count <= self.count)
        var rng = SystemRandomNumberGenerator()

        // We store bytes 64-bits at a time until we can't anymore.
        var targetPtr = self
        while targetPtr.count > 8 {
            targetPtr.storeBytes(of: rng.next(), as: UInt64.self)
            targetPtr = UnsafeMutableRawBufferPointer(rebasing: targetPtr[8...])
        }

        // Now we're down to having to store things an integer at a time. We do this by shifting and
        // masking.
        var remainingWord: UInt64 = rng.next()
        while targetPtr.count > 0 {
            targetPtr.storeBytes(of: UInt8(remainingWord & 0xFF), as: UInt8.self)
            remainingWord >>= 8
            targetPtr = UnsafeMutableRawBufferPointer(rebasing: targetPtr[1...])
        }
    }
}

extension Data {
    init(_ key: SymmetricKey) {
        self = key.withUnsafeBytes { Data($0) }
    }
}

private let finalAAD = Data("final".utf8)
