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

@available(macOS 14, iOS 17, *)
public enum OHTTPEncapsulation {
    public static func encapsulateRequest<PublicKey: HPKEDiffieHellmanPublicKey, Message: DataProtocol>(
        keyID: UInt8, publicKey: PublicKey, ciphersuite: HPKE.Ciphersuite, mediaType: String, content: Message
    ) throws -> (Data, HPKE.Sender) {
        var header = Self.buildHeader(keyID: keyID, ciphersuite: ciphersuite)
        var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: ciphersuite, info: Self.buildInfo(header: header, mediaType: mediaType))
        let ct = try sender.seal(content)

        header.append(contentsOf: sender.encapsulatedKey)
        header.append(contentsOf: ct)

        return (header, sender)
    }

    public static func parseEncapsulatedRequest<Bytes: RandomAccessCollection>(encapsulatedRequest: Bytes) -> EncapsulatedRequest<Bytes.SubSequence>? where Bytes.Element == UInt8 {
        guard encapsulatedRequest.count >= 7 else {
            return nil
        }

        let header = encapsulatedRequest.prefix(7)
        var bytes = encapsulatedRequest[...]
        guard let keyID = bytes.popUInt8(),
              let kem = bytes.popUInt16().flatMap({ HPKE.KEM(networkIdentifier: $0) }),
              let kdf = bytes.popUInt16().flatMap({ HPKE.KDF(networkIdentifier: $0) }),
              let aead = bytes.popUInt16().flatMap({ HPKE.AEAD(networkIdentifier: $0) }),
              let encapsulatedKey = bytes.popFirst(kem.encapsulatedKeySize) else {
            return nil
        }

        return EncapsulatedRequest(
            keyID: keyID,
            kem: kem,
            kdf: kdf,
            aead: aead,
            header: header,
            encapsulatedKey: encapsulatedKey,
            ct: bytes
        )
    }

    public static func encapsulateResponse<Message: DataProtocol, EncapsulatedKey: RandomAccessCollection> (
        context: HPKE.Recipient, encapsulatedKey: EncapsulatedKey,  mediaType: String, ciphersuite: HPKE.Ciphersuite, content: Message
    ) throws -> Data where EncapsulatedKey.Element == UInt8 {
        let secret = try context.exportSecret(context: Array(mediaType.utf8), ciphersuite: ciphersuite, outputByteCount: ciphersuite.aead.keyByteCount)
        let nonceLength = max(ciphersuite.aead.keyByteCount, ciphersuite.aead.nonceByteCount)
        var responseNonce = Data(repeating: 0, count: nonceLength)
        responseNonce.withUnsafeMutableBytes { $0.initializeWithRandomBytes(count: nonceLength) }

        var salt = Data(encapsulatedKey)
        salt.append(contentsOf: responseNonce)

        let prk = ciphersuite.kdf.extract(salt: salt, ikm: secret)
        let aeadKey = ciphersuite.kdf.expand(prk: prk, info: Data("key".utf8), outputByteCount: ciphersuite.aead.keyByteCount)
        let aeadNonce = ciphersuite.kdf.expand(prk: prk, info: Data("nonce".utf8), outputByteCount: ciphersuite.aead.nonceByteCount)
        let ct = try ciphersuite.aead.seal(content, authenticating: Data(), nonce: Data(aeadNonce), using: aeadKey)

        responseNonce.append(contentsOf: ct)
        return responseNonce
    }

    public static func decapsulateResponse<ResponsePayload: DataProtocol>(
        responsePayload: ResponsePayload, mediaType: String, context: HPKE.Sender, ciphersuite: HPKE.Ciphersuite
    ) throws -> Data {
        var payload = responsePayload[...]
        let nonceLength = max(ciphersuite.aead.keyByteCount, ciphersuite.aead.nonceByteCount)
        guard let responseNonce = payload.popFirst(nonceLength) else {
            throw CryptoKitError.incorrectParameterSize
        }

        let secret = try context.exportSecret(context: Array(mediaType.utf8), ciphersuite: ciphersuite, outputByteCount: ciphersuite.aead.keyByteCount)

        var salt = Data(context.encapsulatedKey)
        salt.append(contentsOf: responseNonce)

        let prk = ciphersuite.kdf.extract(salt: salt, ikm: secret)
        let aeadKey = ciphersuite.kdf.expand(prk: prk, info: Data("key".utf8), outputByteCount: ciphersuite.aead.keyByteCount)
        let aeadNonce = ciphersuite.kdf.expand(prk: prk, info: Data("nonce".utf8), outputByteCount: ciphersuite.aead.nonceByteCount)

        return try ciphersuite.aead.open(payload, nonce: Data(aeadNonce), authenticating: Data(), using: aeadKey)
    }

    public struct EncapsulatedRequest<Bytes: RandomAccessCollection & DataProtocol> where Bytes.Element == UInt8, Bytes.SubSequence == Bytes {
        public private(set) var keyID: UInt8

        public private(set) var kem: HPKE.KEM

        public private(set) var kdf: HPKE.KDF

        public private(set) var aead: HPKE.AEAD

        public private(set) var header: Bytes

        public private(set) var encapsulatedKey: Bytes

        public private(set) var ct: Bytes

        init(keyID: UInt8, kem: HPKE.KEM, kdf: HPKE.KDF, aead: HPKE.AEAD, header: Bytes, encapsulatedKey: Bytes, ct: Bytes) {
            self.keyID = keyID
            self.kem = kem
            self.kdf = kdf
            self.aead = aead
            self.header = header
            self.encapsulatedKey = encapsulatedKey
            self.ct = ct
        }

        public func decapsulate<PrivateKey: HPKEDiffieHellmanPrivateKey>(mediaType: String, privateKey: PrivateKey) throws -> (Data, HPKE.Recipient) {
            let info = OHTTPEncapsulation.buildInfo(header: Data(self.header), mediaType: mediaType)
            var recipient = try HPKE.Recipient(
                privateKey: privateKey,
                ciphersuite: HPKE.Ciphersuite(kem: self.kem, kdf: self.kdf, aead: self.aead),
                info: info,
                encapsulatedKey: Data(self.encapsulatedKey)
            )
            let decrypted = try recipient.open(self.ct)
            return (decrypted, recipient)
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
        return (
            UInt16(self.popUInt8()!) << 8 |
            UInt16(self.popUInt8()!)
        )
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

    internal func seal<D: DataProtocol, AD: DataProtocol>(_ message: D, authenticating aad: AD, nonce: Data, using key: SymmetricKey) throws -> Data {
        switch self {
        case .chaChaPoly:
            return try ChaChaPoly.seal(message, using: key, nonce: ChaChaPoly.Nonce(data: nonce), authenticating: aad).combined.suffix(from: nonce.count)
        default:
            return try AES.GCM.seal(message, using: key, nonce: AES.GCM.Nonce(data: nonce), authenticating: aad).combined!.suffix(from: nonce.count)
        }
    }

    internal func open<C: DataProtocol, AD: DataProtocol>(_ ct: C, nonce: Data, authenticating aad: AD, using key: SymmetricKey) throws -> Data {
        guard ct.count >= self.tagByteCount else {
            throw HPKE.Errors.expectedPSK
        }

        switch self {
        case .AES_GCM_128, .AES_GCM_256: do {
            let nonce = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct.dropLast(16), tag: ct.suffix(16))
            return try AES.GCM.open(sealedBox, using: key, authenticating: aad)
        }
        case .chaChaPoly: do {
            let nonce = try ChaChaPoly.Nonce(data: nonce)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct.dropLast(16), tag: ct.suffix(16))
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

extension HPKE.Sender {
    func exportSecret<Context: DataProtocol>(context: Context, ciphersuite: HPKE.Ciphersuite, outputByteCount: Int) throws -> SymmetricKey {
        precondition(outputByteCount > 0);
        return LabeledExpand(prk: self.exporterSecret,
                             label: Data("sec".utf8),
                             info: context,
                             outputByteCount: UInt16(outputByteCount),
                             suiteID: ciphersuite.identifier,
                             kdf: ciphersuite.kdf)
    }
}

extension HPKE.Recipient {
    func exportSecret<Context: DataProtocol>(context: Context, ciphersuite: HPKE.Ciphersuite, outputByteCount: Int) throws -> SymmetricKey {
        precondition(outputByteCount > 0);
        return LabeledExpand(prk: self.exporterSecret,
                             label: Data("sec".utf8),
                             info: context,
                             outputByteCount: UInt16(outputByteCount),
                             suiteID: ciphersuite.identifier,
                             kdf: ciphersuite.kdf)
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
            return SymmetricKey(data: HKDF<SHA256>.expand(pseudoRandomKey: prk, info: info, outputByteCount: outputByteCount))
        case .HKDF_SHA384:
            return SymmetricKey(data: HKDF<SHA384>.expand(pseudoRandomKey: prk, info: info, outputByteCount: outputByteCount))
        case .HKDF_SHA512:
            return SymmetricKey(data: HKDF<SHA512>.expand(pseudoRandomKey: prk, info: info, outputByteCount: outputByteCount))
        }
    }
}

internal func LabeledExpand<Info: DataProtocol>(prk: SymmetricKey, label: Data, info: Info, outputByteCount: UInt16, suiteID: Data, kdf: HPKE.KDF) -> SymmetricKey {
    var labeled_info = I2OSP(value: Int(outputByteCount), outputByteCount: 2)
    labeled_info.append(protocolLabel)
    labeled_info.append(suiteID)
    labeled_info.append(label)
    labeled_info.append(contentsOf: info)
    return kdf.expand(prk: prk, info: labeled_info, outputByteCount: Int(outputByteCount))
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

