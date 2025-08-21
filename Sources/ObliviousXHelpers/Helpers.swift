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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
@preconcurrency import Glibc
#elseif canImport(Musl)
@preconcurrency import Musl
#elseif canImport(Android)
@preconcurrency import Android
#endif

// MARK: - Collection Extensions

extension RandomAccessCollection where Element == UInt8, Self == Self.SubSequence {
    package mutating func popUInt8() -> UInt8? {
        self.popFirst()
    }

    package mutating func popUInt16() -> UInt16? {
        guard self.count >= 2 else { return nil }
        return (UInt16(self.popUInt8()!) << 8 | UInt16(self.popUInt8()!))
    }

    package mutating func popFirst(_ n: Int) -> Self? {
        guard self.count >= n else {
            return nil
        }

        let rvalue = self.prefix(n)
        self = self.dropFirst(n)
        return rvalue
    }
}

// MARK: - Data Extensions

extension Data {
    package mutating func append(bigEndianBytes: UInt16) {
        self.append(UInt8(truncatingIfNeeded: bigEndianBytes >> 8))
        self.append(UInt8(truncatingIfNeeded: bigEndianBytes))
    }
}

extension Data {
    package mutating func xor(with value: UInt64) {
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

extension Data {
    package init(_ key: SymmetricKey) {
        self = key.withUnsafeBytes { Data($0) }
    }
}

// MARK: - UInt16 Network Identifier Extensions

extension UInt16 {
    package init(networkIdentifier: HPKE.KEM) {
        switch networkIdentifier {
        case .P256_HKDF_SHA256:
            self = 0x0010
        case .P384_HKDF_SHA384:
            self = 0x0011
        case .P521_HKDF_SHA512:
            self = 0x0012
        case .Curve25519_HKDF_SHA256:
            self = 0x0020
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported KEM")
        #endif
        }
    }

    package init(networkIdentifier: HPKE.KDF) {
        switch networkIdentifier {
        case .HKDF_SHA256:
            self = 0x0001
        case .HKDF_SHA384:
            self = 0x0002
        case .HKDF_SHA512:
            self = 0x0003
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported KDF")
        #endif
        }
    }

    package init(networkIdentifier: HPKE.AEAD) {
        switch networkIdentifier {
        case .AES_GCM_128:
            self = 0x0001
        case .AES_GCM_256:
            self = 0x0002
        case .chaChaPoly:
            self = 0x0003
        case .exportOnly:
            self = 0xFFFF
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported AEAD")
        #endif
        }
    }
}

// MARK: - HPKE Extensions

extension HPKE.KEM {
    package init?(networkIdentifier: UInt16) {
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

    package var encapsulatedKeySize: Int {
        switch self {
        case .P256_HKDF_SHA256:
            return 65
        case .P384_HKDF_SHA384:
            return 97
        case .P521_HKDF_SHA512:
            return 133
        case .Curve25519_HKDF_SHA256:
            return 32
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported KEM")
        #endif
        }
    }

    package func getPublicKey(data: Data) throws -> any HPKEDiffieHellmanPublicKey {
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

    package var identifier: Data {
        I2OSP(value: Int(UInt16(networkIdentifier: self)), outputByteCount: 2)
    }
}

extension HPKE.KDF {
    package init?(networkIdentifier: UInt16) {
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

    package var hashByteCount: Int {
        switch self {
        case .HKDF_SHA256:
            return 32
        case .HKDF_SHA384:
            return 48
        case .HKDF_SHA512:
            return 64
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported KDF")
        #endif
        }
    }

    package func extract<S: DataProtocol>(salt: S, ikm: SymmetricKey) -> SymmetricKey {
        switch self {
        case .HKDF_SHA256:
            return SymmetricKey(data: HKDF<SHA256>.extract(inputKeyMaterial: ikm, salt: salt))
        case .HKDF_SHA384:
            return SymmetricKey(data: HKDF<SHA384>.extract(inputKeyMaterial: ikm, salt: salt))
        case .HKDF_SHA512:
            return SymmetricKey(data: HKDF<SHA512>.extract(inputKeyMaterial: ikm, salt: salt))
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported KDF")
        #endif
        }
    }

    package func expand(prk: SymmetricKey, info: Data, outputByteCount: Int) -> SymmetricKey {
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
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported KDF")
        #endif
        }
    }

    package var identifier: Data {
        I2OSP(value: Int(UInt16(networkIdentifier: self)), outputByteCount: 2)
    }
}

extension HPKE.AEAD {
    package init?(networkIdentifier: UInt16) {
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

    package var keyByteCount: Int {
        switch self {
        case .AES_GCM_128:
            return 16
        case .AES_GCM_256:
            return 32
        case .chaChaPoly:
            return 32
        case .exportOnly:
            fatalError("ExportOnly should not return a key size.")
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported AEAD")
        #endif
        }
    }

    package var nonceByteCount: Int {
        switch self {
        case .AES_GCM_128, .AES_GCM_256, .chaChaPoly:
            return 12
        case .exportOnly:
            fatalError("ExportOnly should not return a nonce size.")
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported AEAD")
        #endif
        }
    }

    package var tagByteCount: Int {
        switch self {
        case .AES_GCM_128, .AES_GCM_256, .chaChaPoly:
            return 16
        case .exportOnly:
            fatalError("ExportOnly should not return a tag size.")
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported AEAD")
        #endif
        }
    }

    package func seal<D: DataProtocol, AD: DataProtocol>(
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

    package func open<C: DataProtocol, AD: DataProtocol>(
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
        #if canImport(CryptoKit)
        @unknown default:
            fatalError("Unsupported AEAD")
        #endif
        }
    }

    package var identifier: Data {
        I2OSP(value: Int(UInt16(networkIdentifier: self)), outputByteCount: 2)
    }
}

// MARK: - Utility Functions

package func I2OSP(value: Int, outputByteCount: Int) -> Data {
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
    package func initializeWithRandomBytes(count: Int) {
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
