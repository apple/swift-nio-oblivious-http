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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An error occured when adding oblivious encapsulation.
public struct ObliviousDoHError: Error, Hashable {
    private var backing: Backing

    fileprivate init(backing: Backing) {
        self.backing = backing
    }

    /// Create an error indicating that the HPKE parameters given were not supported.
    /// - Returns: An Error representing this failure.
    @inline(never)
    public static var unsupportedHPKEParameters: Self {
        Self.init(backing: .unsupportedHPKEParameters)
    }

    /// Create an error indicating that the ODoH data is malformed or invalid.
    /// - Returns: An Error representing this failure.
    @inline(never)
    public static var invalidODoHData: Self {
        Self.init(backing: .invalidODoHData)
    }

    /// Create an error indicating that the message type does not match expectations.
    /// - Parameters:
    ///   - expected: The expected message type
    ///   - actual: The actual message type received
    /// - Returns: An Error representing this type mismatch.
    @inline(never)
    public static func invalidMessageType(
        expected: ODoH.Message.MessageType,
        actual: ODoH.Message.MessageType
    ) -> ObliviousDoHError {
        Self.init(backing: .invalidMessageType(expected.rawValue, actual.rawValue))
    }

    /// Create an error indicating that the public key is invalid for the given KEM ID.
    /// - Parameters:
    ///   - kemID: The Key Encapsulation Mechanism identifier
    ///   - key: The invalid public key data
    /// - Returns: An Error representing this key validation failure.
    @inline(never)
    public static func invalidPublicKey(kemID: UInt16, key: Data) -> ObliviousDoHError {
        Self.init(backing: .invalidPublicKey(kemID, key))
    }

    /// Create an error indicating that the ODoH message has an invalid length.
    /// - Parameter length: The invalid length value
    /// - Returns: An Error representing this length validation failure.
    @inline(never)
    public static func invalidODoHLength(length: Int) -> ObliviousDoHError {
        Self.init(backing: .invalidODoHLength(length))
    }

    /// Create an error indicating that the ODoH version is not supported.
    /// - Parameter version: The unsupported version number
    /// - Returns: An Error representing this version compatibility failure.
    @inline(never)
    public static func invalidODoHVersion(version: Int) -> ObliviousDoHError {
        Self.init(backing: .invalidODoHVersion(version))
    }
}

extension ObliviousDoHError: CustomStringConvertible {
    public var description: String {
        switch self.backing {
        case .unsupportedHPKEParameters:
            return "Unsupported HPKE parameters"
        case .invalidODoHData:
            return "Invalid ODoH data format"
        case .invalidMessageType(let expected, let actual):
            return "Invalid message type: expected \(expected), got \(actual)"
        case .invalidPublicKey(let kemID, let key):
            return "Invalid public key for KEM ID \(kemID): \(key.count) bytes"
        case .invalidODoHLength(let length):
            return "Invalid ODoH message length: \(length)"
        case .invalidODoHVersion(let version):
            return "Unsupported ODoH version: \(version)"
        }
    }
}

extension ObliviousDoHError {
    enum Backing: Hashable, Sendable {
        case unsupportedHPKEParameters
        case invalidODoHData
        case invalidMessageType(UInt8, UInt8)
        case invalidPublicKey(UInt16, Data)
        case invalidODoHLength(Int)
        case invalidODoHVersion(Int)
    }
}
