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
    public static func unsupportedHPKEParameters() -> ObliviousDoHError {
        Self.init(backing: .unsupportedHPKEParameters)
    }

    @inline(never)
    public static func invalidODoHData() -> ObliviousDoHError {
        Self.init(backing: .invalidODoHData)
    }

    @inline(never)
    public static func invalidMessageType(
        expected: ODoH.Message.MessageType,
        actual: ODoH.Message.MessageType
    ) -> ObliviousDoHError {
        Self.init(backing: .invalidMessageType(expected.rawValue, actual.rawValue))
    }

    @inline(never)
    public static func invalidPublicKey(kemID: UInt16, key: Data) -> ObliviousDoHError {
        Self.init(backing: .invalidPublicKey(kemID, key))
    }

    @inline(never)
    public static func invalidODoHLength(length: Int) -> ObliviousDoHError {
        Self.init(backing: .invalidODoHLength(length))
    }

    @inline(never)
    public static func invalidODoHVersion(version: Int) -> ObliviousDoHError {
        Self.init(backing: .invalidODoHVersion(version))
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