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
import Foundation

/// An error occured when adding oblivious encapsulation.
public struct ObliviousXError: Error, Hashable {
    private var backing: Backing

    fileprivate init(backing: Backing) {
        self.backing = backing
    }

    /// Create an error indicating that the HPKE parameters given were not supported.
    /// - Returns: An Error representing this failure.
    @inline(never)
    public static func unsupportedHPKEParameters() -> ObliviousXError {
        Self.init(backing: .unsupportedHPKEParameters)
    }

    @inline(never)
    public static func invalidODoHData() -> ObliviousXError {
        Self.init(backing: .invalidODoHData)
    }

    @inline(never)
    public static func invalidMessageType(expected: UInt8, actual: UInt8) -> ObliviousXError {
        Self.init(backing: .invalidMessageType(expected, actual))
    }

    @inline(never)
    public static func invalidPublicKey(kemID: UInt16, key: Data) -> ObliviousXError {
        Self.init(backing: .invalidPublicKey(kemID, key))
    }
}

extension ObliviousXError {
    enum Backing: Hashable, Sendable {
        case unsupportedHPKEParameters
        case invalidODoHData
        case invalidMessageType(UInt8, UInt8)
        case invalidPublicKey(UInt16, Data)
    }
}
