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
}

extension ObliviousXError {
    enum Backing: Hashable, Sendable {
        case unsupportedHPKEParameters
    }
}
