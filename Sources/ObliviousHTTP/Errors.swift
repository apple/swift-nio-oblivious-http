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

/// Error encountered when using Oblivious HTTP.
public struct ObliviousHTTPError: Error, Hashable {
    private var backing: Backing

    fileprivate init(backing: Backing) {
        self.backing = backing
    }

    /// Create an error indicating that parsing failed due to unexpected framing indicator value.
    /// - Parameter indicator: The value of the framing indicator which was not recognised.
    /// - Returns: An Error representing this failure,
    @inline(never)
    public static func invalidFramingIndicator(_ indicator: Int) -> ObliviousHTTPError {
        Self.init(backing: .invalidFramingIndicator(indicator))
    }

    /// Create a error indicating that parsing failed when parsing the field section due to unexpected data.
    /// - Parameter reason: Description of the failure which occured.
    /// - Returns: An Error representing this failure.
    @inline(never)
    public static func invalidFieldSection(reason: String) -> ObliviousHTTPError {
        Self.init(backing: .invalidFieldSection(reason: reason))
    }

    /// Create an error indicating that parsing failed due to insufficient data.
    /// - Parameter reason: Description of the failing operation.
    /// - Returns: An Error repesenting this failure.
    @inline(never)
    public static func truncatedEncoding(reason: String) -> ObliviousHTTPError {
        Self.init(backing: .truncatedEncoding(reason: reason))
    }

    /// Create an error indicating that parsing faileud due to an unexpected HTTP status code.
    /// - Parameter status: The status code encountered.
    /// - Returns: An Error representing this failure.
    @inline(never)
    public static func invalidStatus(status: Int) -> ObliviousHTTPError {
        Self.init(backing: .invalidStatus(status: status))
    }
}

extension ObliviousHTTPError {
    enum Backing: Hashable, Sendable {
        case invalidFramingIndicator(Int)
        case invalidFieldSection(reason: String)
        case truncatedEncoding(reason: String)
        case invalidStatus(status: Int)
    }
}
