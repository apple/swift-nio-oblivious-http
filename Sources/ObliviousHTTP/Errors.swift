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
public struct ObliviousHTTPError: Error, Hashable {
  private var backing: Backing

  fileprivate init(backing: Backing) {
    self.backing = backing
  }

  @inline(never)
  public static func invalidFramingIndicator(_ indicator: Int) -> ObliviousHTTPError {
    return Self.init(backing: .invalidFramingIndicator(indicator))
  }

  @inline(never)
  public static func invalidFieldSection(reason: String) -> ObliviousHTTPError {
    return Self.init(backing: .invalidFieldSection(reason: reason))
  }

  @inline(never)
  public static func truncatedEncoding(reason: String) -> ObliviousHTTPError {
    return Self.init(backing: .truncatedEncoding(reason: reason))
  }

  @inline(never)
  public static func invalidStatus(status: Int) -> ObliviousHTTPError {
    return Self.init(backing: .invalidStatus(status: status))
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
