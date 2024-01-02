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
import NIOCore
import NIOHTTP1

final class ObliviousHTTPHandler: ChannelDuplexHandler {
  typealias InboundIn = HTTPServerRequestPart
  typealias InboundOut = HTTPServerRequestPart
  typealias OutboundIn = HTTPServerResponsePart
  typealias OutboundOut = HTTPServerResponsePart
}
