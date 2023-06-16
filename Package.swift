// swift-tools-version: 5.8
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

import PackageDescription

let package = Package(
    name: "swift-nio-oblivious-http",
    platforms: [
        .macOS("14"),
        .iOS("17"),
    ],
    products: [
        .library(
            name: "ObliviousHTTP",
            targets: ["ObliviousHTTP"]),
        .library(
            name: "ObliviousX",
            targets: ["ObliviousX"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.54.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.0.0-beta.1"),
    ],
    targets: [
        .target(
            name: "ObliviousHTTP",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
            ]),
        .target(
            name: "ObliviousX",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ]),
    ]
)
