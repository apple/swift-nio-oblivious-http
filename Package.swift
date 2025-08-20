// swift-tools-version:5.10
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

let strictConcurrencyDevelopment = false

let strictConcurrencySettings: [SwiftSetting] = {
    var initialSettings: [SwiftSetting] = []
    initialSettings.append(contentsOf: [
        .enableUpcomingFeature("StrictConcurrency"),
        .enableUpcomingFeature("InferSendableFromCaptures"),
    ])

    if strictConcurrencyDevelopment {
        // -warnings-as-errors here is a workaround so that IDE-based development can
        // get tripped up on -require-explicit-sendable.
        initialSettings.append(.unsafeFlags(["-require-explicit-sendable", "-warnings-as-errors"]))
    }

    return initialSettings
}()

let package = Package(
    name: "swift-nio-oblivious-http",
    platforms: [
        .macOS("14"),
        .iOS("17"),
        .tvOS("17"),
        .watchOS("10"),
    ],
    products: [
        .library(
            name: "ObliviousHTTP",
            targets: ["ObliviousHTTP"]
        ),
        .library(
            name: "ObliviousX",
            targets: ["ObliviousX"]
        ),
        .library(
            name: "ObliviousDoH",
            targets: ["ObliviousDoH"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.81.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "ObliviousHTTP",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
            ],
            swiftSettings: strictConcurrencySettings
        ),
        .target(
            name: "ObliviousX",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ],
            swiftSettings: strictConcurrencySettings
        ),
        .target(
            name: "ObliviousDoH",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ],
            swiftSettings: strictConcurrencySettings
        ),
        .testTarget(
            name: "ObliviousHTTPTests",
            dependencies: [
                "ObliviousHTTP",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
            ],
            swiftSettings: strictConcurrencySettings
        ),
        .testTarget(
            name: "ObliviousXTests",
            dependencies: [
                "ObliviousX",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            swiftSettings: strictConcurrencySettings
        ),
        .testTarget(
            name: "ObliviousDoHTests",
            dependencies: [
                "ObliviousDoH",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            swiftSettings: strictConcurrencySettings
        ),
    ]
)

// ---    STANDARD CROSS-REPO SETTINGS DO NOT EDIT   --- //
for target in package.targets {
    switch target.type {
    case .regular, .test, .executable:
        var settings = target.swiftSettings ?? []
        // https://github.com/swiftlang/swift-evolution/blob/main/proposals/0444-member-import-visibility.md
        settings.append(.enableUpcomingFeature("MemberImportVisibility"))
        target.swiftSettings = settings
    case .macro, .plugin, .system, .binary:
        ()  // not applicable
    @unknown default:
        ()  // we don't know what to do here, do nothing
    }
}
// --- END: STANDARD CROSS-REPO SETTINGS DO NOT EDIT --- //
