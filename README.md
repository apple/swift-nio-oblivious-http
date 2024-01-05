# swift-nio-oblivious-http

A library for working using Oblivious HTTP with Swift NIO.

## Overview

Oblivous HTTP is a protocol to allow a client to make requests of a server without the 
server being able to identify the source of those requests.  Multiple requests from the 
same client also can't be identified as having originated from the same node.

A trusted relay is used to prevent metadata being used for tracking purposes while the 
payload is encrypted to ensure only the destination can access it.

## Supported Swift Versions

This library was introduced with support for Swift 5.8 or later. This library will
support the latest stable Swift version and the two versions prior.

## Getting Started

To use swift-nio-oblivious-http, add the following dependency to your Package.swift:

```swift
dependencies: [
    .package(url: "https://github.com/apple/swift-nio-oblivious-http.git", .upToNextMinor(from: "0.2.1"))
]
```

You can then add the specific product dependency to your target:

```swift
dependencies: [
    .product(name: "ObliviousHTTP", package: "swift-nio-oblivious-http"),
]
```

