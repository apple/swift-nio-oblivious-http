# swift-nio-oblivious-http

A library for working using Oblivious HTTP with Swift NIO.

## Overview

Oblivous HTTP is a protocol to allow a client to make requests of a server without the 
server being able to identify the source of those requests.  Multiple requests from the 
same client also can't be identified as having originated from the same node.

A trusted relay is used to prevent metadata being used for tracking purposes while the 
payload is encrypted to ensure only the destination can access it.

This library provides all the components required to implement Oblivious HTTP.  We intend to extend
this project to provide out-of-box solutions compatible with swift-nio.

## Supported Swift Versions

This library was introduced with support for Swift 5.8 or later. This library will
support the latest stable Swift version and the two versions prior.

## Getting Started

### Package inclusion
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

### Binary HTTP Encoding

To serialise binary HTTP messages use `BHTTPSerializer.serialize(message, buffer)`.

To deserialise binary HTTP messages use `BHTTPParser`, adding recieved data with `append()`, then calling `completeBodyRecieved()`.  The read the message parts received call `nextMessage()`.

### Oblivious Encapsulation

To encapsulate requests start with `OHTTPEncapsulation.encapsulateRequest()`.  Similarly for responses see `OHTTPEncapsulation.encapsulateResponse()`.

To decapsulate received requests, first headers can be read with `OHTTPEncapsulation.parseRequestHeader()` Use these to enable use of `OHTTPEncapsulation.RequestDecapsulator`.  For responses see `OHTTPEncapsulation.decapsulateResponse()`.

Other functionality exists to support streaming operations.

## Package Structure

The package is split into 2 libraries.  The headline library `OblivousHTTP` provides the binary HTTP encoding
required to implement Oblivious HTTP.  The second library `ObliviousX` provides the Oblivious encapsulation
which can be applied to binary HTTP or other encodings of your choice.
