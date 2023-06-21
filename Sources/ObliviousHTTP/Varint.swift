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

extension ByteBuffer {
    mutating func readVarint() -> Int? {
        guard let firstByte = self.getInteger(at: self.readerIndex, as: UInt8.self) else {
            return nil
        }

        // Look at the first two bits to work out the length, then read that, mask off the top two bits, and
        // extend to integer.
        switch firstByte & 0xC0 {
        case 0x00:
            // Easy case.
            self.moveReaderIndex(forwardBy: 1)
            return Int(firstByte & ~0xC0)
        case 0x40:
            // Length is two bytes long, read the next one.
            return self.readInteger(as: UInt16.self).map { Int($0 & ~(0xC0 << 8)) }
        case 0x80:
            // Length is 4 bytes long.
            return self.readInteger(as: UInt32.self).map { Int($0 & ~(0xC0 << 24)) }
        case 0xC0:
            // Length is 8 bytes long.
            return self.readInteger(as: UInt64.self).map { Int($0 & ~(0xC0 << 56)) }
        default:
            preconditionFailure("Unreachable")
        }
    }

    mutating func readVarintLengthPrefixedSlice() -> ByteBuffer? {
        let originalReaderIndex = self.readerIndex
        guard let length = self.readVarint(), let slice = self.readSlice(length: length) else {
            self.moveReaderIndex(to: originalReaderIndex)
            return nil
        }
        return slice
    }
}
