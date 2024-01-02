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

  @discardableResult
  mutating func writeVarint(_ value: Int) -> Int {
    switch value {
    case 0..<63:
      // Easy, store the value. The top two bits are 0 so we don't need to do any masking.
      return self.writeInteger(UInt8(truncatingIfNeeded: value))
    case 0..<16383:
      // Set the top two bit mask, then write the value.
      let value = UInt16(truncatingIfNeeded: value) | (0x40 << 8)
      return self.writeInteger(value)
    case 0..<1_073_741_823:
      // Set the top two bit mask, then write the value.
      let value = UInt32(truncatingIfNeeded: value) | (0x80 << 24)
      return self.writeInteger(value)
    case 0..<4_611_686_018_427_387_903:
      // Set the top two bit mask, then write the value.
      let value = UInt64(truncatingIfNeeded: value) | (0xC0 << 56)
      return self.writeInteger(value)
    default:
      fatalError()
    }
  }

  @discardableResult
  mutating func writeVarintPrefixedImmutableBuffer(_ buffer: ByteBuffer) -> Int {
    var written = 0
    written += self.writeVarint(buffer.readableBytes)
    written += self.writeImmutableBuffer(buffer)
    return written
  }

  @discardableResult
  mutating func writeVarintPrefixedString(_ string: String) -> Int {
    var written = 0
    written += self.writeVarint(string.utf8.count)
    written += self.writeString(string)
    return written
  }
}
