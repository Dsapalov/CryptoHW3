//
//  InternalSHA1.swift
//  CryptoHW3
//
//  Created by Denis Sapalov on 05.11.2022.
//

import Foundation

infix operator <<< : BitwiseShiftPrecedence
private func <<< (lhs:UInt32, rhs:UInt32) -> UInt32 {
    return lhs << rhs | lhs >> (32-rhs)
}

/**
    SHA-1 implementation
 */
public struct InternalSHA1 {
    private static let ITERATION_COUNT = 80
    
    private static let h0:UInt32 = 0x67452301
    private static let h1:UInt32 = 0xEFCDAB89
    private static let h2:UInt32 = 0x98BADCFE
    private static let h3:UInt32 = 0x10325476
    private static let h4:UInt32 = 0xC3D2E1F0
    
    private struct context {
        var h:[UInt32] = [InternalSHA1.h0, InternalSHA1.h1, InternalSHA1.h2, InternalSHA1.h3, InternalSHA1.h4]
        
        mutating func process(chunk:inout ContiguousArray<UInt32>) {
            for i in 0..<16 {
                chunk[i] = chunk[i].bigEndian
            }
            for i in 16...ITERATION_COUNT - 1 {
                chunk[i] = (chunk[i-3] ^ chunk[i-8] ^ chunk[i-14] ^ chunk[i-16]) <<< 1
            }
            
            var a, b, c, d, e, f, k, temp:UInt32
            a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]
            f = 0x0; k = 0x0
            
            for i in 0...ITERATION_COUNT - 1 {
                switch i {
                case 0...19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                case 20...39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                case 40...59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                case 60...ITERATION_COUNT - 1:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                default: break
                }
                temp = a <<< 5 &+ f &+ e &+ k &+ chunk[i]
                e = d
                d = c
                c = b <<< 30
                b = a
                a = temp
            }

            // final operation
            h[0] = h[0] &+ a
            h[1] = h[1] &+ b
            h[2] = h[2] &+ c
            h[3] = h[3] &+ d
            h[4] = h[4] &+ e
        }
    }
    
    private static func process(data: inout Data) -> InternalSHA1.context? {
        var context = InternalSHA1.context()
        var emptyBuffer = ContiguousArray<UInt32>(repeating: 0x00000000, count: ITERATION_COUNT)
        let messageLen = data.count << 3
        var range = 0..<64
        
        while data.count >= range.upperBound {
            emptyBuffer.withUnsafeMutableBufferPointer{ dest in
                data.copyBytes(to: dest, from: range)
            }
            context.process(chunk: &emptyBuffer)
            range = range.upperBound..<range.upperBound + 64
        }
        
        emptyBuffer = ContiguousArray<UInt32>(repeating: 0x00000000, count: ITERATION_COUNT)
        range = range.lowerBound..<data.count
        emptyBuffer.withUnsafeMutableBufferPointer{ dest in
            data.copyBytes(to: dest, from: range)
        }
        let bytetochange=range.count % 4
        let shift = UInt32(bytetochange * 8)
        emptyBuffer[range.count / 4] |= 0x80 << shift
        
        if range.count+1 > 56 {
            context.process(chunk: &emptyBuffer)
            emptyBuffer = ContiguousArray<UInt32>(repeating: 0x00000000, count: ITERATION_COUNT)
        }
        
        emptyBuffer[15] = UInt32(messageLen).bigEndian
        context.process(chunk: &emptyBuffer)
        
        return context
    }
    
    public static func hexString(from str:String) -> String? {
        guard var data = str.data(using: .utf8),
                let context = InternalSHA1.process(data: &data) else {
            return "Internal error!"
        }
        return String(format: "%08X %08X %08X %08X %08X", context.h[0], context.h[1], context.h[2], context.h[3], context.h[4])
    }
}

