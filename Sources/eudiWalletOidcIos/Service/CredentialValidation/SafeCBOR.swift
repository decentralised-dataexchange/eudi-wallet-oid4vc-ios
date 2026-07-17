//
//  SafeCBOR.swift
//
//
//  Guards CBOR decoding against a denial-of-service crash in SwiftCBOR.
//
//  A malformed/truncated CBOR header can declare an array/map/string length that
//  is close to Int.max (e.g. the 9 bytes `9B FF FF FF FF FF FF FF FF` = "array of
//  0xFFFFFFFFFFFFFFFF items"). SwiftCBOR's `CBORDecoder.readN` reserves capacity
//  for that declared count *before* reading any element, which triggers a
//  non-catchable allocation abort (`fatalError`) deep inside libswiftCore. A
//  `try?` around `CBOR.decode` cannot intercept that trap.
//
//  `SafeCBOR.decode` first walks the byte stream allocation-free and rejects any
//  item whose declared length exceeds the bytes actually remaining, so the input
//  handed to `CBOR.decode` can never provoke the runaway reservation.
//
import Foundation
import SwiftCBOR
enum SafeCBOR {
    /// Maximum nesting depth we are willing to validate/decode. Real mdoc issuer
    /// auth / MSO structures are shallow; this only rejects pathological input.
    private static let maxDepth = 512
    /// Structurally validates `bytes`, then decodes. Returns `nil` for malformed
    /// input instead of crashing.
    static func decode(_ bytes: [UInt8]) -> CBOR? {
        guard !bytes.isEmpty, isStructurallySafe(bytes) else { return nil }
        return try? CBOR.decode(bytes)
    }
    /// Single-pass, allocation-free scan. Returns `true` only if `bytes` begins
    /// with a well-formed CBOR item whose declared lengths never exceed the
    /// remaining input.
    static func isStructurallySafe(_ bytes: [UInt8]) -> Bool {
        var index = 0
        return scanItem(bytes, &index, depth: 0)
    }
    private static func scanItem(_ b: [UInt8], _ i: inout Int, depth: Int) -> Bool {
        guard depth <= maxDepth, i < b.count else { return false }
        let initialByte = b[i]; i += 1
        let major = initialByte >> 5
        let additionalInfo = initialByte & 0x1f
        // Resolve the argument (length / element count / value).
        var arg: UInt64 = 0
        switch additionalInfo {
        case 0...23:
            arg = UInt64(additionalInfo)
        case 24:
            guard i + 1 <= b.count else { return false }
            arg = UInt64(b[i]); i += 1
        case 25:
            guard i + 2 <= b.count else { return false }
            arg = (UInt64(b[i]) << 8) | UInt64(b[i + 1]); i += 2
        case 26:
            guard i + 4 <= b.count else { return false }
            for k in 0..<4 { arg = (arg << 8) | UInt64(b[i + k]) }
            i += 4
        case 27:
            guard i + 8 <= b.count else { return false }
            for k in 0..<8 { arg = (arg << 8) | UInt64(b[i + k]) }
            i += 8
        case 31:
            // Indefinite length — valid only for strings/arrays/maps (major 2...5).
            return scanIndefinite(b, &i, major: major, depth: depth)
        default:
            // 28, 29, 30 are reserved and not well-formed.
            return false
        }
        switch major {
        case 0, 1:
            // Unsigned / negative integer — no payload follows.
            return true
        case 2, 3:
            // Byte string / text string — `arg` payload bytes follow.
            guard arg <= UInt64(b.count - i) else { return false }
            i += Int(arg)
            return true
        case 4:
            // Array of `arg` items — each item is at least one byte.
            guard arg <= UInt64(b.count - i) else { return false }
            var remaining = arg
            while remaining > 0 {
                guard scanItem(b, &i, depth: depth + 1) else { return false }
                remaining -= 1
            }
            return true
        case 5:
            // Map of `arg` key/value pairs — each pair is at least two bytes.
            guard arg <= UInt64(b.count - i) else { return false }
            var remaining = arg
            while remaining > 0 {
                guard scanItem(b, &i, depth: depth + 1) else { return false } // key
                guard scanItem(b, &i, depth: depth + 1) else { return false } // value
                remaining -= 1
            }
            return true
        case 6:
            // Tag — exactly one item follows.
            return scanItem(b, &i, depth: depth + 1)
        case 7:
            // Simple value / float — trailing bytes already consumed via `arg`.
            return true
        default:
            return false
        }
    }
    private static func scanIndefinite(_ b: [UInt8], _ i: inout Int, major: UInt8, depth: Int) -> Bool {
        switch major {
        case 2, 3, 4:
            // Indefinite byte/text string chunks or array items until break.
            while true {
                guard i < b.count else { return false }
                if b[i] == 0xff { i += 1; return true }
                guard scanItem(b, &i, depth: depth + 1) else { return false }
            }
        case 5:
            // Indefinite map: key/value pairs until break.
            while true {
                guard i < b.count else { return false }
                if b[i] == 0xff { i += 1; return true }
                guard scanItem(b, &i, depth: depth + 1) else { return false }        // key
                guard i < b.count, b[i] != 0xff else { return false }                // value required
                guard scanItem(b, &i, depth: depth + 1) else { return false }        // value
            }
        default:
            // Indefinite length is not well-formed for other major types.
            return false
        }
    }
}
