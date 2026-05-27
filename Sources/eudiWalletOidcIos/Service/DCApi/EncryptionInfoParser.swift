import Foundation
import SwiftCBOR

public struct ParsedCOSEKey {
    public let kty: Int
    public let crv: Int
    public let x: [UInt8]
    public let y: [UInt8]

    public func toUncompressedPoint() -> Data {
        var point = Data([0x04])
        point.append(contentsOf: x)
        point.append(contentsOf: y)
        return point
    }
}

public struct ParsedEncryptionInfo {
    public let cipherSuiteIdentifier: String
    public let nonce: [UInt8]?
    public let recipientPublicKey: ParsedCOSEKey
}

public class EncryptionInfoParser {

    public static func parse(base64url: String) throws -> ParsedEncryptionInfo {
        guard let data = Data(base64URLEncoded: base64url) else {
            throw DCAPIError.invalidEncryptionInfo("Invalid base64url encoding")
        }
        return try parse(cborBytes: [UInt8](data))
    }

    public static func parse(cborBytes: [UInt8]) throws -> ParsedEncryptionInfo {
        guard let decoded = try? CBOR.decode(cborBytes),
              case let .array(arr) = decoded,
              arr.count >= 2 else {
            throw DCAPIError.invalidEncryptionInfo("Expected CBOR array with at least 2 elements")
        }

        // Format: ["dcapi", {"nonce": bytes, "recipientPublicKey": COSE_Key}]
        let cipherSuiteId: String
        switch arr[0] {
        case .utf8String(let s):
            cipherSuiteId = s
        case .unsignedInt(let v):
            cipherSuiteId = String(v)
        default:
            cipherSuiteId = "unknown"
        }

        guard case let .map(infoMap) = arr[1] else {
            throw DCAPIError.invalidEncryptionInfo("Second element is not a CBOR map")
        }

        var nonce: [UInt8]? = nil
        if let nonceCbor = infoMap[.utf8String("nonce")],
           case let .byteString(nonceBytes) = nonceCbor {
            nonce = nonceBytes
        }

        guard let rpkCbor = infoMap[.utf8String("recipientPublicKey")] else {
            throw DCAPIError.invalidEncryptionInfo("Missing 'recipientPublicKey'")
        }

        let parsedKey = try parseCOSEKey(rpkCbor)
        return ParsedEncryptionInfo(
            cipherSuiteIdentifier: cipherSuiteId,
            nonce: nonce,
            recipientPublicKey: parsedKey
        )
    }

    private static func parseCOSEKey(_ cbor: CBOR) throws -> ParsedCOSEKey {
        guard case let .map(keyMap) = cbor else {
            throw DCAPIError.invalidEncryptionInfo("COSE_Key is not a CBOR map")
        }

        // COSE_Key labels use integer keys:
        // 1 = kty, -1 = crv, -2 = x, -3 = y
        // In SwiftCBOR: -1 → .negativeInt(0), -2 → .negativeInt(1), -3 → .negativeInt(2)

        let kty: Int
        if let ktyCbor = keyMap[.unsignedInt(1)] {
            switch ktyCbor {
            case .unsignedInt(let v): kty = Int(v)
            default: throw DCAPIError.invalidEncryptionInfo("kty is not an integer")
            }
        } else {
            throw DCAPIError.invalidEncryptionInfo("Missing kty (label 1)")
        }

        let crv: Int
        if let crvCbor = keyMap[.negativeInt(0)] {
            switch crvCbor {
            case .unsignedInt(let v): crv = Int(v)
            default: throw DCAPIError.invalidEncryptionInfo("crv is not an integer")
            }
        } else {
            throw DCAPIError.invalidEncryptionInfo("Missing crv (label -1)")
        }

        guard let xCbor = keyMap[.negativeInt(1)],
              case let .byteString(xBytes) = xCbor,
              xBytes.count == 32 else {
            throw DCAPIError.invalidEncryptionInfo("Missing or invalid x coordinate (label -2)")
        }

        guard let yCbor = keyMap[.negativeInt(2)],
              case let .byteString(yBytes) = yCbor,
              yBytes.count == 32 else {
            throw DCAPIError.invalidEncryptionInfo("Missing or invalid y coordinate (label -3)")
        }

        return ParsedCOSEKey(kty: kty, crv: crv, x: xBytes, y: yBytes)
    }
}
