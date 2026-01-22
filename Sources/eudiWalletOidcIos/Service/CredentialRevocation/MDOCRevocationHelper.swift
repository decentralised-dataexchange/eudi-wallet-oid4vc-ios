//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 22/01/26.
//

import Foundation
import SwiftCBOR
import OrderedCollections

class MDOCRevocationHelper {
    
    public init() {}
    
    func cborToAny(_ cbor: CBOR) -> Any {
        switch cbor {

        case .map(let map):
            var dict: [String: Any] = [:]
            for (key, value) in map {
                if case let .utf8String(k) = key {
                    dict[k] = cborToAny(value)
                }
            }
            return dict

        case .array(let array):
            return array.map { cborToAny($0) }

        case .utf8String(let string):
            return string

        case .unsignedInt(let uint):
            return Int(uint)

        case .negativeInt(let int):
            return Int(int)

        case .boolean(let bool):
            return bool

        case .double(let double):
            return double

        case .float(let float):
            return Double(float)

        case .null:
            return NSNull()

        default:
            return "\(cbor)"   // fallback for unsupported types
        }
    }

    func getStatusFromIssuerAuth(cborData: CBOR) ->  [String: Any]? {
        guard case let CBOR.array(elements) = cborData else {
            return nil
        }
        var status:  [String: Any]?  = [:]
        for element in elements {
            if case let CBOR.byteString(byteString) = element {
                if let nestedCBOR = try? CBOR.decode(byteString) {
                    if case let CBOR.tagged(tag, item) = nestedCBOR, tag.rawValue == 24 {
                        if case let CBOR.byteString(data) = item {
                            if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)) {
                                status = extractStatus(cborData: decodedInnerCBOR )
                            } else {
                                print("Failed to decode inner ByteString under Tag 24.")
                            }
                        }
                    }
                }
            }
        }
        return status ?? [:]
    }
    
    func extractStatus(cborData: CBOR) -> [String: Any]? {
        guard case let CBOR.map(map) = cborData else {
            return nil
        }
        for (key, value) in map {
            if case let CBOR.utf8String(keyString) = key, keyString == "status" {
                if case let CBOR.map(statusMap) = value {
                    for (statusKey, statusValue) in statusMap {
                        let statusDict = cborToAny(statusValue) as? [String: Any]
                        return statusDict
                    }
                }
            }
        }
        return nil
    }
    
}
