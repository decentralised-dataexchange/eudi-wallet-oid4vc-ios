//
//  File.swift
//  eudi-wallet-oid4vc-ios
//
//  Created by iGrant on 22/08/25.
//

import Foundation
import CryptoKit
import PresentationExchangeSdkiOS
import SwiftCBOR
import OrderedCollections
import Security
import ASN1Decoder

protocol CustomCborConvertible {
    func toCBOR() -> CBOR
}

public struct DeviceResponse :CustomCborConvertible{
    let version: String
    let documents: [Document]?
    let status: Int
    
    enum Keys: String {
        case version
        case documents
        case status
    }
    
    init(version: String? = nil, documents: [Document]? = nil, status: Int) {
        self.version = version ?? "1.0"
        self.documents = documents
        self.status = status
    }
    
    func toDictionary() -> [String: Any] {
        var dict: [String: Any] = [:]
        dict["version"] = version
        dict["documents"] = documents
        dict["status"] = status
        return dict
    }
    
    func encodeToCBOR(_ dict: [String: Any]) -> CBOR? {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        
        for (key, value) in dict {
            let cborKey = CBOR.utf8String(key)
            
            // Handle different value types
            if let stringValue = value as? String {
                if stringValue == "NULL" {
                    cborMap[cborKey] = CBOR.null
                } else if stringValue.contains("ByteString") {
                    // Handle ByteString placeholder
                    cborMap[cborKey] = CBOR.byteString([0x01, 0x02, 0x03]) // Example ByteString, customize as needed
                } else {
                    cborMap[cborKey] = CBOR.utf8String(stringValue)
                }
            } else if let intValue = value as? Int {
                if intValue >= 0 {
                    cborMap[cborKey] = CBOR.unsignedInt(UInt64(intValue))
                } else {
                    cborMap[cborKey] = CBOR.negativeInt(UInt64(-1 - intValue))
                }
            } else if let floatValue = value as? Float {
                cborMap[cborKey] = CBOR.float(floatValue)
            } else if let doubleValue = value as? Double {
                cborMap[cborKey] = CBOR.double(doubleValue)
            } else if let boolValue = value as? Bool {
                cborMap[cborKey] = CBOR.boolean(boolValue)
            } else if let arrayValue = value as? [Any] {
                cborMap[cborKey] = encodeArrayToCBOR(arrayValue)
            } else if let dictValue = value as? [String: Any] {
                if let encodedDict = encodeToCBOR(dictValue) {
                    cborMap[cborKey] = encodedDict
                }
            } else if let cborValue = value as? SwiftCBOR.CBOR {
                // Handle CBOR types directly
                cborMap[cborKey] = cborValue
            } else if let customObject = value as? CustomCborConvertible {
                // Handle custom objects that conform to CustomCborConvertible
                cborMap[cborKey] = customObject.toCBOR()
            } else {
                print("Unsupported type for key: \(key)")
                return nil
            }
        }
        
        return CBOR.map(cborMap)
    }
    
    func encodeArrayToCBOR(_ array: [Any]) -> CBOR {
        var cborArray: [CBOR] = []
        
        for value in array {
            if let stringValue = value as? String {
                if stringValue == "NULL" {
                    cborArray.append(CBOR.null)
                } else if stringValue.contains("ByteString") {
                    cborArray.append(CBOR.byteString([0x01, 0x02, 0x03])) // Example ByteString
                } else {
                    cborArray.append(CBOR.utf8String(stringValue))
                }
            } else if let intValue = value as? Int {
                if intValue >= 0 {
                    cborArray.append(CBOR.unsignedInt(UInt64(intValue)))
                } else {
                    cborArray.append(CBOR.negativeInt(UInt64(-1 - intValue)))
                }
            } else if let floatValue = value as? Float {
                cborArray.append(CBOR.float(floatValue))
            } else if let boolValue = value as? Bool {
                cborArray.append(CBOR.boolean(boolValue))
            } else if let dictValue = value as? [String: Any], let encodedDict = encodeToCBOR(dictValue) {
                cborArray.append(encodedDict)
            } else if let subArray = value as? [Any] {
                cborArray.append(encodeArrayToCBOR(subArray))
            } else if let cborValue = value as? SwiftCBOR.CBOR {
                // Handle CBOR values directly
                cborArray.append(cborValue)
            } else if let customObject = value as? CustomCborConvertible {
                // Handle custom objects
                cborArray.append(customObject.toCBOR())
            } else {
                print("Unsupported type in array")
                return CBOR.null
            }
        }
        
        return CBOR.array(cborArray)
    }
    
    func toCBOR() -> CBOR {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        cborMap[CBOR.utf8String("version")] = CBOR.utf8String(version)
        
        if let documents = documents {
            cborMap[CBOR.utf8String("documents")] = encodeArrayToCBOR(documents.map { $0.toCBOR() })
        }
        
        cborMap[CBOR.utf8String("status")] = CBOR.unsignedInt(UInt64(status))
        
        return CBOR.map(cborMap)
    }
}

public struct Document : CustomCborConvertible{
    
    let docType: String
    let issuerSigned: IssuerSigned
    let deviceSigned: DeviceSigned?
    
    enum Keys:String {
        case docType
        case issuerSigned
        case deviceSigned
    }
    
    init(docType: String, issuerSigned: IssuerSigned, deviceSigned: DeviceSigned? = nil) {
        self.docType = docType
        self.issuerSigned = issuerSigned
        self.deviceSigned = deviceSigned
    }
    
    func toCBOR() -> CBOR {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        cborMap[CBOR.utf8String("docType")] = CBOR.utf8String(docType)
        
        cborMap[CBOR.utf8String("issuerSigned")] = issuerSigned.toCBOR()
        
        if let deviceSigned = deviceSigned {
            cborMap[CBOR.utf8String("deviceSigned")] = deviceSigned.toCBOR()
        }
        
        return CBOR.map(cborMap)
    }
}

// Model for IssuerSigned part
struct IssuerSigned : CustomCborConvertible{
    let nameSpaces: SwiftCBOR.CBOR // Using ByteString struct here
    let issuerAuth: SwiftCBOR.CBOR
    
    init(nameSpaces: SwiftCBOR.CBOR, issuerAuth: SwiftCBOR.CBOR) {
        self.nameSpaces = nameSpaces
        self.issuerAuth = issuerAuth
    }
    
    func toCBOR() -> CBOR {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        cborMap[CBOR.utf8String("nameSpaces")] = nameSpaces
        cborMap[CBOR.utf8String("issuerAuth")] = issuerAuth
        
        return CBOR.map(cborMap)
    }
}

struct DeviceSigned: CustomCborConvertible {

    let nameSpaces: CBOR
    let deviceAuth: CBOR

    init(nameSpaces: CBOR, deviceAuth: CBOR) {
        self.nameSpaces = nameSpaces
        self.deviceAuth = deviceAuth
    }

    func toCBOR() -> CBOR {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        cborMap[.utf8String("nameSpaces")] = nameSpaces
        cborMap[.utf8String("deviceAuth")]  = deviceAuth
        return .map(cborMap)
    }
}
