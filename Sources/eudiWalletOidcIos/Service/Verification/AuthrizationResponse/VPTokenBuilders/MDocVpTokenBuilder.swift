//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation
import SwiftCBOR
import OrderedCollections

/// CBOR helpers for mdoc credentials. The presentation itself is built by `MdocVpTokenBuilder`
/// in `Verification/Presentation/`.
public class MDocVpTokenBuilder {
    public init() {}
    
    /// The device key an mdoc is bound to: `deviceKeyInfo.deviceKey` of the MSO
    /// in `issuerAuth`, as JWK coordinates (`x`, `y`, base64url). The mdoc
    /// counterpart of an SD-JWT's `cnf.jwk`, for pairing a batch of mdocs with
    /// the keys they were requested for. Nil when it cannot be read.
    public func extractDeviceKeyFromIssuerSigned(credential: String) -> [String: String]? {
        guard case let .array(elements)? = getIssuerAuth(credential: credential), elements.count > 2,
              case let .byteString(payload) = elements[2],
              let tagged = try? CBOR.decode(payload),
              case let .tagged(tag, .byteString(msoBytes)) = tagged, tag.rawValue == 24,
              let mso = try? CBOR.decode(msoBytes),
              case let .map(deviceKeyInfo)? = mso[.utf8String("deviceKeyInfo")],
              case let .map(coseKey)? = deviceKeyInfo[.utf8String("deviceKey")],
              // COSE_Key labels: -2 = x, -3 = y (CBOR negative n encodes -1-n).
              case let .byteString(x)? = coseKey[.negativeInt(1)],
              case let .byteString(y)? = coseKey[.negativeInt(2)] else { return nil }
        return ["x": Data(x).base64URLEncodedString(), "y": Data(y).base64URLEncodedString()]
    }

    public func getIssuerAuth(credential: String) -> CBOR? {
        if let data = Data(base64URLEncoded: credential) {
            do {
                let decodedCBOR = try CBOR.decode([UInt8](data))
                
                if let dictionary = decodedCBOR {
                    if let issuerAuthValue = dictionary[CBOR.utf8String("issuerAuth")] {
                        return issuerAuthValue
                    }
                }
            } catch {
                print("Error decoding CBOR: \(error)")
                return nil
            }
        } else {
            print("Invalid base64 URL encoded credential.")
            return nil
        }
        
        return nil
    }
    
    func getNameSpaces(credential: String, query: Any?) -> CBOR? {
        var requestedParamse: [String] = []
        if let inputDescriptor = query as? InputDescriptor, let fields = inputDescriptor.constraints?.fields {
            for field in fields {
                let components = field.path?.first?.components(separatedBy: ["[", "]", "'"])
                
                let filteredComponents = components?.filter { !$0.isEmpty }
                
                if let identifier = filteredComponents?.last {
                    requestedParamse.append(String(identifier))
                }
            }
        } else if let dcql = query as? CredentialItems {
        }
        // Convert the base64 URL encoded credential to Data
        if let data = Data(base64URLEncoded: credential) {
            do {
                // Decode the CBOR data into a dictionary
                let decodedCBOR = try CBOR.decode([UInt8](data))
                
                if let dictionary = decodedCBOR {
                    // Check for the presence of "issuerAuth" in the dictionary
                    if let issuerAuthValue = dictionary[CBOR.utf8String("nameSpaces")] {
                        return issuerAuthValue // Return the issuerAuth value directly
                    }
                }
            } catch {
                print("Error decoding CBOR: \(error)")
                return nil
            }
        } else {
            print("Invalid base64 URL encoded credential.")
            return nil
        }
        
        return nil // Return nil if "issuerAuth" is not found
    }
    
    public func filterNameSpaces(nameSpacesValue: CBOR, requestedParams: [String]) -> CBOR? {
        if case let CBOR.map(nameSpaces) = nameSpacesValue {
            var filteredNameSpaces: OrderedDictionary<CBOR, CBOR> = [:]
            for (key, namespaceValue) in nameSpaces {
                var valuesArray: [CBOR] = []
                
                if case let CBOR.array(orgValues) = namespaceValue {
                    for value in orgValues {
                        if case let CBOR.tagged(tag, taggedValue) = value, tag.rawValue == 24 {
                            if case let CBOR.byteString(byteString) = taggedValue {
                                let data = Data(byteString)
                                if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)),
                                   case let CBOR.map(decodedMap) = decodedInnerCBOR {
                                    if let identifier = decodedMap[CBOR.utf8String("elementIdentifier")],
                                       let value = decodedMap[CBOR.utf8String("elementValue")],
                                       case let CBOR.utf8String(identifierString) = identifier {
                                        if requestedParams.contains(identifierString) {
                                            valuesArray.append(CBOR.tagged(tag, CBOR.byteString(byteString)))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                if !valuesArray.isEmpty {
                    filteredNameSpaces[key] = CBOR.array(valuesArray)
                }
            }
            return CBOR.map(filteredNameSpaces)
        }
        
        return nil
    }
    
    public func getDocTypeFromIssuerAuth(cborData: CBOR) -> String? {
        guard case let .array(elements) = cborData else { return nil }
        
        for element in elements {
            guard case let .byteString(byteString) = element else { continue }
            guard let nested = try? CBOR.decode(byteString) else { continue }
            guard case let .tagged(tag, item) = nested, tag.rawValue == 24 else { continue }
            guard case let .byteString(innerBytes) = item else { continue }
            guard let decodedInner = try? CBOR.decode(innerBytes) else { continue }
            
            if let type = extractDocType(cborData: decodedInner), !type.isEmpty {
                return type
            }
        }
        return nil
    }
    
    func extractDocType(cborData: CBOR) -> String? {
        guard case let CBOR.map(map) = cborData else {
            return nil
        }
        
        // Iterate over the map to find the key 'docType'
        for (key, value) in map {
            if case let CBOR.utf8String(keyString) = key, keyString == "docType" {
                if case let CBOR.utf8String(docTypeValue) = value {
                    return docTypeValue
                } else {
                    print("The value associated with 'docType' is not a string.")
                }
            }
        }
        
        print("docType not found in the CBOR map.")
        return nil
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
    
    func buildFullJWK(publicJWK: [String: Any], privateKeyData: Data) -> [String: Any] {
        var fullJWK = publicJWK
        // Base64URL-encode the raw private scalar
        let dBase64 = privateKeyData.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        fullJWK["d"] = dBase64
        return fullJWK
    }
    
    func convertCBORtoJson(credential: String) -> String? {
        if let data = Data(base64URLEncoded: credential) {
            do {
                let decodedCBOR = try CBOR.decode([UInt8](data))
                if let dictionary = decodedCBOR {
                    
                    if let nameSpacesValue = dictionary[CBOR.utf8String("nameSpaces")],
                       case let CBOR.map(nameSpaces) = nameSpacesValue {
                        
                        var resultDict: [String: [String: String]] = [:]
                        for (key, namespaceValue) in nameSpaces {
                            var valuesDict: [String: String] = [:]
                            if case let CBOR.array(orgValues) = namespaceValue {
                                for value in orgValues {
                                    if case let CBOR.tagged(tag, taggedValue) = value, tag.rawValue == 24 {
                                        if case let CBOR.byteString(byteString) = taggedValue {
                                            let data = Data(byteString)
                                            
                                            if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)),
                                               case let CBOR.map(decodedMap) = decodedInnerCBOR {
                                                if let identifier = decodedMap[CBOR.utf8String("elementIdentifier")],
                                                   let value = decodedMap[CBOR.utf8String("elementValue")],
                                                   case let CBOR.utf8String(identifierString) = identifier {
                                                    
                                                    valuesDict[identifierString] = cborToString(value)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            resultDict[cborToString(key)] = valuesDict
                        }
                        
                        // Convert the result dictionary to JSON
                        let jsonData = try JSONSerialization.data(withJSONObject: resultDict, options: .prettyPrinted)
                        let jsonString = String(data: jsonData, encoding: .utf8)
                        return jsonString?.replacingOccurrences(of: "\n", with: "")
                    } else {
                        print("Key 'nameSpaces' not found or not a valid map.")
                    }
                }
            } catch {
                print("Error decoding CBOR: \(error)")
            }
        }
        return nil
    }
    
    func cborToString(_ cbor: CBOR) -> String {
        switch cbor {
        case .utf8String(let stringValue):
            return stringValue
        case .unsignedInt(let uintValue):
            return String(uintValue)
        case .negativeInt(let intValue):
            return String(intValue)
        case .boolean(let boolValue):
            return String(boolValue)
        case .null:
            return "null"
        case .float(let floatValue):
            return String(floatValue)
        case .double(let doubleValue):
            return String(doubleValue)
     case .map(let dict):
        var result: [String] = []
        for (key, value) in dict {
            let keyString = cborToString(key)
            let valueString = cborToString(value)
            result.append("\"\(keyString)\": \"\(valueString)\"")
        }
        return "{\(result.joined(separator: ", "))}"
        default:
            return "Unsupported CBOR type"
        }
    }
    
}
