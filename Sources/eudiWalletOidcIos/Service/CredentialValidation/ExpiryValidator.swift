//
//  File.swift
//
//
//  Created by iGrant on 25/07/24.
//
import Foundation
import SwiftCBOR
public class ExpiryValidator {
    
    public init () {}
    
    public func validateExpiryDate(jwt: String?, format: String) -> Bool? {
        var expirationDate: String = ""
        if format == "mso_mdoc" {
            if let issuerAuthData = ExpiryValidator.getIssuerAuth(credential: jwt ?? "") {
                expirationDate = ExpiryValidator.getExpiryFromIssuerAuth(cborData: issuerAuthData) ?? ""
            } else {
                return false
            }
        } else {
            guard let split = jwt?.split(separator: "."), split.count > 1,  let jsonString = "\(split[1])".decodeBase64(),
                  let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) else { return false }
            guard let vc = jsonObject["vc"] as? [String: Any], let expiryDate = vc["expirationDate"] as? String else { return false }
            expirationDate = expiryDate
        }
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        guard let expiryDate = dateFormatter.date(from: expirationDate) else { return false}
        let currentDate = Date()
        if currentDate <= expiryDate {
            return false
        } else {
            return true
        }
    }
    static func getIssuerAuth(credential: String) -> CBOR? {
        // Convert the base64 URL encoded credential to Data
        guard let data = Data(base64URLEncoded: credential) else {
            print("Invalid base64 URL encoded credential.")
            return nil
        }
        // Decode via SafeCBOR so a malformed credential that declares an
        // implausible collection length cannot trigger an allocation abort.
        if let dictionary = SafeCBOR.decode([UInt8](data)),
           let issuerAuthValue = dictionary[CBOR.utf8String("issuerAuth")] {
            return issuerAuthValue // Return the issuerAuth value directly
        }
        return nil // Return nil if "issuerAuth" is not found
    }
    
    static func getExpiryFromIssuerAuth(cborData: CBOR) -> String? {
        guard case let CBOR.array(elements) = cborData else {
            print("Expected CBOR array, but got something else.")
            return nil
        }
        var expiryValue: String? = ""
        // Decode every nested byte string via SafeCBOR. A malformed COSE_Sign1
        // element could otherwise declare an array/map length near Int.max, which
        // makes SwiftCBOR reserve that capacity before reading and abort the process
        // with a non-catchable allocation fatalError (`try?` cannot intercept it).
        for element in elements {
            if case let CBOR.byteString(byteString) = element {
                if let nestedCBOR = SafeCBOR.decode(byteString) {
                    if case let CBOR.tagged(tag, item) = nestedCBOR, tag.rawValue == 24 {
                        if case let CBOR.byteString(data) = item {
                            if let decodedInnerCBOR = SafeCBOR.decode([UInt8](data)) {
                                expiryValue = extractExpiry(cborData: decodedInnerCBOR)
                            } else {
                                print("Failed to decode inner ByteString under Tag 24.")
                            }
                        }
                    }
                } else {
                    print("Could not decode ByteString as CBOR, inspecting data directly.")
                }
            } else {
                print("Element: \(element)")
            }
        }
        return expiryValue ?? ""
    }
    
    static func extractExpiry(cborData: CBOR) -> String? {
        guard case let CBOR.map(map) = cborData else {
            return nil
        }
        for (key, value) in map {
            if case let CBOR.utf8String(keyString) = key, keyString == "validityInfo" {
                if case let CBOR.map(validityMap) = value {
                    for (validityKey, validityValue) in validityMap {
                        if case let CBOR.utf8String(validityKeyString) = validityKey, validityKeyString == "validUntil" {
                            if case let CBOR.tagged(_, CBOR.utf8String(validUntilString)) = validityValue {
                                return validUntilString
                            } else {
                                print("The value associated with 'validUntil' is not in the expected format.")
                            }
                        }
                    }
                } else {
                    print("The value associated with 'validityInfo' is not a map.")
                }
            }
        }
        print("validityInfo not found in the CBOR map.")
        return nil
    }
    
}
