//
//  File.swift
//
//
//  Created by iGrant on 25/07/24.
//

import Foundation
import SwiftCBOR


class ExpiryValidator {

    static func validateExpiryDate(jwt: String?, format: String) -> Bool? {
    var expirationDate: String = ""
    if format == "mso_mdoc" {
        if let issuerAuthData = getIssuerAuth(credential: jwt ?? "") {
            expirationDate = getExpiryFromIssuerAuth(cborData: issuerAuthData) ?? ""
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
        if let data = Data(base64URLEncoded: credential) {
            do {
                // Decode the CBOR data into a dictionary
                let decodedCBOR = try CBOR.decode([UInt8](data))
                
                if let dictionary = decodedCBOR {
                    // Check for the presence of "issuerAuth" in the dictionary
                    if let issuerAuthValue = dictionary[CBOR.utf8String("issuerAuth")] {
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


static  func getExpiryFromIssuerAuth(cborData: CBOR) -> String? {
    guard case let CBOR.array(elements) = cborData else {
        print("Expected CBOR array, but got something else.")
        return nil
    }
    var docType: String? = ""
    for element in elements {
        if case let CBOR.byteString(byteString) = element {
            if let nestedCBOR = try? CBOR.decode(byteString) {
        if case let CBOR.tagged(tag, item) = nestedCBOR, tag.rawValue == 24 {
            if case let CBOR.byteString(data) = item {
                if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)) {
            docType = extractExpiry(cborData: decodedInnerCBOR )
                } else {
                    print("Failed to decode inner ByteString under Tag 24.")
                }
            }
        }
            } else {
                print("Could not decode ByteString as CBOR, inspecting data directly.")
                print("ByteString data: \(byteString)")
            }
        } else {
            print("Element: \(element)")
        }
    }
    return docType ?? ""
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
