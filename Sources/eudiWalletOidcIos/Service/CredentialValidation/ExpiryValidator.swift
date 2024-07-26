//
//  File.swift
//
//
//  Created by iGrant on 25/07/24.
//

import Foundation

class ExpiryValidator {

    static func validateExpiryDate(jwt: String?) -> Bool? {
        guard let split = jwt?.split(separator: "."),
              let jsonString = "\(split[1])".decodeBase64(),
              let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) else { return false }
        guard let vc = jsonObject["vc"] as? [String: Any], let expirationDate = vc["expirationDate"] as? String else { return false }
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
    
}
