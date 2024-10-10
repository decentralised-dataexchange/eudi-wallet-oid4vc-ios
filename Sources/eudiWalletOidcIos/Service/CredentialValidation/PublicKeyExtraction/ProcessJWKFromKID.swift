//
//  File.swift
//  
//
//  Created by oem on 10/10/24.
//

import Foundation

class ProcessJWKFromKID {
    static func parseDIDJWK(_ didJwk: String) -> [String: Any]? {
        guard didJwk.hasPrefix("did:jwk:") else {
            return nil
        }
        
        let base64UrlValue = didJwk.replacingOccurrences(of: "did:jwk:", with: "")
        
        guard let jsonString = base64UrlValue.decodeBase64(),
              let jsonData = jsonString.data(using: .utf8),
              let jwk = try? JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] else {
            return nil
        }
        
        return jwk
    }
}
