//
//  File.swift
//
//
//  Created by oem on 10/10/24.
//

import Foundation

class ProcessEbsiJWKFromKID {
    
    static func processJWKforEBSI(did: String?) async -> [String: Any]{
        guard let did = did else { return [:]}
        let ebsiEndPoint = "https://api-conformance.ebsi.eu/did-registry/v5/identifiers/\(did)"
        let pilotEndpoint = "https://api-pilot.ebsi.eu/did-registry/v5/identifiers/\(did)"
        
        do {
            guard let url = URL(string: ebsiEndPoint) else { return [:] }
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse else { return [:] }
            
            if httpResponse.statusCode == 200 {
                // Process the response from the first URL
                return try processPublicKeyFromJWKList(data)
            } else {
                // Call the fallback URL if the status is not 200
                return try await fetchJWKListFromUrl(pilotEndpoint)
            }
        } catch {
            print("Error fetching from primary URL: \(error)")
        }
        return [:]
    }
    
    private static func processPublicKeyFromJWKList(_ data: Data) throws -> [String: Any] {
        guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
              let verificationMethods = jsonObject["verificationMethod"] as? [[String: Any]] else { return [:] }
        
        for method in verificationMethods {
            if let publicKeyJwk = method["publicKeyJwk"] as? [String: Any],
               let crv = publicKeyJwk["crv"] as? String, crv == "P-256" {
                return publicKeyJwk
            }
        }
        return [:]
    }
    
    private static func fetchJWKListFromUrl(_ fallbackURL: String) async throws -> [String: Any] {
        guard let url = URL(string: fallbackURL) else { return [:] }
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else { return [:] }
        
        return try processPublicKeyFromJWKList(data)
    }
}

