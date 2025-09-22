//
//  File.swift
//
//
//  Created by oem on 10/10/24.
//

import Foundation
import Base58Swift

class ProcessWebJWKFromKID {
    static func fetchDIDDocument(did: String) async throws -> [String: Any]? {
        guard did.hasPrefix("did:web:") else { return nil }
        var publicKeyJwk: [String: Any]? = [:]
        let didWithoutPrefix = did.replacingOccurrences(of: "did:web:", with: "")
        let pathAndFragment = didWithoutPrefix.split(separator: "#").first ?? ""
        let didParts = pathAndFragment.split(separator: ":")
        
        guard didParts.count > 1 else { return nil }
        
        let host = didParts[0]
        let path = didParts.dropFirst().joined(separator: "/")
        var didDocURLString: String = ""
        if path == nil || path == "" {
            didDocURLString = "https://\(host)/.well-known/did.json"
        } else {
            didDocURLString = "https://\(host)/\(path)/did.json"
        }
        
        guard let didDocURL = URL(string: didDocURLString) else { return nil }
        
        let (data, response) = try await URLSession.shared.data(from: didDocURL)
        
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            return nil
        }
        
        let didDoc = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        if let verificationMethod = didDoc?["verificationMethod"] as? [[String: Any]] {
            for (index, item) in verificationMethod.enumerated(){
                if item["id"] as? String == did {
                    publicKeyJwk = verificationMethod[index]["publicKeyJwk"] as? [String: Any]
                }
            }
        }
        
        // Fallback: if no JWK found, pick first with publicKeyBase58
        if publicKeyJwk == nil {
            if let verificationMethod = didDoc?["verificationMethod"] as? [[String: Any]] {
                if let firstBase58Item = verificationMethod.first(where: { $0["publicKeyBase58"] != nil }) {
                    if let publicKeyBase58 = firstBase58Item["publicKeyBase58"] as? String {
                        if let pubBytes = Base58.base58Decode(publicKeyBase58) {
                            let pubData = Data(pubBytes)
                            let x = pubData.base64URLEncodedString()
                            
                            // Construct a JWK dictionary
                            publicKeyJwk = [
                                "kty": "OKP",
                                "crv": "Ed25519",
                                "x": x
                            ]
                        }
                    }
                    
                }
            }
        }
        
        return publicKeyJwk
    }
}
