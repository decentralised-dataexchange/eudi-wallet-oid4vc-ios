//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 14/04/26.
//

import Foundation
import JOSESwift
import CryptoKit

class VerifierJwk {
    
    func deriveVerifiersJWKFromClientMetadata(presentationRequest: PresentationRequest?) async -> [String: Any]? {
        let jwk: [String: Any]
        var clientMetaData: [String: Any] = [:]
        if let clientMetaDataString = presentationRequest?.clientMetaData, let dataObject = clientMetaDataString.data(using: .utf8) {
            do {
                let dict = try JSONSerialization.jsonObject(with: dataObject, options: []) as? [String: Any]
                clientMetaData = dict ?? [:]
            } catch {
                print("")
            }
        }
        let supportedEncryptions = clientMetaData["encrypted_response_enc_values_supported"] as? [String]
        if let jwksURI = clientMetaData["jwks_uri"] as? String {
            jwk = try await fetchJWKFromURI(jwksURI)
        } else if let jwks = clientMetaData["jwks"] as? [String: Any],
                  let keys = jwks["keys"] as? [[String: Any]],
                  let p256Key = keys.first(where: { $0["crv"] as? String == "P-256" }) {
            jwk = p256Key
        } else {
            return nil
        }
        
        return jwk
    }
    
    private func fetchJWKFromURI(_ uri: String) async -> [String: Any] {
        return await ProcessJWKFromJwksUri.fetchJwkData(kid: nil, jwksUri: uri, keyUse: "enc")
    }
    
}
