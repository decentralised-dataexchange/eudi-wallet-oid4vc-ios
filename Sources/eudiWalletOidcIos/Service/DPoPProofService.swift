//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 28/04/26.
//

import Foundation
import CryptoKit

class DPoPProofService {
    
      /// Generates a DPoP proof JWT for the given token endpoint.
      /// A fresh P-256 key pair is created for each call and the public key is embedded as a JWK in the header.
     static func generateProof(tokenEndpoint: String, httpMethod: String = "POST", dpopKey: P256.Signing.PrivateKey?, claims: [String: Any] = [:]) -> String? {
            guard let privateKey = dpopKey else { return nil}
            let publicKeyRaw = privateKey.publicKey.rawRepresentation
            guard publicKeyRaw.count == 64 else { return nil }
            let x = Data(publicKeyRaw.prefix(32))
            let y = Data(publicKeyRaw.suffix(32))
            let kid = "\(UUID().uuidString)_dpop"
        
            let jwk: [String: Any] = [
                  "alg": "ES256",
                  "crv": "P-256",
                  "kid": kid,
                  "kty": "EC",
                  "use": "sig",
                  "x": x.urlSafeBase64EncodedString(),
                  "y": y.urlSafeBase64EncodedString()
                ]
        
            let header: [String: Any] = [
                  "alg": "ES256",
                  "jwk": jwk,
                  "typ": "dpop+jwt"
                ]
        
        var payload: [String: Any] = [
                  "iat": Int(Date().timeIntervalSince1970),
                  "htu": tokenEndpoint,
                  "htm": httpMethod,
                  "jti": UUID().uuidString
                ]
        // Merge extra claims into payload
           claims.forEach { payload[$0.key] = $0.value }
            guard
              let headerData = try? JSONSerialization.data(withJSONObject: header),
              let payloadData = try? JSONSerialization.data(withJSONObject: payload)
            else { return nil }
        
            let signingInput = "\(headerData.urlSafeBase64EncodedString()).\(payloadData.urlSafeBase64EncodedString())"
            guard
              let signingBytes = signingInput.data(using: .utf8),
              let signature = try? privateKey.signature(for: signingBytes)
            else { return nil }
        
            let jwt = "\(signingInput).\(signature.rawRepresentation.urlSafeBase64EncodedString())"
            print("[DPoP] generated for htu=\(tokenEndpoint) htm=\(httpMethod) jti=\(payload["jti"] ?? "")")
            print("[DPoP] jwt=\(jwt)")
            return jwt
          }
    
    static func computeAccessTokenHash(token: String) -> String {
        let tokenData = Data(token.utf8) // US-ASCII is subset of UTF-8
        let hash = SHA256.hash(data: tokenData)
        let hashData = Data(hash)
        return hashData.urlSafeBase64EncodedString()
    }
    
}
