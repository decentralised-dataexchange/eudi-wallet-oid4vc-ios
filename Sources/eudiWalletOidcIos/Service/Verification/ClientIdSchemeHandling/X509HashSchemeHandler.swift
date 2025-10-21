//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 21/10/25.
//

import Foundation
import Crypto
import CryptoKit

class X509HashSchemeHandler: ClientIdSchemeHandler {
    
    public func validate(presentationRequest: PresentationRequest, jwtRequest: String?) async throws -> Bool? {
        // Extract x5c certificate chain from the JWT
        let x5cData = X509SanRequestVerifier.shared.extractX5cFromJWT(jwt: jwtRequest ?? "") ?? []
     guard let leafCertData = Data(base64Encoded: x5cData.first ?? "") else {
            return false
        }
        // Extract the client ID suffix (after colon) and validate against x5c
        let clientID = ClientIdSchemeRequestHandler().getClientIDFromClientID(afterColon: presentationRequest.clientId ?? "") ?? ""
        let computedHash = sha256Base64URL(of: leafCertData)
        
         let isHashValid = computedHash == clientID

        // Validate the certificate trust chain
        let isTrustChainValid = X509SanRequestVerifier.shared.validateTrustChain(x5cChain: x5cData)

        // Validate the JWT's signature using the x5c certificate
        let isSignValid = X509SanRequestVerifier.shared.validateSignatureWithCertificate(
            jwt: jwtRequest ?? "",
            x5cChain: x5cData
        )

        // Return true only if all validations pass
        if isHashValid && isTrustChainValid && isSignValid {
            return true
        } else {
            return false
        }
    }
    
    public func update(presentationRequest: PresentationRequest, jwtRequest: String?) -> PresentationRequest {
        var updated = presentationRequest
        
        return updated
    }
    
    private func sha256Base64URL(of data: Data) -> String {
        let hash = SHA256.hash(data: data)
        let hashData = Data(hash)
        return base64URLEncode(hashData)
    }
    
    private func base64URLEncode(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
}
