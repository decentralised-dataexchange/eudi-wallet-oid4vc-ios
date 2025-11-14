//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 02/04/25.
//

import Foundation
import Crypto
import CryptoKit
import JOSESwift

class ProofService {
    
    static func generateProof(nonce: String, credentialOffer: CredentialOffer, issuerConfig: IssuerWellKnownConfiguration, did: String, keyHandler: SecureKeyProtocol, credentialTypes: [String]) async -> String? {
        let cryptographicBindingMethodsSupported = getCryptographicBindingMethodsFromIssuerConfig(issuerConfig: issuerConfig, type: credentialTypes.last)
        let keyId = generateKeyId(credentialOffer: credentialOffer, bindingMethod: cryptographicBindingMethodsSupported, did: did, keyHandler: keyHandler)
        // Generate JWT Header
        
        var header = ([
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256"
        ]) as [String : Any]
        
        if cryptographicBindingMethodsSupported.contains("jwk") {
            header["jwk"] = keyHandler.getJWK(publicKey: keyHandler.generateSecureKey()?.publicKey ?? Data())
        } else  {
            header["kid"] = keyId
        }
        
        let headerString = header.toString() ?? ""
        
        // Generate JWT payload
        let currentTime = Int(Date().epochTime) ?? 0
        let payload = ([
            "iss": did,
            "iat": currentTime,
            "aud": "\(credentialOffer.credentialIssuer ?? "")",
            "exp": currentTime + 86400,
            "nonce": "\(nonce)"
        ] as [String : Any]).toString() ?? ""
        let headerData = Data(headerString.utf8)
        let secureData = await keyHandler.generateSecureKey()
        guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.privateKey) else{return nil}
        return idToken
    }
    
    static func generateKeyId(credentialOffer: CredentialOffer,
                              bindingMethod: [String], did: String, keyHandler: SecureKeyProtocol) -> String? {
        
        var keyId: String? = nil
        let methodSpecificId = did.replacingOccurrences(of: "did:key:", with: "")
        if bindingMethod.contains("did:jwk") {
            guard let jwk = keyHandler.getJWK(publicKey: keyHandler.generateSecureKey()?.publicKey ?? Data()) else { return nil }
            let base64JWK = base64URLEncodeJWK(jwk) ?? ""
            keyId = "did:jwk:\(base64JWK)"
        } else if bindingMethod.contains("jwk") {
            let jwk = keyHandler.getJWK(publicKey: keyHandler.generateSecureKey()?.publicKey ?? Data())
            do {
                let jsonData = try JSONSerialization.data(withJSONObject: jwk, options: [.sortedKeys])
                let sha256 = SHA256.hash(data: jsonData)
                let thumbprint = Data(sha256).base64URLEncodedString()
                keyId = thumbprint
            } catch {
                print("Error generating thumbprint: \(error)")
                return nil
            }
        } else {
            keyId = "\(did)#\(methodSpecificId)"
        }
        return keyId
    }
    
    static func getCryptographicBindingMethodsFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> [String] {
        guard let issuerConfig = issuerConfig else { return [] }
        
        if let credentialSupported = issuerConfig.credentialsSupported?.dataSharing?[type ?? ""] {
            return credentialSupported.cryptographicBindingMethodsSupported ?? []
        } else {
            return []
        }
    }
    
    static func base64URLEncodeJWK(_ jwk: [String: Any]) -> String? {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: jwk, options: []) else {
            return nil
        }
        
        let base64String = jsonData.base64EncodedString()
        
        let base64URLString = base64String
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        
        return base64URLString
    }
    
}
