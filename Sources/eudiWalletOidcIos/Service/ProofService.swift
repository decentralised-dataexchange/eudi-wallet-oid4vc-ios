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
    
    static func generateProof(nonce: String, credentialOffer: CredentialOffer, issuerConfig: IssuerWellKnownConfiguration, did: String, keyHandler: SecureKeyProtocol, credentialTypes: [String], keyAttestation: String? = nil) async -> String? {
        // Resolve the key ONCE. generateSecureKey() is load-or-create, so every
        // extra call is a chance to mint a replacement rather than observe the
        // existing key - which would both change what gets signed and make any
        // logging report a key that did not sign anything.
        let secureData = await keyHandler.generateSecureKey()
        let signingJwk = keyHandler.getJWK(publicKey: secureData?.publicKey ?? Data())
        let cryptographicBindingMethodsSupported = getCryptographicBindingMethodsFromIssuerConfig(issuerConfig: issuerConfig, type: credentialTypes.last)
        // Generate JWT Header
        var header = ([
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256"
        ]) as [String : Any]

        if let didBindingMethod = cryptographicBindingMethodsSupported.first(where: { $0.starts(with: "did") }) {
            let keyId = generateKeyId(credentialOffer: credentialOffer, bindingMethod: didBindingMethod, did: did, keyHandler: keyHandler, signingJwk: signingJwk)
            header["kid"] = keyId
        } else if credentialOffer.credentials?.first?.trustFramework != nil {
            let keyId = generateKeyId(credentialOffer: credentialOffer, bindingMethod: cryptographicBindingMethodsSupported.first ?? "", did: did, keyHandler: keyHandler, signingJwk: signingJwk)
            header["kid"] = keyId
        } else  {
            header["jwk"] = signingJwk
        }

        // ARF TS3 v1.5: the wallet-provider Key Attestation travels in the
        // key_attestation JOSE header of the jwt proof.
        if let keyAttestation = keyAttestation, !keyAttestation.isEmpty {
            header["key_attestation"] = keyAttestation
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
        guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.privateKey) else{return nil}
        // TS3 2.2.2.1: a jwt proof carrying a key attestation SHALL be signed with
        // the key at index 0 of attested_keys. A proof that breaks that is rejected
        // by every issuer, so sending it only buys a generic error one round trip
        // later - and that is how this last went unnoticed: the wallet built a proof
        // it could already tell was doomed and sent it anyway.
        if let keyAttestation = keyAttestation, !keyAttestation.isEmpty,
           let attestedX = jwtSegment(keyAttestation, 1)?["attested_keys"] as? [[String: Any]],
           let firstAttested = attestedX.first?["x"] as? String,
           let signingX = signingJwk?["x"] as? String,
           firstAttested != signingX {
            return nil
        }
        return idToken
    }

    private static func short(_ value: String?) -> String {
        guard let value = value, !value.isEmpty else { return "<none>" }
        return value.count <= 12 ? value : String(value.prefix(12)) + "…"
    }

    private static func jsonObject(_ text: String) -> [String: Any]? {
        guard let data = text.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    private static func jwtSegment(_ jwt: String, _ index: Int) -> [String: Any]? {
        let parts = jwt.split(separator: ".")
        guard parts.count > index else { return nil }
        var s = String(parts[index])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        guard let data = Data(base64Encoded: s) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
    
    static func generateKeyId(credentialOffer: CredentialOffer,
                              bindingMethod: String, did: String, keyHandler: SecureKeyProtocol,
                              signingJwk: [String: Any]? = nil) -> String? {

        var keyId: String? = nil
        let methodSpecificId = did.replacingOccurrences(of: "did:key:", with: "")
        if bindingMethod == "did:jwk" {
            guard let jwk = signingJwk ?? keyHandler.getJWK(publicKey: keyHandler.generateSecureKey()?.publicKey ?? Data()) else { return nil }
            let base64JWK = base64URLEncodeJWK(jwk) ?? ""
            keyId = "did:jwk:\(base64JWK)"
        } else if bindingMethod == "jwk" {
            let jwk = signingJwk ?? keyHandler.getJWK(publicKey: keyHandler.generateSecureKey()?.publicKey ?? Data())
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
