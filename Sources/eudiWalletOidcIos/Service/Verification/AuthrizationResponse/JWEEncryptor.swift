//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation
import JOSESwift
import CryptoKit

class JWEEncryptor {

    func encrypt(
        payload: [String: Any],
        presentationRequest: PresentationRequest?
    ) async throws -> String {
        
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
                  let keys = jwks["keys"] as? [[String: Any]] {
            // Among P-256 keys prefer an explicit encryption key (use=enc), then a
            // key with no `use`. Never a signing key: a verifier may publish both a
            // sig and an enc P-256 key in the same set, and encrypting the response
            // to the sig key leaves it unable to decrypt - which it reports as a
            // rejected response, not as a key problem. The jwks_uri branch above
            // already asks for keyUse "enc"; this branch did not, and took whichever
            // P-256 key happened to come first.
            let p256Keys = keys.filter { $0["crv"] as? String == "P-256" }
            if let encKey = p256Keys.first(where: { ($0["use"] as? String) == "enc" }) {
                jwk = encKey
            } else if let noUseKey = p256Keys.first(where: { $0["use"] == nil }) {
                jwk = noUseKey
            } else {
                throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey:
                    "client_metadata.jwks has \(p256Keys.count) P-256 key(s) but none usable for encryption (all marked use=sig)"])
            }
        } else {
            throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey:
                "client_metadata carried neither jwks_uri nor an inline jwks - nothing to encrypt the response to"])
        }

        return try await encrypt(payload: payload,
                       jwks: jwk,
                       nonce: presentationRequest?.nonce,
                                 clientID: presentationRequest?.clientId, supportedEncryptions: supportedEncryptions)
    }
    
    func encrypt(
        payload: [String: Any],
        jwks: [String: Any]?,
        nonce: String? = nil,
        clientID: String? = nil,
        supportedEncryptions: [String]? = nil
    ) async throws -> String {
        guard let x = jwks?["x"] as? String,
              let y = jwks?["y"] as? String,
              let kid = jwks?["kid"] as? String else {
            throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey: "Invalid JWK"])
        }
     let selectedEncryptionMethod = try selectEncryptionMethod(supported: supportedEncryptions ?? [])
        let ecKeyData = ECPublicKey(crv: .P256, x: x, y: y, additionalParameters: ["kid": kid])
        var header = JWEHeader(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: selectedEncryptionMethod)
        header.kid = kid
        if let nonce = nonce, !nonce.isEmpty {
            let apvData = nonce.data(using: .utf8)
            header.apv = apvData?.base64URLEncodedString()
        }
        if let clientID = clientID, !clientID.isEmpty {
            let apuData = clientID.data(using: .utf8)
            header.apu = apuData?.base64URLEncodedString()
        }

        // 4. Convert payload to JSON data
        let payloadData = try JSONSerialization.data(withJSONObject: payload, options: [])

        // 5. Encrypt
        let payloadEncrypted = Payload(payloadData)
        let encrypter = try Encrypter(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: selectedEncryptionMethod, encryptionKey: ecKeyData)
        guard let encrypter = encrypter else { return ""}
        let jwe = try JWE(header: header, payload: payloadEncrypted, encrypter: encrypter)

        return jwe.compactSerializedString
    }
    
    private func toEncryptionMethod(_ enc: String) -> ContentEncryptionAlgorithm? {
        switch enc {
        case "A128CBC-HS256":
            return .A128CBCHS256
        case "A128GCM":
            return .A128GCM
        case "A256GCM":
            return .A256GCM
        default:
            return nil
        }
    }

    private func selectEncryptionMethod(
        supported: [String]
    ) throws -> ContentEncryptionAlgorithm {
        
        let preferenceOrder = [
            "A128CBC-HS256",
            "A128GCM",
            "A256GCM"
        ]
        
        guard let selected = preferenceOrder.first(where: { supported.contains($0) }) else {
            throw NSError(
                domain: "EncryptionMethodSelection",
                code: 0,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "No supported encryption method found. Verifier supports: \(supported)"
                ]
            )
        }
        
        guard let method = toEncryptionMethod(selected) else {
            throw NSError(
                domain: "EncryptionMethodSelection",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Unsupported enc method: \(selected)"
                ]
            )
        }
        
        return method
    }
    
    func generateEphemeralEncryptionJWK(privateKey: ECPrivateKey?) -> Any? {
        guard let privateKey = privateKey else {
            return nil
        }
        let publicKey = privateKey.getPublic()

        let jwk: [String: String] = [
            "kty": "EC",
            "crv": "P-256",
            "x": publicKey.x,
            "y": publicKey.y,
            "alg": "ECDH-ES",
            "enc": "A128CBC-HS256",
            "use": "enc"
        ]

        return jwk
    }
    
    // Helper: Fetch JWK from URI (you need to implement async network fetch)
    private func fetchJWKFromURI(_ uri: String) async -> [String: Any] {
        return await ProcessJWKFromJwksUri.fetchJwkData(kid: nil, jwksUri: uri, keyUse: "enc")
    }
    
}
