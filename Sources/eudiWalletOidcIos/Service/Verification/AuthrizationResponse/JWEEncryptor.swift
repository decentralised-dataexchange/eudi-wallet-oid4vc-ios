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

        if let jwksURI = clientMetaData["jwks_uri"] as? String {
            jwk = try await fetchJWKFromURI(jwksURI)
        } else if let jwks = clientMetaData["jwks"] as? [String: Any],
                  let keys = jwks["keys"] as? [[String: Any]],
                  let p256Key = keys.first(where: { $0["crv"] as? String == "P-256" }) {
            jwk = p256Key
        } else {
            throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey: "No P-256 key found"])
        }

        return try await encrypt(payload: payload,
                       jwks: jwk,
                       nonce: presentationRequest?.nonce,
                       clientID: presentationRequest?.clientId)
    }
    
    func encrypt(
        payload: [String: Any],
        jwks: [String: Any]?,
        nonce: String? = nil,
        clientID: String? = nil
    ) async throws -> String {
        guard let x = jwks?["x"] as? String,
              let y = jwks?["y"] as? String,
              let kid = jwks?["kid"] as? String else {
            throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey: "Invalid JWK"])
        }
        let ecKeyData = ECPublicKey(crv: .P256, x: x, y: y, additionalParameters: ["kid": kid])
        var header = JWEHeader(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A128CBCHS256)
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
        let encrypter = try Encrypter(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A128CBCHS256, encryptionKey: ecKeyData)
        guard let encrypter = encrypter else { return ""}
        let jwe = try JWE(header: header, payload: payloadEncrypted, encrypter: encrypter)

        return jwe.compactSerializedString
    }
    
    func base64UrlDecode(_ str: String) -> Data? {
        var base64 = str
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        let paddingLength = 4 - base64.count % 4
        if paddingLength < 4 {
            base64 += String(repeating: "=", count: paddingLength)
        }
        return Data(base64Encoded: base64)
    }
    
    func ecPublicKeyWithoutKid(x: String, y: String) throws -> SecKey {
        guard
            let xData = base64UrlDecode(x),
            let yData = base64UrlDecode(y)
        else {
            throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey: "Invalid base64url x/y"])
        }

        // P-256 uncompressed key = 0x04 + x + y
        var keyBytes = Data([0x04])
        keyBytes.append(xData)
        keyBytes.append(yData)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]

        guard let secKey = SecKeyCreateWithData(keyBytes as CFData, attributes as CFDictionary, nil) else {
            throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey: "Failed to create EC key"])
        }

        return secKey
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

    // Helper: Convert base64url strings to EC public key (CryptoKit)
    struct EphemeralPublicKey {
        let x: String
        let y: String

        var rawRepresentation: Data {
            let xData = Data(base64URLEncoded: x)!
            let yData = Data(base64URLEncoded: y)!
            return Data([0x04]) + xData + yData // Uncompressed EC point format
        }

        init(x: String, y: String) throws {
            self.x = x
            self.y = y
        }
    }

    // Helper: Fetch JWK from URI (you need to implement async network fetch)
    private func fetchJWKFromURI(_ uri: String) async -> [String: Any] {
        return await ProcessJWKFromJwksUri.fetchJwkData(kid: nil, jwksUri: uri, keyUse: "enc")
    }
}
