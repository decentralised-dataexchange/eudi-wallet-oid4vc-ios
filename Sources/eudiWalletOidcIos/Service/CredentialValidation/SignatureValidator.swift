//
//  File.swift
//
//
//  Created by iGrant on 25/07/24.
//

import Foundation
import Base58Swift
import Security
import CryptoKit

class SignatureValidator {
    
    static func validateSign(jwt: String?, jwksURI: String?, format: String) async -> Bool? {
        var jwk: [String: Any] = [:]
        if format == "mso_mdoc" {
            return true
        } else {
            guard let split = jwt?.split(separator: "."), split.count > 1 else { return true}
            guard let jsonString = "\(split[0])".decodeBase64(),
                  let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) else { return false }
            if var kid = jsonObject["kid"] as? String {
                if kid.hasPrefix("did:jwk:") {
                    if let parsedJWK = ProcessJWKFromKID.parseDIDJWK(kid) {
                        jwk = parsedJWK
                    }
                } else if kid.hasPrefix("did:key:z") {
                    jwk = ProcessKeyJWKFromKID.processJWKfromKid(did: kid)
                } else if kid.hasPrefix("did:ebsi:z") {
                    jwk = await ProcessEbsiJWKFromKID.processJWKforEBSI(did: kid)
                } else if kid.hasPrefix("did:web:") {
                    if let didDocument = try? await ProcessWebJWKFromKID.fetchDIDDocument(did: kid),
                       let verificationMethod = didDocument["verificationMethod"] as? [[String: Any]],
                       let publicKeyJwk = verificationMethod.first?["publicKeyJwk"] as? [String: Any] {
                        jwk = publicKeyJwk
                    } else {
                        print("Failed to fetch or parse DID document for did:web")
                        return false
                    }
                    
                } else {
                    jwk = await ProcessJWKFromJwksUri.processJWKFromJwksURI2(kid: kid, jwksURI: jwksURI)
                }
            } else {
                let kid = jsonObject["kid"] as? String
                jwk = await ProcessJWKFromJwksUri.processJWKFromJwksURI2(kid: kid, jwksURI: jwksURI)
            }
            return validateSignature(jwt: jwt, jwk: jwk)
        }
    }
    
    static private func validateSignature(jwt: String?, jwk: [String: Any]) -> Bool? {
        let segments = jwt?.split(separator: ".")
        guard segments?.count == 3 else {
            return true
        }
        let headerData = String(segments?[0] ?? "")
        let payloadData = String(segments?[1] ?? "")
        var sigatureData = String(segments?[2] ?? "")
        if sigatureData.contains("~") {
            let splitData = sigatureData.split(separator: "~")
            sigatureData = String(splitData[0])
        }
        guard let headerEncoded = Data(base64URLEncoded: headerData) else { return false }
        guard let signatureEncoded = Data(base64URLEncoded: sigatureData) else { return false }
        guard let headerJson = try? JSONSerialization.jsonObject(with: headerEncoded, options: []) as? [String: Any], let alg = headerJson["alg"] as? String else {
            return false
        }
        guard let crv = jwk["crv"] as? String else {
            return false
        }
        let algToCrvMap: [String: String] = [
            "ES256": "P-256",
            "ES384": "P-384",
            "ES512": "P-521"
        ]
        if let expectedCrv = algToCrvMap[alg], expectedCrv != crv {
            return false
        }
        guard let publicKey = extractPublicKey(from: jwk, crv: crv) else {
            return false
        }
        
        let signedData = "\(headerData).\(payloadData)".data(using: .utf8)!
        let isVerified = verifySignature(signature: signatureEncoded, for: signedData, using: publicKey)
        
        return isVerified
    }
    
    static private func extractPublicKey(from jwk: [String: Any], crv: String? = "ES") -> Any? {
        guard let crv = jwk["crv"] as? String,
              let x = jwk["x"] as? String,
              let y = jwk["y"] as? String,
              let xData = Data(base64URLEncoded: x),
              let yData = Data(base64URLEncoded: y) else {
            return nil
        }
        
        var publicKeyData = Data()
        publicKeyData.append(0x04)
        publicKeyData.append(xData)
        publicKeyData.append(yData)
        
        do {
            switch crv {
            case "P-256":
                return try P256.Signing.PublicKey(x963Representation: publicKeyData)
            case "P-384":
                return try P384.Signing.PublicKey(x963Representation: publicKeyData)
            case "P-521":
                return try P521.Signing.PublicKey(x963Representation: publicKeyData)
            default:
                return try P256.Signing.PublicKey(x963Representation: publicKeyData)
            }
        } catch {
            print("Error creating public key: \(error)")
            return nil
        }
    }
    
    static private func verifySignature(signature: Data, for data: Data, using publicKey: Any) -> Bool {
        do {
            switch publicKey {
            case let publicKey as P256.Signing.PublicKey:
                guard let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else {
                    print("Error converting signature to P256 ECDSASignature")
                    return false
                }
                return publicKey.isValidSignature(ecdsaSignature, for: data)
                
            case let publicKey as P384.Signing.PublicKey:
                guard let ecdsaSignature = try? P384.Signing.ECDSASignature(rawRepresentation: signature) else {
                    print("Error converting signature to P384 ECDSASignature")
                    return false
                }
                return publicKey.isValidSignature(ecdsaSignature, for: data)
                
            case let publicKey as P521.Signing.PublicKey:
                guard let ecdsaSignature = try? P521.Signing.ECDSASignature(rawRepresentation: signature) else {
                    print("Error converting signature to P521 ECDSASignature")
                    return false
                }
                return publicKey.isValidSignature(ecdsaSignature, for: data)
                
            default:
                print("Unsupported public key type")
                return false
            }
        } catch {
            print("Error during signature verification: \(error)")
            return false
        }
    }
}
