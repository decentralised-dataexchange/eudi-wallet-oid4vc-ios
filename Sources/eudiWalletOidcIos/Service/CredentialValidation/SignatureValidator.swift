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
    
    static func validateSign(jwt: String?, jwksURI: String?) async -> Bool? {
        var jwk: [String: Any] = [:]
        guard let split = jwt?.split(separator: "."),
              let jsonString = "\(split[0])".decodeBase64(),
              let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) else { return false }
        if let kid = jsonObject["kid"] as? String {
            if kid.hasPrefix("did:key:z") {
                jwk = processJWKfromKid(did: kid)
            } else if kid.hasPrefix("did:ebsi:z") {
                jwk = await processJWKforEBSI(did: kid)
            } else {
                jwk = await processJWKFromJwksURI2(kid: kid, jwksURI: jwksURI)
            }
        } else {
            let kid = jsonObject["kid"] as? String
            jwk = await processJWKFromJwksURI2(kid: kid, jwksURI: jwksURI)
        }
        return validateSignature(jwt: jwt, jwk: jwk)
    }
    
    
    static func processJWKfromKid(did: String?) -> [String: Any] {
        guard let did = did else { return [:]}
        let components = did.split(separator: "#")
        guard let didPart = components.first else {
            return [:]
        }
        return DidService.shared.createJWKfromDID(did: String(didPart))
    }
    
    static func processJWKforEBSI(did: String?) async -> [String: Any]{
        guard let did = did else { return [:]}
        let ebsiEndPoint = "https://api-conformance.ebsi.eu/did-registry/v5/identifiers/\(did)"
        do {
            guard let url = URL(string: ebsiEndPoint) else { return [:]}
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else { return [:]}
            guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let verificationMethods = jsonObject["verificationMethod"] as? [[String: Any]]  else { return [:]}
            for data in verificationMethods {
                if let publicKeyJwk = data["publicKeyJwk"] as? [String: Any], let crv = publicKeyJwk["crv"] as? String, crv == "P-256" {
                    return publicKeyJwk
                }
            }
        } catch {
            print("error")
        }
        return [:]
    }
    
    static func processJWKFromJwksURI2(kid: String?, jwksURI: String?) async -> [String: Any] {
        guard let jwksURI = jwksURI else {return [:]}
        return await fetchJwkData(kid: kid, jwksUri: jwksURI)
    }
    
    static func fetchJwkData(kid: String?, jwksUri: String)async -> [String: Any] {
        guard let url = URL(string: jwksUri) else {
            return [:]
        }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else { return [:]}
            guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let keys = jsonObject["keys"] as? [[String: Any]] else { return [:]}
             
             var jwkKey: [String: Any]? = keys.first { $0["use"] as? String == "sig" }
             
             if jwkKey == nil, let kid = kid {
                 jwkKey = keys.first { $0["kid"] as? String == kid }
             }
            return jwkKey ?? [:]
            
        } catch {
            print("error")
        }
        return [:]
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
