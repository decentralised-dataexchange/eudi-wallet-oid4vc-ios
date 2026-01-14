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
import SwiftCBOR
import JOSESwift

public class SignatureValidator {
    
    static func validateSign(jwt: String?, jwksURI: String?, format: String) async throws-> Bool? {
        var jwk: [String: Any] = [:]
        var jwksArray: [Any] = []
        if format == "mso_mdoc" {
            guard let issuerAuthData = MDocVpTokenBuilder().getIssuerAuth(credential: jwt ?? "") else {
                return true
            }
            let x5cChain = FilterCredentialService().extractX5cFromIssuerAuth1(issuerAuth: issuerAuthData)
            let kid = FilterCredentialService().extractKidOrDidFromIssuerAuth(issuerAuth: issuerAuthData).0
            let jwkArray = try await JWKResolver().resolve(kid: kid, x5cChain: x5cChain)
            let (isValidSignature, isX5cSigNotValid) = MdocSignatureValidationHelper().validateSignatureForMdoc(jwk: jwkArray, issuerAuth: issuerAuthData, cborString: jwt ?? "")
            if let isValid = isValidSignature, isValid {
                return true
            } else if isX5cSigNotValid {
                throw ValidationError.invalidKID
            } else {
                return false
            }
        } else {
            guard let split = jwt?.split(separator: "."), split.count > 1 else { return true}
            guard let jsonString = "\(split[0])".decodeBase64(),
                  let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) else { return false }
            let x5cList = jsonObject["x5c"] as? [String]
            let kid = jsonObject["kid"] as? String
            let jwlPayload = "\(split[1])".decodeBase64()
            let jwlPayloadDict = UIApplicationUtils.shared.convertStringToDictionary(text: jwlPayload ?? "")
            var jwkArray = try await JWKResolver().resolve(kid: kid, x5cChain: x5cList)

            if let jwksURI = jwksURI {
                let kid = jsonObject["kid"] as? String
                jwk = await ProcessJWKFromJwksUri.processJWKFromJwksURI2(kid: kid, jwksURI: jwksURI)
                if !jwk.isEmpty {
                    jwkArray.append(jwk)
                }
            }
            if let iss = jwlPayloadDict?["iss"] as? String,
               let issURL = JWTVCIssuerMetadataResolver().validateIssuerURL(iss),
               let metadataURL = JWTVCIssuerMetadataResolver().buildIssuerMetadataURL(from: issURL) {
                if let metadata = try await JWTVCIssuerMetadataResolver()
                    .fetchIssuerMetadata(from: metadataURL) {
                    let kid = jsonObject["kid"] as? String
                    let issuerJwks = await JWTVCIssuerMetadataResolver()
                        .resolveJWKs(metadata: metadata, kid: kid)
                    jwksArray.append(contentsOf: issuerJwks)
                }
            }
            let (isValidSignature, isX5cSigNotValid) = validateSignature(jwt: jwt, jwk: jwkArray)
            if let isValid = isValidSignature, isValid {
                return true
            } else if isX5cSigNotValid {
                throw ValidationError.invalidKID
            } else {
                return false
            }
        }
    }
    
    static public func validateSignature(jwt: String?, jwk: [Any]) -> (Bool?, Bool) {
        var validationResults: [Bool] = []
        var isX5cSigNotValid: Bool = false
        for data in jwk {
            if let item = data as? [String] {
                let isValid = X509SanRequestVerifier.shared.validateSignatureWithCertificate(jwt: jwt ?? "", x5cChain: item)
                validationResults.append(isValid)
                if !isValid {
                    isX5cSigNotValid = true
                }
            } else {
                let segments = jwt?.split(separator: ".")
                guard segments?.count == 3 else {
                    validationResults.append(false)
                    continue
                }
                let headerData = String(segments?[0] ?? "")
                let payloadData = String(segments?[1] ?? "")
                var sigatureData = String(segments?[2] ?? "")
                if sigatureData.contains("~") {
                    let splitData = sigatureData.split(separator: "~")
                    sigatureData = String(splitData[0])
                }
                guard let headerEncoded = Data(base64URLEncoded: headerData) else { validationResults.append(false)
                    continue }
                guard let signatureEncoded = Data(base64URLEncoded: sigatureData) else { validationResults.append(false)
                    continue }
                guard let headerJson = try? JSONSerialization.jsonObject(with: headerEncoded, options: []) as? [String: Any], let alg = headerJson["alg"] as? String else {
                    validationResults.append(false)
                    continue
                }
                
                var publicKey: Any?
                if alg == "RS256" {
                    publicKey = createRSAPublicKey(from: data as? [String: Any] ?? [:])
                } else if alg == "EdDSA" {
                    // Expect crv == "Ed25519"
                    guard let jwkData = data as? [String: Any], let crv = jwkData["crv"] as? String, crv == "Ed25519" else {
                        validationResults.append(false)
                        continue
                    }
                    publicKey = extractPublicKey(from: jwkData, crv: crv)
                } else {
                    guard let jwkData = data as? [String: Any], let crv = jwkData["crv"] as? String else {
                        validationResults.append(false)
                        continue
                    }
                    let algToCrvMap: [String: String] = [
                        "ES256": "P-256",
                        "ES384": "P-384",
                        "ES512": "P-521"
                    ]
                    if let expectedCrv = algToCrvMap[alg], expectedCrv != crv {
                        validationResults.append(false)
                        continue
                    }
                    publicKey = extractPublicKey(from: data as? [String: Any] ?? [:], crv: crv)
                }
                if publicKey == nil { validationResults.append(false)
                    continue }
                
                let signedData = "\(headerData).\(payloadData)".data(using: .utf8)!
                let isVerified = verifySignature(signature: signatureEncoded, for: signedData, using: publicKey)
                
                validationResults.append(isVerified)
            }
        }
        return (validationResults.contains(true), isX5cSigNotValid)
    }
    
    static private func createRSAPublicKey(from jwk: [String: Any]) -> SecKey? {
        guard let kty = jwk["kty"] as? String, kty == "RSA",
              let nStr = jwk["n"] as? String, let eStr = jwk["e"] as? String,
              let modulusData = base64URLDecode(nStr),
              let exponentData = base64URLDecode(eStr) else {
            print("Invalid JWK or missing required parameters")
            return nil
        }
        
        // Create the ASN.1 DER-encoded RSA public key
        guard let keyData = createRSAPublicKeyData(modulus: modulusData, exponent: exponentData) else {
            print("Failed to create RSA public key data")
            return nil
        }
        
        // Define the key attributes
        let keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: modulusData.count * 8
        ]
        
        // Create the SecKey
        return SecKeyCreateWithData(keyData as CFData, keyAttributes as CFDictionary, nil)
    }

    static private func base64URLDecode(_ base64URL: String) -> Data? {
        var base64 = base64URL
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        // Pad with '=' to make it a multiple of 4
        while base64.count % 4 != 0 {
            base64.append("=")
        }
        
        return Data(base64Encoded: base64)
    }

    static private func createRSAPublicKeyData(modulus: Data, exponent: Data) -> Data? {
        // Encode the modulus and exponent as an ASN.1 sequence
        let modulusBytes = [0x00] + [UInt8](modulus) // Add a leading 0x00 to ensure positive value
        let exponentBytes = [UInt8](exponent)
        
        // ASN.1 encoding for each part
        guard let modulusASN1 = asn1Encode(modulusBytes),
              let exponentASN1 = asn1Encode(exponentBytes) else {
            return nil
        }
        
        // Combine the encoded parts into a single sequence
        let sequence = Array(modulusASN1 + exponentASN1) // Explicitly convert to [UInt8]
        return asn1Encode(sequence, tag: 0x30) // ASN.1 SEQUENCE
    }

    static private func asn1Encode(_ data: [UInt8], tag: UInt8 = 0x02) -> Data? {
        var encoded = Data([tag]) // Add tag
        let length = data.count
        
        // Encode length
        if length < 0x80 {
            encoded.append(UInt8(length))
        } else {
            let lengthBytes = withUnsafeBytes(of: UInt32(length).bigEndian) { Data($0).drop(while: { $0 == 0 }) }
            encoded.append(0x80 | UInt8(lengthBytes.count))
            encoded.append(contentsOf: lengthBytes)
        }
        
        // Add the actual data
        encoded.append(contentsOf: data)
        return encoded
    }
    
    static func extractPublicKey(from jwk: [String: Any], crv: String? = "ES") -> Any? {
        
        var publicKeyData = Data()
        if let crv = jwk["crv"] as? String, crv == "Ed25519"{
            guard let x = jwk["x"] as? String else {
                return nil
            }
        } else {
            guard let x = jwk["x"] as? String,
                  let y = jwk["y"] as? String,
                  let xData = Data(base64URLEncoded: x),
                  let yData = Data(base64URLEncoded: y) else {
                return nil
            }
            
            publicKeyData.append(0x04)
            publicKeyData.append(xData)
            publicKeyData.append(yData)
        }
        
        do {
            switch crv {
            case "P-256":
                return try P256.Signing.PublicKey(x963Representation: publicKeyData)
            case "P-384":
                return try P384.Signing.PublicKey(x963Representation: publicKeyData)
            case "P-521":
                return try P521.Signing.PublicKey(x963Representation: publicKeyData)
            case "Ed25519":
                guard let xStr = jwk["x"] as? String,
                    let xData = Data(base64URLEncoded: xStr) else {
                    return nil
                }
                return try Curve25519.Signing.PublicKey(rawRepresentation: xData)
            default:
                return try P256.Signing.PublicKey(x963Representation: publicKeyData)
            }
        } catch {
            print("Error creating public key: \(error)")
            return nil
        }
    }
    
    static func verifySignature(signature: Data, for data: Data, using publicKey: Any) -> Bool {
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
                
            case let publicKey as Curve25519.Signing.PublicKey:
                return publicKey.isValidSignature(signature, for: data)
            case let publicKey as SecKey:
                        // Using SecKey for RS256 verification
                        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
                        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
                            print("Algorithm not supported for the provided SecKey")
                            return false
                        }
                        
                        // Perform verification
                        let isValid = SecKeyVerifySignature(
                            publicKey,
                            algorithm,
                            data as CFData,
                            signature as CFData,
                            nil
                        )
                        if !isValid {
                            print("RS256 signature verification failed")
                        }
                        return isValid
                
            default:
                print("Unsupported public key type")
                return false
            }
        } catch {
            print("Error during signature verification: \(error)")
            return false
        }
    }

    static func extractX5C(data: [String: Any]?) -> [String]?{
        var x5cData: [String] = []
        if let data = data, let x5cArray = data["x5c"] as? [String]{
            x5cData = x5cArray
        }
        return x5cData
    }
    
}

