//
//  File.swift
//
//
//  Created by iGrant on 24/07/24.
//

import Foundation
import Base58Swift

public enum ValidationError: Error {
    case JWTExpired
    case signatureExpired
}

public class CredentialValidatorService: CredentialValidaorProtocol {
    public static var shared = CredentialValidatorService()
    public init() {}
    
    public func validateCredential(jwt: String?) async throws {
        let isJWTExpired = validateExpiryDate(jwt: jwt) ?? false
        let isSignatureExpied = await validateSign(jwt: jwt) ?? false
        if !isJWTExpired {
            throw ValidationError.JWTExpired
        }
        if !isSignatureExpied {
            throw ValidationError.signatureExpired
        }
    }
    
    public func validateExpiryDate(jwt: String?) -> Bool? {
        guard let split = jwt?.split(separator: "."),
              let jsonString = "\(split[1])".decodeBase64(),
              let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) else { return false }
        guard let vc = jsonObject["vc"] as? [String: Any], let expirationDate = vc["expirationDate"] as? String else { return true}
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        guard let expiryDate = dateFormatter.date(from: expirationDate) else { return false}
        let currentDate = Date()
        if currentDate <= expiryDate {
            return true
        } else {
            return false
        }
    }
    
    public func validateSign(jwt: String?) async -> Bool? {
        guard let split = jwt?.split(separator: "."),
              let jsonString = "\(split[0])".decodeBase64(),
              let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) else { return false }
        guard let kid = jsonObject["kid"] as? String else { return true}
        var jwk: [String: Any] = [:]
        if kid.hasPrefix("did:key:z") {
            jwk = processJWKfromKid(did: kid)
        } else if kid.hasPrefix("did:ebsi:z") {
            jwk = await processJWKforEBSI(did: kid)
        } else {
            
        }
        return true
    }
    
    
    func processJWKfromKid(did: String?) -> [String: Any] {
        do {
            guard let did = did else { return [:]}
            let components = did.split(separator: "#")
            guard let didPart = components.first else {
                return [:]
            }
            let multibaseString = String(didPart.dropFirst("did:key:z".count))
            
            guard let decodedData = Base58.base58Decode(multibaseString) else {
                print("Failed to decode Multibase string")
                return [:]
            }
            
            let multicodecPrefixLength = 3
            guard decodedData.count > multicodecPrefixLength else {
                print("Invalid decoded data length")
                return [:]
            }
            let jsonData = Data(decodedData.dropFirst(multicodecPrefixLength))
            
            let jwk = try JSONSerialization.jsonObject(with: jsonData, options: [])
            return jwk as? [String: Any] ?? [:]
        } catch {
            print("Error: \(error)")
            return [:]
        }
    }
    
    func processJWKforEBSI(did: String?) async -> [String: Any]{
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
    
}
