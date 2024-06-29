//
//  SDJWTService.swift
//
//
//  Created by Mumthasir mohammed on 26/04/24.
//

import Foundation
import CryptoKit

public class SDJWTService {
    
    public static var shared = SDJWTService()
    private init() {}
    
    /**
      * Calculates the SHA-256 hash of the input string and returns it in base64url encoding.
      *
      * @param inputString The input string to be hashed.
      * @return The SHA-256 hash of the input string in base64url encoding, or null if the input is null.
      */
    public func calculateSHA256Hash(inputString: String?) -> String? {
        guard let inputString = inputString,
              let inputData = inputString.data(using: .utf8) else {
            return nil
        }
        
        // Compute the SHA-256 hash
        let sha256Digest = SHA256.hash(data: inputData)
        
        // Encode the hash using base64url encoding
        let base64EncodedHash = Data(sha256Digest).base64EncodedString()
        let base64urlEncodedHash = base64EncodedHash
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
        
        return base64urlEncodedHash
    }

    public func createSDJWTR(
        credential: String?,
        presentationRequest: PresentationRequest,
        privateKey: P256.Signing.PrivateKey
    ) -> String? {
        do {
            guard let credential = credential else {
                return nil
            }
            
            let processedCredentialWithRequiredDisclosures = try processDisclosuresWithPresentationDefinition(
                credential: credential,
                presentationDefinition: VerificationService.processPresentationDefinition(presentationRequest.presentationDefinition)
            )
            
//            let iat = Date()
//            let payload =
//            ([
//              "audience": "\(presentationRequest.clientId ?? "")",
//              "issueTime": "\(iat)",
//              "nonce": "\(UUID().uuidString)",
//              "exp": SDJWTService().calculateSHA256Hash(inputString: processedCredentialWithRequiredDisclosures) ?? ""
//            ] as [String : Any]).toString() ?? ""
//
//            let header =
//            ([
//              "algorithm": "ES256",
//              "type": "kb_jwt"
//            ]).toString() ?? ""
//
//            // Create JWT token
//            let headerData = Data(header.utf8)
//            let payloadData = Data(payload.utf8)
//            let unsignedToken = "\(headerData.base64URLEncodedString()).\(payloadData.base64URLEncodedString())"
//            let signatureData = try! privateKey.signature(for: unsignedToken.data(using: .utf8)!)
//            let signature = signatureData.rawRepresentation
//            let idToken = "\(unsignedToken).\(signature.base64URLEncodedString())"
            
            return processedCredentialWithRequiredDisclosures
        } catch {
            print("Error creating SD-JWT-R: \(error)")
            return nil
        }
    }

    public func processDisclosuresWithPresentationDefinition(
        credential: String?,
        presentationDefinition: PresentationDefinitionModel
    ) -> String? {
        guard let credential = credential else { return nil }
        
        // Split the credential into disclosures and the issued JWT
        guard let disclosures = getDisclosuresFromSDJWT(credential),
              var issuedJwt = getIssuerJwtFromSDJWT(credential) else {
            return nil
        }
        
        // Extract requested parameters from the presentation definition
        var requestedParams: [String] = []
        if let fields = presentationDefinition.inputDescriptors?.first?.constraints?.fields {
            for field in fields {
                if let paramName = field.path?.first?.split(separator: ".").last {
                    requestedParams.append(String(paramName))
                }
            }
        }
        
        // Filter disclosures based on requested parameters
        for disclosure in disclosures {
            if let decodedDisclosure = disclosure.decodeBase64(),
               let list = try? JSONSerialization.jsonObject(with: Data(decodedDisclosure.utf8), options: []) as? [Any],
               list.count >= 2,
               let paramName = list[1] as? String,
               requestedParams.contains(paramName) {
                issuedJwt += "~\(disclosure)"
            }
        }
        
        return issuedJwt.isEmpty ? nil : issuedJwt
    }
    
    public func updateIssuerJwtWithDisclosures(credential: String?) -> String? {
        guard let split = credential?.split(separator: "."),
              let jsonString = "\(split[1])".decodeBase64(),
              let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) else { return nil }
        
        var object = jsonObject
        
        var hashList: [String] = []
        let disclosures = getDisclosuresFromSDJWT(credential) ?? []
        disclosures.forEach { encodedString in
            guard let hash = calculateSHA256Hash(inputString: encodedString) else { return }
            hashList.append(hash)
        }
        
        object = addDisclosuresToCredential(jsonElement: jsonObject, disclosures: disclosures, hashList: hashList)
        
        guard let jsonData = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return String(data: jsonData, encoding: .utf8)
    }
    
    private func addDisclosuresToCredential(jsonElement: [String: Any], disclosures: [String], hashList: [String]) -> [String: Any] {
        var modifiedJsonElement = jsonElement
        
        if modifiedJsonElement["_sd"] != nil {
            guard let sdList = modifiedJsonElement["_sd"] as? [String] else { return [:] }
            for (index, hash) in hashList.enumerated() {
                if isStringPresentInJSONArray(jsonArray: sdList, searchString: hash) {
                    
                    if let disclosure = disclosures[index].decodeBase64() {
                        let (decodedKey, decodedValue) = extractKeyValue(from: disclosure) ?? ("","" as Any)
                        if let decodedValue = decodedValue as? [String: Any] {
                            modifiedJsonElement[decodedKey] = decodedValue as Any
                        } else if let decodedValue = decodedValue as? [Any] {
                            modifiedJsonElement[decodedKey] = decodedValue as Any
                        } else {
                            modifiedJsonElement[decodedKey] = decodedValue
                        }
                    }
                }
            }
        }
        
        for (key, value) in modifiedJsonElement {
            if(value is [String: Any]){
                modifiedJsonElement[key] = addDisclosuresToCredential(jsonElement: value as! [String : Any], disclosures: disclosures, hashList: hashList)
            }
        }
        
        return modifiedJsonElement
    }

    
    private func isStringPresentInJSONArray(jsonArray: [String], searchString: String) -> Bool {
        for element in jsonArray {
            if element == searchString {
                return true
            }
        }
        return false
    }

    private func extractKeyValue(from decodedString: String) -> (String, Any)? {
        guard let jsonArray = try? JSONSerialization.jsonObject(with: Data(decodedString.utf8)) as? [Any],
              jsonArray.count >= 3,
              let key = jsonArray[1] as? String,
              let value = jsonArray[2] as? Any else {
            return nil
        }
        return (key, value)
    }

    private func getDisclosuresFromSDJWT(_ credential: String?) -> [String]? {
        guard let split = credential?.split(separator: "~"), split.count > 1 else {
            return []
        }
        return split.dropFirst().map { String($0) }
    }

    private func getIssuerJwtFromSDJWT(_ credential: String?) -> String? {
        guard let split = credential?.split(separator: "~"), let first = split.first else {
            return nil
        }
        return String(first)
    }
}

