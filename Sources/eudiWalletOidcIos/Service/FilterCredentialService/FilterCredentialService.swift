//
//  File 2.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 10/07/25.
//

import Foundation
import PresentationExchangeSdkiOS
import SwiftCBOR

public class FilterCredentialService {
    
    public init() {
    }
    
    
    public func filterCredentials(credentialList: [String?], queryItems: Any, completion: @escaping ([[String]]) -> Void) {
        var response: [[String]] = []
        let group = DispatchGroup()
        
        if let presentationDefinition = queryItems as? PresentationDefinitionModel {
            let matchesString = PresentationDefinitionFiltering.filterCredentialUsingPresentationDefinition(
                presentationDefinition: presentationDefinition,
                credentialList: credentialList
            )
            
            for item in matchesString {
                var filteredCredentialList: [String] = []
                for data in item {
                    filteredCredentialList.append(credentialList[data.index] ?? "")
                }
                response.append(filteredCredentialList)
            }
            completion(response)
            
        } else if let dcql = queryItems as? DCQLQuery {
            let matchesString = DCQLFiltering.filterCredentialsUsingDCQL(
                dcql: dcql,
                credentials: credentialList
            )
            
            // Create an array to store results for each index
            var results: [[String]] = Array(repeating: [], count: matchesString.count)
            
            for (index, item) in matchesString.enumerated() {
                group.enter()
                
                var filteredCredentialList: [String] = []
                for data in item {
                    filteredCredentialList.append(credentialList[data.index] ?? "")
                }
                
                var updatedFilteredCredentialList: [String] = []
                let credentialItemGroup = DispatchGroup()
                
                for credential in filteredCredentialList {
                    credentialItemGroup.enter()
                    isCredentialIssuerTrusted(
                        credential: credential,
                        credentialItem: dcql.credentials[index]
                    ) { isTrusted in
                        if isTrusted == true {
                            updatedFilteredCredentialList.append(credential)
                        }
                        credentialItemGroup.leave()
                    }
                }
                
                credentialItemGroup.notify(queue: .main) {
                    results[index] = updatedFilteredCredentialList
                    group.leave()
                }
            }
            
            group.notify(queue: .main) {
                response.append(contentsOf: results)
                completion(response)
            }
        }
    }
    
    public func isCredentialIssuerTrusted(
        credential: String?,
        credentialItem: CredentialItems,
        completion: @escaping (Bool?) -> Void
    ) {
        
        var x5cData: [String]?
        var kid: String?
        var did: String?
        let credentialCount = credential?.split(separator: ".")

        if credentialCount?.count == 1 {
            guard let issuerAuthData = MDocVpTokenBuilder().getIssuerAuth(credential: credential ?? "") else {
                completion(nil)
                return
            }
            x5cData = extractX5cFromIssuerAuth1(issuerAuth: issuerAuthData)
            (kid, did) = extractKidOrDidFromIssuerAuth(issuerAuth: issuerAuthData)
        } else {
            x5cData = extractX5cFromCredential(data: credential)
            (kid, did) = extractDidOrKidFromCredential(data: credential)
        }

        guard x5cData != nil || kid != nil || did != nil else {
            completion(nil)
            return
        }
        guard let trustedAuthorities = credentialItem.trustedAuthorities?.first,
              let values = trustedAuthorities.values,
              !values.isEmpty else {
            completion(true)
            return
        }

        var currentIndex = 0

        func processNext() {
            if currentIndex >= values.count {
                completion(false)
                return
            }

            let value = values[currentIndex]
            currentIndex += 1
            validateIdentifiers(url: value, x5cList: x5cData, kid: kid, did: did, jwksURI: "") { isTrusted in
                if isTrusted == true {
                    completion(true)
                } else {
                    processNext()
                }
                
            }
        }

        processNext()
    }
    
    private func validateIdentifiers(url: String,
                                   x5cList: [String]?,
                                   kid: String?,
                                   did: String?,
                                   jwksURI: String?,
                                   completion: @escaping (Bool?) -> Void) {
        let group = DispatchGroup()
        var validationResults: [Bool] = []
        
        // Validate x5c certificates
        if let x5cList = x5cList {
            for cert in x5cList {
                validateCertificate(url: url, certificate: cert, jwksURI: jwksURI, group: group) { result in
                    if let result = result { validationResults.append(result) }
                }
            }
        }
        
        // Validate kid if present
        if let kid = kid {
            group.enter()
            TrustMechanismService.shared.isIssuerOrVerifierTrusted(url: url, x5c: kid, jwksURI: jwksURI) { result in
                defer { group.leave() }
                if let result = result { validationResults.append(result) }
            }
        }
        
        // Validate did if present
        if let did = did {
            group.enter()
            TrustMechanismService.shared.isIssuerOrVerifierTrusted(url: url, x5c: did, jwksURI: jwksURI) { result in
                defer { group.leave() }
                if let result = result { validationResults.append(result) }
            }
        }
        
        group.notify(queue: .main) {
            completion(validationResults.contains(true) ? true : false)
        }
    }

    private func validateCertificate(url: String,
                                    certificate: String,
                                    jwksURI: String?,
                                    group: DispatchGroup,
                                    completion: @escaping (Bool?) -> Void) {
        group.enter()
        TrustMechanismService.shared.isIssuerOrVerifierTrusted(url: url, x5c: certificate, jwksURI: jwksURI) { result in
            defer { group.leave() }
            if let result = result {
                completion(result)
                return
            }
            
            // If direct validation fails, try with SKI
            guard let ski = X509SkiGeneratorHelper.generateSKI(from: certificate) else {
                completion(nil)
                return
            }
            
            group.enter()
            TrustMechanismService.shared.isIssuerOrVerifierTrusted(url: url, x5c: ski, jwksURI: jwksURI) { skiResult in
                defer { group.leave() }
                if let skiResult = skiResult {
                    completion(skiResult)
                    return
                }
                
                // If SKI validation fails, try with public key
                guard let publicKey = X509SkiGeneratorHelper.extractBase64PublicKey(from: certificate) else {
                    completion(nil)
                    return
                }
                
                group.enter()
                TrustMechanismService.shared.isIssuerOrVerifierTrusted(url: url, x5c: publicKey, jwksURI: jwksURI) { pubKeyResult in
                    defer { group.leave() }
                    completion(pubKeyResult)
                }
            }
        }
    }

    
    func extractX5cFromCredential(data: String?) -> [String]? {
        let credSegments = data?.split(separator: ".")
        var x5c: [String]? = nil
        if credSegments?.count ?? 0 > 1 {
            let jsonString = "\(credSegments?[0] ?? "")".decodeBase64() ?? ""
            let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString)
            x5c = jsonObject?["x5c"] as? [String]
        }
        return x5c
    }
    
    func extractDidOrKidFromCredential(data: String?) -> (String?, String?) {
        let credSegments = data?.split(separator: ".")
        var kid: String? = nil
        var did: String? = nil
        var credentialFilter: String?
        if credSegments?.count ?? 0 > 1 {
            let jsonString = "\(credSegments?[0] ?? "")".decodeBase64() ?? ""
            let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString)
            if let data =  jsonObject?["kid"] as? String {
                credentialFilter = data
            } else if let data = jsonObject?["did"] as? String {
                credentialFilter = data
            }
        }
        if credentialFilter?.hasPrefix("did") == true {
            did = credentialFilter
        } else {
            kid = credentialFilter
        }
        return (kid, did)
    }
    
    func extractX5cFromIssuerAuth1(issuerAuth: CBOR) -> [String]? {
        var certs: [String] = []

        guard case let CBOR.array(coseArray) = issuerAuth,
              coseArray.count >= 2 else {
            print("Invalid COSE_Sign1 structure")
            return nil
        }
        
        // The x5c is in the unprotected headers (second element)
        guard case let CBOR.map(unprotectedHeaders) = coseArray[1] else {
            print("No unprotected headers found")
            return nil
        }
        
        // Look for x5c in standard location (key 33)
        guard let x5cItem = unprotectedHeaders[CBOR.unsignedInt(33)] else {
            print("x5c not found in unprotected headers (key 33)")
            // Print all available headers for debugging
            print("Available unprotected headers:")
            for (key, _) in unprotectedHeaders {
                print("Key: \(key)")
            }
            return nil
        }
        // Handle array of items
        if case let CBOR.array(items) = x5cItem {
            for item in items {
                if case let CBOR.byteString(certData) = item {
                    certs.append(Data(certData).base64EncodedString())
                } else if case let CBOR.utf8String(certString) = item {
                    certs.append(certString)
                } else {
                    print("Unexpected x5c item format in array")
                    return nil
                }
            }
            return certs
        }

        // Handle single byteString
        if case let CBOR.byteString(certData) = x5cItem {
            certs.append(Data(certData).base64EncodedString())
            return certs
        }

        // Handle single utf8String
        if case let CBOR.utf8String(certString) = x5cItem,
           let certData = certString.data(using: .utf8) {
            certs.append(certData.base64EncodedString())
            return certs
        }

        // Fallback
        print("x5c item is not in expected format (array, byteString, or utf8String)")
        return nil
    }
    
    func extractKidOrDidFromIssuerAuth(issuerAuth: CBOR) -> (kid: String?, did: String?) {
        // issuerAuth is a COSE_Sign1 structure (array of 4 elements)
        guard case let CBOR.array(coseArray) = issuerAuth,
              coseArray.count >= 2 else {
            print("Invalid COSE_Sign1 structure")
            return (nil, nil)
        }
        
        // The headers are in the unprotected headers (second element)
        guard case let CBOR.map(unprotectedHeaders) = coseArray[1] else {
            print("No unprotected headers found")
            return (nil, nil)
        }
        
        var kid: String? = nil
        var did: String? = nil
        
        // Check for kid (key 4 in COSE)
        if let kidItem = unprotectedHeaders[CBOR.unsignedInt(4)] {
            switch kidItem {
            case .utf8String(let str):
                kid = str
            case .byteString(let bytes):
                kid = String(data: Data(bytes), encoding: .utf8)
            default:
                print("kid is in unexpected format")
            }
        }
        
        // Check for did (common location in some implementations)
        // Note: DID isn't standard in COSE, so implementations vary
        if let didItem = unprotectedHeaders[CBOR.utf8String("did")] {
            switch didItem {
            case .utf8String(let str):
                did = str
            case .byteString(let bytes):
                did = String(data: Data(bytes), encoding: .utf8)
            default:
                print("did is in unexpected format")
            }
        }
        
        // Alternative check for did in custom integer key (if used)
        if did == nil, let didItem = unprotectedHeaders[CBOR.unsignedInt(100)] { // Example custom key
            switch didItem {
            case .utf8String(let str):
                did = str
            case .byteString(let bytes):
                did = String(data: Data(bytes), encoding: .utf8)
            default:
                print("did is in unexpected format")
            }
        }
        
        return (kid, did)
    }

    
    func processCborCredentialToJsonString(credentialList: [String?]) -> [String] {
        var processedCredentials = [String]()
        for cred in credentialList {
            var cborItem = MDocVpTokenBuilder().convertCBORtoJson(credential: cred ?? "") ?? ""
            processedCredentials.append(cborItem)
        }
        return processedCredentials
    }
    
    func splitCredentialsBySdJWT(allCredentials: [String?], isSdJwt: Bool) -> [String?] {
        return allCredentials
    }
    
    func processCredentialsToJsonString(credentialList: [String?]) -> [String] {
        var processedCredentials = [String]()
        for cred in credentialList {
            guard let cred = cred else { continue }
            let split = cred.split(separator: ".")
            
            let jsonString: String
            if (cred.split(separator: "~").count) > 0 {
                jsonString = SDJWTService.shared.updateIssuerJwtWithDisclosures(credential: cred) ?? ""
            } else if split.count > 1,
                      let base64Data = Data(base64Encoded: String(split[1]), options: .ignoreUnknownCharacters),
                      let decodedString = String(data: base64Data, encoding: .utf8) {
                jsonString = decodedString
            } else {
                jsonString = ""
            }
            
            let json = try? JSONSerialization.jsonObject(with: Data(jsonString.utf8), options: []) as? [String: Any] ?? [:]
            
            var vcString = ""
            if let vc = json?["vc"] as? [String: Any] {
                vcString = vc.toString() ?? ""
            } else {
                vcString = jsonString
            }
            
            processedCredentials.append(vcString)
        }
        return processedCredentials
    }
    
    func updatePath(in descriptor: InputDescriptor) -> InputDescriptor {
        var updatedDescriptor = descriptor
        guard var constraints = updatedDescriptor.constraints else { return updatedDescriptor }
        guard var fields = constraints.fields else { return updatedDescriptor }
        
        for j in 0..<fields.count {
            guard var pathList = fields[j].path else { continue }
            
            for k in 0..<pathList.count {
                let path = pathList[k]
                if path.contains("$.vc.") {
                    let newPath = path.replacingOccurrences(of: "$.vc.", with: "$.")
                    if !pathList.contains(newPath) {
                        pathList.append(newPath)
                    }
                }
            }
            fields[j].path = pathList
        }
        constraints.fields = fields
        updatedDescriptor.constraints = constraints
        
        return updatedDescriptor
    }
    
}
