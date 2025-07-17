//
//  File 2.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 10/07/25.
//

import Foundation
import PresentationExchangeSdkiOS

public class FilterCredentialService {
    
    public init() {
    }
    
    
    public func filterCredentials(credentialList: [String?], queryItems: Any) -> [[String]] {
        var response: [[String]] = []
        if let presentationDefinition = queryItems as? PresentationDefinitionModel {
            var filteredCredentialList: [String] = []
            let matchesString = PresentationDefinitionFiltering.filterCredentialUsingPresentationDefinition(presentationDefinition: presentationDefinition, credentialList: credentialList)
            for item in matchesString {
                filteredCredentialList = []
                for data in item {
                    filteredCredentialList.append(credentialList[data.index] ?? "")
                }
                response.append(filteredCredentialList)
            }
        } else if let dcql = queryItems as? DCQLQuery {
            var filteredCredentialList: [String] = []
            let matchesString = DCQLFiltering.filterCredentialsUsingDCQL(dcql: dcql, credentials: credentialList)
                for item in matchesString {
                    filteredCredentialList = []
                    for data in item {
                        filteredCredentialList.append(credentialList[data.index] ?? "")
                    }
                    response.append(filteredCredentialList)
                }
        }
        
        return response
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
