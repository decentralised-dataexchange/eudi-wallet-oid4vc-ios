//
//  File.swift
//  eudi-wallet-oid4vc-ios
//
//  Created by iGrant on 29/08/25.
//

import Foundation

public class RequestedCredentialsValidator {
    
    public init() {}
    
    public func validate(
        queryData: Any,
        filteredCredentials: [[String]]
    ) -> CredentialsValidatorResult? {
        
        
        var isValid = true
        
        var missing: [String] = []
        
        if let presentationDefinition = queryData as? PresentationDefinitionModel {
            
            // Process the definition
            do {
                
                // Check each filtered list
                for (index, creds) in filteredCredentials.enumerated() {
                    if creds.isEmpty {
                        isValid = false
                        let name = presentationDefinition.inputDescriptors?[index].name ?? presentationDefinition.inputDescriptors?[index].id ?? ""
                        missing.append(name)
                    }
                }
            } catch {
                return nil
            }
            
        } else if let dcqlQuery = queryData as? DCQLQuery {
            
            if let credentialSets = dcqlQuery.credentialSets {
                // Map credential.id → index in filteredCredentials
                var idToIndex: [String: Int] = [:]
                for (idx, item) in dcqlQuery.credentials.enumerated() {
                    idToIndex[item.id] = idx
                }
                
                // Process credential_sets
                for (setIndex, set) in credentialSets.enumerated() {
                    let required = set.required ?? true
                    
                    if required {
                        // At least one option group (OR) must be satisfied
                        let setSatisfied = set.options.contains { optionIds in
                            // For this option group, ALL credential IDs must be present (AND)
                            optionIds.allSatisfy { optionId in
                                if let idx = idToIndex[optionId], idx < filteredCredentials.count {
                                    return !filteredCredentials[idx].isEmpty
                                }
                                return false
                            }
                        }
                        
                        if !setSatisfied {
                            isValid = false
                            missing.append("CredentialSet \(setIndex)")
                        }
                    }
                }
            } else {
                // No credential_sets → all filtered credentials must be non-empty
                for (index, creds) in filteredCredentials.enumerated() {
                    if creds.isEmpty {
                        isValid = false
                        missing.append("Credential at index \(index)")
                    }
                }
            }
        }
        
        return CredentialsValidatorResult(isValid: isValid, missingCredentials: missing)
    }
}

public struct CredentialsValidatorResult {
    public let isValid: Bool
    public let missingCredentials: [String]
}
