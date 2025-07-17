//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 10/07/25.
//

import Foundation
import PresentationExchangeSdkiOS

public class PresentationDefinitionFiltering {
    
    public static func filterCredentialUsingPresentationDefinition(presentationDefinition: PresentationDefinitionModel?, credentialList: [String?]) -> [[MatchedCredential]] {
        var filteredList: [[MatchedCredential]] = []
        if let inputDescriptors = presentationDefinition?.inputDescriptors {
            for inputDescriptor in inputDescriptors {
                var processedCredentials:[String] = []
                var tempCredentialList: [String?] = []
                var credentialFormat: String = ""
                if let format = presentationDefinition?.format ?? inputDescriptor.format {
                    for (key, value) in format {
                        credentialFormat = key
                    }
                }
                if credentialFormat == "mso_mdoc" {
                    tempCredentialList = credentialList
                    processedCredentials = FilterCredentialService().processCborCredentialToJsonString(credentialList: tempCredentialList)
                } else {
                    tempCredentialList = FilterCredentialService().splitCredentialsBySdJWT(allCredentials: credentialList, isSdJwt: inputDescriptor.constraints?.limitDisclosure != nil)
                    
                    processedCredentials = FilterCredentialService().processCredentialsToJsonString(credentialList: tempCredentialList)
                }
                
                let updatedDescriptor = FilterCredentialService().updatePath(in: inputDescriptor)
                var filteredCredentialList: [String] = []
                
                let jsonEncoder = JSONEncoder()
                jsonEncoder.keyEncodingStrategy = .convertToSnakeCase
                guard let jsonData = try? jsonEncoder.encode(updatedDescriptor),
                      let dictionary = try? JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] else {
                    fatalError("Failed to convert Person to dictionary")
                }
                // Convert the dictionary to a string
                guard let inputDescriptorString = String(data: try! JSONSerialization.data(withJSONObject: dictionary, options: .withoutEscapingSlashes), encoding: .utf8) else {
                    fatalError("Failed to convert dictionary to string")
                }
                do {
                    let matchesString = try matchCredentials(inputDescriptorJson: inputDescriptorString, credentials: processedCredentials)
                    
                    filteredList.append(matchesString)
                    
                } catch {
                    print("error")
                }
                
            }
        }
        return filteredList
    }
    
}
