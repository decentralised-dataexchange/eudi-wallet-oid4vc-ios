//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation
import CryptoKit

class SDJWTVpTokenBuilder : VpTokenBuilder{
        
    func build(credentials: [String], presentationRequest: PresentationRequest?, did: String, index: Int?, keyHandler: SecureKeyProtocol) async -> [String]? {
        let item = credentials.first ?? ""
        guard !item.isEmpty else { return nil }
        var claims: [String: Any] = [:]
        claims["aud"] = presentationRequest?.clientId ?? ""
        claims["nonce"] = presentationRequest?.nonce ?? ""
        
        var queryItem: Any?
        var format: String?
        if let pd = presentationRequest?.presentationDefinition, !pd.isEmpty {
            var presentationDefinition :PresentationDefinitionModel? = nil
            do {
                presentationDefinition = try VerificationService.processPresentationDefinition(presentationRequest?.presentationDefinition)
            } catch {
                presentationDefinition = nil
            }
            queryItem = presentationDefinition?.inputDescriptors?[index ?? 0]
        } else if let dcql = presentationRequest?.dcqlQuery {
            queryItem = dcql.credentials[index ?? 0]
        }
        var transactionData: String? = nil
        if !(presentationRequest?.transactionData?.isEmpty ?? true) {
            transactionData = presentationRequest?.transactionData?.first
            if checkTransactionDataWithMultipleInputDescriptors(queryItem: queryItem, transactionDataItem: transactionData) {
                claims["transaction_data_hashes"] = [self.generateHash(input: transactionData ?? "")]
                claims["transaction_data_hashes_alg"] = "sha-256"
            }
        }
        var processedResults: [String] = []
        for item in credentials {
               
               let itemWithTilda = item.hasSuffix("~") ? item : "\(item)~"
               
               if let keyBindingJwt = await KeyBindingJwtService().generateKeyBindingJwt(
                   issuerSignedJwt: itemWithTilda,
                   claims: claims,
                   keyHandler: keyHandler
               ) {
                   processedResults.append("\(itemWithTilda)\(keyBindingJwt)")
               } else {
                   processedResults.append(item)
               }
           }
        return processedResults
    }
    
    func checkTransactionDataWithMultipleInputDescriptors(queryItem: Any?,
                                                          transactionDataItem: String?) -> Bool {
        var id: String?
        if let inputDescriptor = queryItem as? InputDescriptor {
            id = inputDescriptor.id
        } else if let credentialItem = queryItem as? CredentialItems {
            id = credentialItem.id
        }
        let decodedTransactionData = transactionDataItem?.decodeBase64() ?? ""
        let transactionDataDict = UIApplicationUtils.shared.convertToDictionary(text: decodedTransactionData)
        let credIdsArray = transactionDataDict?["credential_ids"] as? [String]
        guard let inputDescriptorId = id else { return false }
        return credIdsArray?.contains(inputDescriptorId) ?? false
    }
    
    func generateHash(input: String) -> String? {
        guard let data = input.data(using: .utf8) else { return nil }
        
        let hash = Data(SHA256.hash(data: data))
        
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
