//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation

class DCQLAuthorisationResponseBuilder {
    
    func build(credentialsList: [[String]]?,
               presentationRequest: PresentationRequest?,
               did: String, keyHandler: SecureKeyProtocol, isSca: Bool, keyIds: [[String]], isEncrypted: Bool = false, amrInherenceFactor: String?, amrKnowledgeFactor: String?) async -> [String: Any]{
        
        var params: [String: Any] = [:]
        
        guard let request = presentationRequest,
              let dcqlCredentials = request.dcqlQuery?.credentials,
              let credentialsList = credentialsList,
              dcqlCredentials.count == credentialsList.count else {
            print("Mismatch or missing data in dcqlQuery or credentialsList")
            return params
        }
        
        // One SelectedCredential per non-blank credential, named by its credential query; a
        // missing key id falls back to the holder key instead of crashing.
        var selected: [SelectedCredential] = []
        for (index, entry) in dcqlCredentials.enumerated() {
            let ids = index < keyIds.count ? keyIds[index] : []
            for (position, credential) in credentialsList[index].enumerated()
            where !credential.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                selected.append(SelectedCredential(entryId: entry.id, credential: credential,
                                                   keyId: position < ids.count ? ids[position] : nil))
            }
        }
        let inputs = PresentationInputs(
            request: request,
            holderDid: did,
            holderKey: keyHandler,
            transactionDataHashes: LegacyTransactionData.hashes(presentationRequest, entryIds: dcqlCredentials.map { $0.id }),
            strongCustomerAuthentication: LegacyTransactionData.isStrongCustomerAuthentication(presentationRequest, flag: isSca),
            authentication: AuthenticationMethods(inherence: amrInherenceFactor, knowledge: amrKnowledgeFactor))
        let presentations = (try? await PresentationBuilder(lenient: true).build(selected, inputs: inputs)) ?? []

        let clientDataString = presentationRequest?.clientMetaData?.replacingOccurrences(of: "+", with: " ")
        let clientMetaDataModel = clientDataString?.data(using: .utf8)
            .flatMap { try? JSONDecoder().decode(eudiWalletOidcIos.ClientMetaData.self, from: $0) }
        let isDraft23 = clientMetaDataModel?.version == "draft_23"

        var credentialMap: [String: Any] = [:]
        for entry in dcqlCredentials {
            let tokens = presentations.filter { $0.entryId == entry.id }.map { $0.token }
            guard !tokens.isEmpty else { continue }
            credentialMap[entry.id] = isDraft23 ? tokens[0] : tokens
        }
        // Example: embed this dictionary in a vp_token structure
        let mainVpToken = generateMainVPToken(from: credentialMap)
        if isEncrypted {
            params["vp_token"] = credentialMap
        } else {
            params["vp_token"] = mainVpToken
        }
        params["state"] = presentationRequest?.state ?? ""
        
        return params
    }
    
    private func generateMainVPToken(from credentialMap: [String: Any]) -> String {
        // Replace with actual VP token generation logic (JWS/JWT/JWE etc.)
        // For now, we just JSON-encode it
        if let jsonData = try? JSONSerialization.data(withJSONObject: credentialMap, options: []),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString // This is a placeholder
        }
        return ""
    }
}
