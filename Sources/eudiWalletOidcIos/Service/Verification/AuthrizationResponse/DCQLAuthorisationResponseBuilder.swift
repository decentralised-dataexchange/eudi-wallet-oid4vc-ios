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
               did: String, keyHandler: SecureKeyProtocol) async -> [String: Any]{
        
        var params: [String: Any] = [:]
        
        guard let dcqlCredentials = presentationRequest?.dcqlQuery?.credentials,
              let credentialsList = credentialsList,
              dcqlCredentials.count == credentialsList.count else {
            print("Mismatch or missing data in dcqlQuery or credentialsList")
            return params
        }
        
        var credentialMap: [String: Any] = [:]
        
        for (index, credential) in dcqlCredentials.enumerated() {
            
                   var hasDoctype = false
                    var format = credential.format ?? ""
                   switch credential.meta {
                   case .msoMdoc(let meta):
                       hasDoctype = !meta.doctypeValue.isEmpty
                   case .dcSDJWT:
                       hasDoctype = false
                   case .jwt:
                       hasDoctype = false
                   }
            let generatedVPToken = await generateVpTokensBasedOfCredntialFormat(credential: credentialsList[index], presentationRequest: presentationRequest, did: did, isMdoc: hasDoctype, index: index, keyHandler: keyHandler, format: format)
            let clientDataString = presentationRequest?.clientMetaData?.replacingOccurrences(of: "+", with: " ")
            let clientMetadataJson = clientDataString?.data(using: .utf8)!
            var clientMetaDataModel: ClientMetaData? = nil
            if let data = clientMetadataJson {
                clientMetaDataModel = try? JSONDecoder().decode(eudiWalletOidcIos.ClientMetaData.self, from: data)
            }
            
            var generatedToken: Any? = nil
            if let version = clientMetaDataModel?.version, version == "draft_23" {
                generatedToken = generatedVPToken.first
            } else {
                generatedToken = generatedVPToken
            }
            if !generatedVPToken.isEmpty {
                credentialMap[credential.id] = generatedToken
            }
        }
        // Example: embed this dictionary in a vp_token structure
        let mainVpToken = generateMainVPToken(from: credentialMap)
        
        params["vp_token"] = mainVpToken
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
    
    private func generateVpTokensBasedOfCredntialFormat(credential:[String],
                                                        presentationRequest: PresentationRequest?,
                                                        did: String,
                                                        isMdoc: Bool, index: Int, keyHandler: SecureKeyProtocol, format: String) async -> [String] {
        if format == "mso_mdoc"  {
            return MDocVpTokenBuilder().build(credentials: credential, presentationRequest: presentationRequest ?? nil, did: did, index: index, keyHandler: keyHandler) ?? []
        } else if format == "jwt_vc_json"  {
            return await JWTVpTokenBuilder().build(credentials: credential, presentationRequest: presentationRequest, did: did, index: index, keyHandler: keyHandler) ?? []
        } else {
            return await SDJWTVpTokenBuilder().build(credentials: credential, presentationRequest: presentationRequest, did: did, index: index, keyHandler: keyHandler) ?? []
        }
    }
}
