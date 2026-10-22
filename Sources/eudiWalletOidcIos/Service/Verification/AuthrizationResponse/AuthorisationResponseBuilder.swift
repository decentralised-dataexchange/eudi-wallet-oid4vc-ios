//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation

class AuthorisationResponseBuilder {
    
    static func buildResponse(
        credentialsList: [[String]]?,
        presentationRequest: PresentationRequest?,
        did: String, keyHandler: SecureKeyProtocol, isSca: Bool, keyIds: [[String]] = [], isEncrypted: Bool = false, amrInherenceFactor: String?, amrKnowledgeFactor: String?) async -> [String: Any] {
        
        var params: [String: Any] = [:]
        
        if let dcql = presentationRequest?.dcqlQuery {
            //Fixme: handle DCQL response
            params = await DCQLAuthorisationResponseBuilder().build(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler, isSca: isSca, keyIds: keyIds, isEncrypted: isEncrypted, amrInherenceFactor: amrInherenceFactor, amrKnowledgeFactor: amrKnowledgeFactor)
            return params
        }else{
            var credentialsArray: [String]? = []
            var credentialKeyIDs: [String] = []
            for item in credentialsList ?? [] {
                credentialsArray?.append(item.first ?? "")
            }
            for keyId in keyIds {
                credentialKeyIDs.append((keyId.first ?? ""))
            }
            let tokensAndPresentationSubmission = await createVPTokenAndPresentationSubmission(
                credentialsList: credentialsArray,
                did: did,
                presentationRequest: presentationRequest, keyHandler: keyHandler, keyIds: credentialKeyIDs
            )
            
            // Handle vp_token
            if presentationRequest?.responseType?.contains("vp_token") ?? false {
                // appending vp_token to params
                let token = tokensAndPresentationSubmission.0
                // Use single token if only one exists, else array
                let vpToken: Any = (token.count == 1) ? token[0] : token
                params["vp_token"] = vpToken
                
                // appending presentation_submission to params
                let presentationSubmission = tokensAndPresentationSubmission.1
                let encoder = JSONEncoder()
                encoder.keyEncodingStrategy = .convertToSnakeCase
                let data = try? encoder.encode(presentationSubmission)
                var json = [String: Any]()
                do {
                    let jsonObj = try JSONSerialization.jsonObject(with: data!, options: .mutableContainers)
                    json = jsonObj as! [String : Any]
                } catch let myJSONError {
                    debugPrint(myJSONError)
                }
                
                var resultDict: [String: Any]? = [:]
                for (key, value) in json {
                    if let valueData = value as? String {
                        resultDict?[key] = valueData
                    } else if let arrayValue = value as? [[String: Any]] {
                        let stringifiedArray = arrayValue.map { dict in
                            var stringDict: [String: String] = [:]
                            for (k, v) in dict {
                                stringDict[k] = "\(v)"
                            }
                            return stringDict
                        }
                        resultDict?[key] = stringifiedArray
                    }
                    else {
                        resultDict?[key] = value
                    }
                }
                
                params["presentation_submission"] = json
            }
            
            // Handle id_token
            if presentationRequest?.responseType?.contains("id_token") ?? false {
                let idToken = tokensAndPresentationSubmission.2
                params["id_token"] = idToken
            }
            
            // Always include state if available
            if let state = presentationRequest?.state {
                params["state"] = state
            }
            
            return params
        }
    }
    
    static func createVPTokenAndPresentationSubmission(credentialsList: [String]?, did: String, presentationRequest: PresentationRequest?, keyHandler: SecureKeyProtocol, keyIds: [String]) async -> ([String], PresentationSubmissionModel?, String){
        let presentationDefinition = try? VerificationService.processPresentationDefinition(presentationRequest?.presentationDefinition)
        var vpTokenList: [String] = []
        var idToken: String = ""
        var presentationSubmission: PresentationSubmissionModel? = nil

        // checking if credential list is empty or not, if empty return
        // Fixme: what if only id token needed ?
        guard let credentialsList = credentialsList else { return ([], nil, "")}

        if let request = presentationRequest, let resType = request.responseType, resType.contains("vp_token") {
            // Credential i answers input descriptor i; a missing key id falls back to the holder key.
            let descriptors = presentationDefinition?.inputDescriptors ?? []
            let selected = credentialsList.enumerated().map { index, credential in
                SelectedCredential(entryId: index < descriptors.count ? descriptors[index].id ?? "" : "",
                                   credential: credential, keyId: index < keyIds.count ? keyIds[index] : nil)
            }
            let inputs = PresentationInputs(
                request: request,
                holderDid: did,
                holderKey: keyHandler,
                transactionDataHashes: LegacyTransactionData.hashes(request, entryIds: selected.map { $0.entryId }))
            let presentations = (try? await PresentationBuilder(lenient: true).build(selected, inputs: inputs)) ?? []
            vpTokenList = presentations.map { $0.token }
            presentationSubmission = PresentationSubmissionBuilder().build(presentations, definition: presentationDefinition)
        }

        if let resType = presentationRequest?.responseType, resType.contains("id_token") {
            idToken =  await generateJWTokenForIDtokenRequest(didKeyIdentifier: did, authorizationEndpoint: presentationRequest?.clientId ?? "", nonce: presentationRequest?.nonce ?? "", keyHandler: keyHandler)
        }

        return (vpTokenList, presentationSubmission, idToken)
    }
    
    static func generateJWTokenForIDtokenRequest(
            didKeyIdentifier: String,
            authorizationEndpoint: String,
            nonce: String, keyHandler: SecureKeyProtocol
           ) async -> String{
            // Generate JWT header
            let header =
            ([
                "typ": "JWT",
                "alg": "ES256",
                "kid": "\(didKeyIdentifier)#\(didKeyIdentifier.replacingOccurrences(of: "did:key:", with: ""))"
            ]).toString() ?? ""
            
            // Generate JWT payload
            let currentTime = Int(Date().timeIntervalSince1970)
            let payload =
            ([
                "iss": "\(didKeyIdentifier)",
                "sub": "\(didKeyIdentifier)",
                "aud": "\(authorizationEndpoint)",
                "exp": currentTime + 3600,
                "iat": currentTime,
                "nonce": "\(nonce)"
            ] as [String : Any]).toString() ?? ""
            
            // Create JWT token
            let headerData = Data(header.utf8)
            let payloadData = Data(payload.utf8)
            
            let secureData = await keyHandler.generateSecureKey()
                guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.privateKey) else{return ""}
            return idToken
        }
    
    static func fetchFormat(presentationDefinition: PresentationDefinitionModel?, index: Int) -> String {
        var credentialFormat: String = ""
        var credentialFormatString: String = ""
        var inputDescriptorFromat: String = ""
        var presentationDefinitionFormat: String = ""
        if var format = presentationDefinition?.inputDescriptors?[index].format ?? presentationDefinition?.format {
            for (key, _) in format {
                credentialFormat = key
            }
        }
        if credentialFormat == "vcsd-jwt" || credentialFormat == "vpsd-jwt"{
            credentialFormatString = "vc+sd-jwt"
        } else if credentialFormat == "dcsd-jwt" {
            credentialFormatString = "dc+sd-jwt"
        } else {
            credentialFormatString = credentialFormat
        }
        
        guard let encodedFormat = credentialFormatString.addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed.union(CharacterSet(charactersIn: "+")).subtracting(CharacterSet(charactersIn: "+")))?.replacingOccurrences(of: "+", with: "%2B") else { return ""}
        if var format = presentationDefinition?.inputDescriptors?[index].format  {
            for (key, _) in format {
                inputDescriptorFromat = key
            }
        }
        if var format = presentationDefinition?.format  {
            for (key, _) in format {
                presentationDefinitionFormat = key
            }
        }
        if inputDescriptorFromat.contains("jwt_vp") {
            return "jwt_vp"
        }
        if inputDescriptorFromat.contains("jwt_vp_json") {
            return "jwt_vp_json"
        }
        if presentationDefinitionFormat.contains("jwt_vp")  {
            return "jwt_vp"
        }
        if  presentationDefinitionFormat.contains("jwt_vp_json") {
            return "jwt_vp_json"
        }
        return credentialFormatString
    }
}
