//
//  VerificationService.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//

import Foundation
import CryptoKit
import PresentationExchangeSdkiOS

public class VerificationService: VerificationServiceProtocol {
    
    static var shared = VerificationService()
    private init() {}
    
    // MARK: - Sends a Verifiable Presentation (VP) token asynchronously.
    public func sendVPToken(
        did: String,
        privateKey: P256.Signing.PrivateKey,
        presentationRequest: PresentationRequest?,
        credentialsList: [String]?) async -> Data? {
        
        let jwk = generateJWKFromPrivateKey(privateKey: privateKey, did: did)
        
        // Generate JWT header
        let header = generateJWTHeader(jwk: jwk, did: did)
        
        // Generate JWT payload
        let payload = generateJWTPayload(did: did, nonce: presentationRequest?.nonce ?? "", credentialsList: credentialsList ?? [], state: presentationRequest?.state ?? "", clientID: presentationRequest?.clientId ?? "")
        debugPrint("payload:\(payload)")
        
        let vpToken =  generateVPToken(header: header, payload: payload, privateKey: privateKey)
        
        // Presentation Submission model
        guard let presentationSubmission = preparePresentationSubmission() else { return nil }
        
        return await sendVPRequest(vpToken: vpToken, presentationSubmission: presentationSubmission, redirectURI: presentationRequest?.redirectUri ?? "", state: presentationRequest?.state ?? "")
    }
    
    private func generateJWKFromPrivateKey(privateKey: P256.Signing.PrivateKey, did: String) -> [String: Any] {
        let rawRepresentation = privateKey.publicKey.rawRepresentation
        let x = rawRepresentation[rawRepresentation.startIndex..<rawRepresentation.index(rawRepresentation.startIndex, offsetBy: 32)]
        let y = rawRepresentation[rawRepresentation.index(rawRepresentation.startIndex, offsetBy: 32)..<rawRepresentation.endIndex]
        return [
            "crv": "P-256",
            "kty": "EC",
            "x": x.urlSafeBase64EncodedString(),
            "y": y.urlSafeBase64EncodedString()
        ]
    }
    
    
    public func processAuthorisationRequest(data: String?) async -> PresentationRequest? {
        guard let _ = data else { return nil }
        
        if let code = data {
            let state = URL(string: code)?.queryParameters?["state"] ?? ""
            let nonce = URL(string: code)?.queryParameters?["nonce"] ?? ""
            let redirectUri = URL(string: code)?.queryParameters?["redirect_uri"] ?? ""
            let clientID = URL(string: code)?.queryParameters?["client_id"] ?? ""
            let responseType = URL(string: code)?.queryParameters?["response_type"] ?? ""
            let scope = URL(string: code)?.queryParameters?["scope"] ?? ""
            let requestUri = URL(string: code)?.queryParameters?["request_uri"] ?? ""
            let responseUri = URL(string: code)?.queryParameters?["response_uri"] ?? ""
            let responseMode = URL(string: code)?.queryParameters?["response_mode"] ?? ""
            let presentationDefinition = URL(string: code)?.queryParameters?["presentation_definition"] ?? ""
            
            if presentationDefinition != "" {
                let presentationRequest = PresentationRequest(state: state,
                                                              clientId: clientID,
                                                              redirectUri: redirectUri,
                                                              responseType: responseType,
                                                              responseMode: responseMode,
                                                              scope: scope,
                                                              nonce: nonce,
                                                              requestUri: requestUri,
                                                              presentationDefinition: presentationDefinition)
                
                return presentationRequest
            } else if requestUri != "" {
                var request = URLRequest(url: URL(string: requestUri)!)
                request.httpMethod = "GET"
                
                do {
                    let (data, _) = try await URLSession.shared.data(for: request)
                    let jsonDecoder = JSONDecoder()
                    let model = try? jsonDecoder.decode(PresentationRequest.self, from: data)
                    if model == nil {
                        _ = Error(message:"Invalid DID", code: nil)
                        return nil
                    }
                    return model
                } catch {
                    
                }
            }
        }
        
        return nil
    }
    
    private func generateJWTHeader(jwk: [String: Any], did: String) -> String {
        let methodSpecificId = did.replacingOccurrences(of: "did:key:", with: "")
        
        return ([
            "alg": "ES256",
            "kid": "\(did)#\(methodSpecificId)",
            "typ": "JWT",
            "jwk": jwk
        ] as [String : Any]).toString() ?? ""
    }
    
    private func generateJWTPayload(did: String, nonce: String, credentialsList: [String], state: String, clientID: String) -> String {
        let vp =
        ([
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "holder": did,
            "id": "urn:uuid:\(UUID().uuidString)",
            "type": [
                "VerifiablePresentation"
            ],
            "verifiableCredential": credentialsList
        ] as [String : Any])
        
        let currentTime = Int(Date().timeIntervalSince1970)
        let uuid4 = UUID().uuidString
        
        return ([
            "aud": clientID,
            "exp": currentTime + 3600,
            "iat": currentTime,
            "iss": "\(did)",
            "jti": "urn:uuid:\(uuid4)",
            "nbf": currentTime,
            "nonce": "\(nonce)",
            "sub": "\(did)",
            "vp": vp,
        ] as [String : Any]).toString() ?? ""
    }
    
    private func generateVPToken(header: String, payload: String, privateKey: P256.Signing.PrivateKey) -> String {
        let headerData = Data(header.utf8)
        let payloadData = Data(payload.utf8)
        let unsignedToken = "\(headerData.base64URLEncodedString()).\(payloadData.base64URLEncodedString())"
        let signatureData = try? privateKey.signature(for: unsignedToken.data(using: .utf8)!)
        let signature = signatureData?.rawRepresentation
        return "\(unsignedToken).\(signature?.base64URLEncodedString() ?? "")"
    }
    
    private func preparePresentationSubmission() -> PresentationSubmissionModel? {
//        if !isVPExchange && !isPassportExchange {
//            var descMaps = [DescriptorMap]()
//            for i in 0..<(presentationDefinitionModel?.inputDescriptors?.count ?? 1) {
//                descMaps.append(DescriptorMap(id: presentationDefinitionModel?.inputDescriptors?[i].id ?? "", path: "$", format: "jwt_vp", pathNested: DescriptorMap(id: presentationDefinitionModel?.inputDescriptors?[i].id ?? "", path: "$.verifiableCredential[\(i)]", format: "jwt_vc", pathNested: nil)))
//            }
//            return PresentationSubmissionModel(id: "a30e3b91-fb77-4d22-95fa-871689c322e2", definitionID: "holder-wallet-qualification-presentation", descriptorMap: descMaps)
//        } else if isPassportExchange {
//            let uuid = UUID().uuidString
//            let component = nonce
//            let dict = UIApplicationUtils.shared.convertToDictionary(text: component)
//            guard let data = try? JSONSerialization.data(withJSONObject: dict ?? [:]) else { return nil }
//            let elements = try? JSONDecoder().decode(PresentationDefinitionModel.self, from: data)
//
//            let pathNested = DescriptorMap(id: elements?.inputDescriptors?[0].id ?? "", path: "$.verifiableCredential[0]", format: "jwt_vc", pathNested: nil)
//            let descMap = [
//                DescriptorMap(id: elements?.inputDescriptors?[0].id ?? "", path: "$", format: "jwt_vp", pathNested: pathNested)]
//            return PresentationSubmissionModel(id: uuid, definitionID: elements?.id ?? "", descriptorMap: descMap)
//        } else {
            let pathNested = DescriptorMap(id: "vp1", path: "$.verifiableCredential[0]", format: "jwt_vc", pathNested: nil)
            let descMap = [
                DescriptorMap(id: "vp1", path: "$", format: "jwt_vp", pathNested: pathNested)]
            return PresentationSubmissionModel(id: "essppda1", definitionID: "essppda1", descriptorMap: descMap)
 //       }
    }
    
    private func sendVPRequest(vpToken: String, presentationSubmission: PresentationSubmissionModel, redirectURI: String, state: String) async -> Data? {
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
        
        let params = ["vp_token": vpToken, "presentation_submission": json.toString() ?? "", "state": state] as [String: Any]
        let postString = UIApplicationUtils.shared.getPostString(params: params)
        let paramsData = postString.data(using: .utf8)
        
        var request = URLRequest(url: URL(string: redirectURI)!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = paramsData
        
        // Performing the token request
        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            return data
        } catch {
            debugPrint("JSON Serialization Error: \(error)")
            return nil
        }
    }
    
    
   public func processPresentationDefinition(_ presentationDefinition: Any?) throws -> PresentationDefinitionModel {
       do {
           guard let presentationDefinition = presentationDefinition else {
               throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid presentation definition"])
           }
           
           if let presentationDefinition = presentationDefinition as? PresentationDefinitionModel {
               return presentationDefinition
           } else if let linkedTreeMap = presentationDefinition as? [AnyHashable: Any] {
               let jsonData = try JSONSerialization.data(withJSONObject: linkedTreeMap)
               let jsonString = String(data: jsonData, encoding: .utf8) ?? ""
               return try JSONDecoder().decode(PresentationDefinitionModel.self, from: jsonString.data(using: .utf8) ?? Data())
           } else if let jsonString = presentationDefinition as? String {
               let str = jsonString.replacingOccurrences(of: "+", with: "")
               let data = str.data(using: .utf8)
               let model = try JSONDecoder().decode(PresentationDefinitionModel.self, from: data!)
               return model
           } else {
               throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid presentation definition format"])
           }
       } catch {
            throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Error processing presentation definition"])
        }
    }

    public func filterCredentials(credentialList: [String?], presentationDefinition: PresentationDefinitionModel) -> [[String]] {
        var response: [[String]] = []
        
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
          
            let vcString = if let vc = json?["vc"] as? [String: Any] {
                vc.toString() ?? ""
            } else {
                 jsonString
            }
            
            processedCredentials.append(vcString)
        }
        
        if let inputDescriptors = presentationDefinition.inputDescriptors {
            for inputDescriptor in inputDescriptors {
                var filteredCredentialList: [String] = []
                
                let jsonEncoder = JSONEncoder()
                jsonEncoder.keyEncodingStrategy = .convertToSnakeCase
                guard let jsonData = try? jsonEncoder.encode(inputDescriptor),
                      let dictionary = try? JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] else {
                    fatalError("Failed to convert Person to dictionary")
                }

                // Convert the dictionary to a string
                guard let inputDescriptorString = String(data: try! JSONSerialization.data(withJSONObject: dictionary, options: .withoutEscapingSlashes), encoding: .utf8) else {
                    fatalError("Failed to convert dictionary to string")
                }
                
                let matchesString = matchCredentials(inputDescriptorJson: inputDescriptorString, credentials: processedCredentials)

                // Assuming `matchesString` contains a JSON array of matches
                if let matchesData = matchesString.data(using: .utf8),
                   let matchesArray = try? JSONSerialization.jsonObject(with: matchesData) as? [String: Any] {
                    for index in 0..<matchesArray.count {
                        if index < credentialList.count {
                            filteredCredentialList.append(credentialList[index] ?? "")
                        }
                    }
                }
                
                response.append(filteredCredentialList)
            }
        }
        
        return response
    }
}
