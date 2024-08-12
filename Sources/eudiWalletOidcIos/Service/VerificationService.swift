//
//  VerificationService.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//
import Foundation
import CryptoKit
import PresentationExchangeSdkiOS
public class VerificationService: NSObject, VerificationServiceProtocol {
    
    var keyHandler: SecureKeyProtocol
    
    // MARK: - A custom initialiser with dependency injection for encryption key generation handler
    ///
    /// - Parameters:
    ///   - keyhandler: A handler to encryption key generation class
    /// - Returns: An `VerificationService` object
    public required init(keyhandler: SecureKeyProtocol) {
        keyHandler = keyhandler
    }
    
    // MARK: - Sends a Verifiable Presentation (VP) token asynchronously.
    public func sendVPToken(
        did: String,
        secureKey: SecureKeyData,
        presentationRequest: PresentationRequest?,
        credentialsList: [String]?) async -> WrappedVerificationResponse? {
            
            let jwk = generateJWKFromPrivateKey(secureKey: secureKey, did: did)
            
            // Generate JWT header
            let header = generateJWTHeader(jwk: jwk, did: did)
            
            // Generate JWT payload
            let payload = generateJWTPayload(did: did, nonce: presentationRequest?.nonce ?? "", credentialsList: credentialsList ?? [], state: presentationRequest?.state ?? "", clientID: presentationRequest?.clientId ?? "")
            debugPrint("payload:\(payload)")
            
            let vpToken =  generateVPToken(header: header, payload: payload, secureKey: secureKey)
            
            // Presentation Submission model
            guard let presentationSubmission = preparePresentationSubmission(presentationRequest: presentationRequest) else { return nil }
        
        guard let redirectURL = presentationRequest?.redirectUri else {return nil}
        return await sendVPRequest(vpToken: vpToken, presentationSubmission: presentationSubmission, redirectURI: presentationRequest?.redirectUri ?? "", state: presentationRequest?.state ?? "")
    }
    
    private func generateJWKFromPrivateKey(secureKey: SecureKeyData, did: String) -> [String: Any] {
        let rawRepresentation = secureKey.publicKey
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
            var presentationDefinition = URL(string: code)?.queryParameters?["presentation_definition"] ?? ""
            
            if presentationDefinition != "" {
                
                let presentationRequest =  PresentationRequest(state: state,
                                                               clientId: clientID,
                                                               redirectUri: redirectUri,
                                                               responseUri: responseUri,
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
                        if let jwtString = String(data: data, encoding: .utf8) {
                            do {
                                let segments = jwtString.split(separator: ".")
                                if segments.count == 3 {
                                    // Decoding received JWT here
                                    guard let jsonPayload = try? jwtString.decodeJWT(jwtToken: jwtString) else { return nil }
                                    guard let data = try? JSONSerialization.data(withJSONObject: jsonPayload, options: []) else { return nil }
                                    let model = try jsonDecoder.decode(PresentationRequest.self, from: data)
                                    return model
                                }
                            } catch {
                                debugPrint("Error:\(error)")
                            }
                        } else {
                            let error = EUDIError(from: ErrorResponse(message:"Invalid DID", code: nil))
                            debugPrint(error)
                            return nil
                        }
                    }
                    return model
                } catch {
                    debugPrint("Error:\(error)")
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
        let uuid4 = UUID().uuidString
        let vp =
        ([
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "holder": did,
            "id": "urn:uuid:\(uuid4)",
            "type": [
                "VerifiablePresentation"
            ],
            "verifiableCredential": credentialsList
        ] as [String : Any])
        
        let currentTime = Int(Date().timeIntervalSince1970)
        
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
    
    private func generateVPToken(header: String, payload: String, secureKey: SecureKeyData) -> String {
        let headerData = Data(header.utf8)
        //let payloadData = Data(payload.utf8)
        //let unsignedToken = "\(headerData.base64URLEncodedString()).\(payloadData.base64URLEncodedString())"
        //let signatureData = try? privateKey.signature(for: unsignedToken.data(using: .utf8)!)
        //let signature = signatureData?.rawRepresentation
        guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureKey.privateKey) else{return ""}
        //guard let signature = keyHandler.sign(data: unsignedToken.data(using: .utf8)!, withKey: secureKey.privateKey) else{return ""}
        return idToken//"\(unsignedToken).\(signature.base64URLEncodedString() ?? "")"
    }
    
    private func preparePresentationSubmission(
        presentationRequest: PresentationRequest?
    ) -> PresentationSubmissionModel? {
        if presentationRequest == nil { return nil }
        var descMap : [DescriptorMap] = []
        var presentationDefinition :PresentationDefinitionModel? = nil
        do {
            presentationDefinition = try VerificationService.processPresentationDefinition(presentationRequest?.presentationDefinition)
        } catch {
            presentationDefinition = nil
        }
        //encoding is done because '+' was removed by the URL session
        let formatKey = presentationDefinition?.format?.first(where: { key, _ in key.contains("vc") })?.key ?? ""
        let format = formatKey == "vcsd-jwt" ? "vc+sd-jwt" : formatKey
        let encodedFormat = format.addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed.union(CharacterSet(charactersIn: "+")).subtracting(CharacterSet(charactersIn: "+")))?.replacingOccurrences(of: "+", with: "%2B")
        if let inputDescriptors = presentationDefinition?.inputDescriptors {
            for index in 0..<inputDescriptors.count {
                let item = inputDescriptors[index]
                let pathNested = DescriptorMap(id: item.id ?? "", path: "$.vp.verifiableCredential[\(index)]", format: "jwt_vc", pathNested: nil)
                
                descMap.append(DescriptorMap(id: item.id ?? "", path: "$", format: encodedFormat ?? "", pathNested: pathNested))
            }
        }
        
        
        return PresentationSubmissionModel(id: UUID().uuidString, definitionID: presentationDefinition?.id ?? "", descriptorMap: descMap)
    }
    
    private func sendVPRequest(vpToken: String, presentationSubmission: PresentationSubmissionModel, redirectURI: String, state: String) async -> WrappedVerificationResponse? {
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
        var responseUrl = ""
        do {
            let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
            
            let (data, response) = try await session.data(for: request)
            
            
            let httpres = response as? HTTPURLResponse
            
            if httpres?.statusCode == 302 || httpres?.statusCode == 200 {
                if let location = httpres?.value(forHTTPHeaderField: "Location") {
                    responseUrl = location
                    return WrappedVerificationResponse(data: responseUrl, error: nil)
                } else {
                    return WrappedVerificationResponse(data: "https://www.example.com?code=1", error: nil)
                }
            } else if httpres?.statusCode ?? 400 >= 400 {
                return WrappedVerificationResponse(data: nil, error: ErrorHandler.processError(data: data))
            } else{
                guard let dataString = String(data: data, encoding: .utf8) else {
                    return WrappedVerificationResponse(data: "data", error: nil)
                }
                return WrappedVerificationResponse(data: dataString, error: nil)
            }
        } catch {
            debugPrint("JSON Serialization Error: \(error)")
            return nil
        }
    }
    
    
    public static func processPresentationDefinition(_ presentationDefinition: Any?) throws -> PresentationDefinitionModel {
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
        
        if let inputDescriptors = presentationDefinition.inputDescriptors {
            for inputDescriptor in inputDescriptors {
                
                let tempCredentialList = splitCredentialsBySdJWT(allCredentials: credentialList, isSdJwt: inputDescriptor.constraints?.limitDisclosure != nil)
                
                let processedCredentials = processCredentialsToJsonString(credentialList: tempCredentialList)
                
                let updatedDescriptor = updatePath(in: inputDescriptor)
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
                    for item in matchesString {
                        filteredCredentialList.append(tempCredentialList[item.index] ?? "")
                    }
                } catch {
                    print("error")
                }
                response.append(filteredCredentialList)
            }
        }
        
        return response
    }
    
    private func splitCredentialsBySdJWT(allCredentials: [String?], isSdJwt: Bool) -> [String?] {
        var filteredCredentials: [String?] = []
        for item in allCredentials {
            if isSdJwt == true,
               item?.contains("~") == true {
                filteredCredentials.append(item)
            } else if isSdJwt == false,
                      item?.contains("~") == false {
                filteredCredentials.append(item)
            }
        }
        return filteredCredentials
    }
    
    private func processCredentialsToJsonString(credentialList: [String?]) -> [String] {
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
extension VerificationService: URLSessionDelegate, URLSessionTaskDelegate {
    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            // Stops the redirection, and returns (internally) the response body.
            completionHandler(nil)
        }
    }
