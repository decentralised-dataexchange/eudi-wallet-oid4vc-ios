//
//  VerificationService.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//
import Foundation
import CryptoKit
import PresentationExchangeSdkiOS
import SwiftCBOR
import OrderedCollections
import Security
import ASN1Decoder


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
    
    
    public func processOrSendAuthorizationResponse(
        did: String,
        presentationRequest: PresentationRequest?,
        credentialsList: [[String]]?,
        wua: String,
        pop: String) async -> WrappedVerificationResponse? {
            
            let params = await AuthorisationResponseHandler().prepareAuthorisationResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler) ?? [:]
            guard let redirectURL = presentationRequest?.redirectUri else {return nil}
            return await sendVPRequest(params: params, redirectURI: presentationRequest?.redirectUri ?? "", wua: wua, pop: pop)
        }
    
    public func processAuthorisationRequest(data: String?) async -> (PresentationRequest?, EUDIError?) {
            guard let _ = data else { return (nil, nil) }
            
            if let code = data {
                let state = URL(string: code)?.queryParameters?["state"] ?? ""
                let nonce = URL(string: code)?.queryParameters?["nonce"] ?? ""
                let responseUri = URL(string: code)?.queryParameters?["response_uri"] ?? ""
                let redirectUri = URL(string: code)?.queryParameters?["redirect_uri"] ?? responseUri
                let clientID = URL(string: code)?.queryParameters?["client_id"] ?? ""
                let responseType = URL(string: code)?.queryParameters?["response_type"] ?? ""
                let scope = URL(string: code)?.queryParameters?["scope"] ?? ""
                let requestUri = URL(string: code)?.queryParameters?["request_uri"] ?? ""
                let responseMode = URL(string: code)?.queryParameters?["response_mode"] ?? ""
                var presentationDefinition = URL(string: code)?.queryParameters?["presentation_definition"] ?? ""
                var clientMetaData = URL(string: code)?.queryParameters?["client_metadata"] ?? ""
                var presentationDefinitionUri = URL(string: code)?.queryParameters?["presentation_definition_uri"] ?? ""
                var clientMetaDataUri = URL(string: code)?.queryParameters?["client_metadata_uri"] ?? ""
                var clientIDScheme = URL(string: code)?.queryParameters?["client_id_scheme"] ?? ""
                var dcql = ""
                var authSession = URL(string: code)?.queryParameters?["auth_session"] ?? ""
                var openid4vpRequest = URL(string: code)?.queryParameters?["openid4vp_request"] ?? ""
                var request = ""
                var dcqlQueryModel: DCQLQuery? = nil
                if URL(string: code)?.queryParameters?["type"] == "openid4vp_presentation" {
                    if let openid4vpRequest = URL(string: code)?.queryParameters?["openid4vp_request"] as? String,
                       let jsonData = openid4vpRequest.data(using: .utf8) {
                        
                        do {
                            let requestDict = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any]
                            if let requestString = requestDict?["request"] as? String {
                                request = requestString ?? ""
                            }
                            if let dcqlData = requestDict?["dcql_query"] as? [String: Any] {
                                dcql = dcqlData.toString() ?? ""
                            }
                        } catch {
                            print("Error parsing JSON: \(error)")
                        }
                    }
                } else {
                    request = URL(string: code)?.queryParameters?["request"] ?? ""
                    dcql = URL(string: code)?.queryParameters?["dcql_query"] ?? ""
                }
                if !dcql.isEmpty {
                    if let data = dcql.data(using: .utf8) {
                        do {
                            dcqlQueryModel = try JSONDecoder().decode(DCQLQuery.self, from: data)
                        } catch {
                        }
                    }
                }
                
                if presentationDefinition != "" || presentationDefinitionUri != "" {
                    var presentationRequest =  PresentationRequest(state: state,
                                                                   clientId: clientID,
                                                                   redirectUri: redirectUri ?? responseUri,
                                                                   responseUri: responseUri,
                                                                   responseType: responseType,
                                                                   responseMode: responseMode,
                                                                   scope: scope,
                                                                   nonce: nonce,
                                                                   requestUri: requestUri,
                                                                   presentationDefinition: presentationDefinition,
                                                                   clientMetaData: clientMetaData,
                                                                   presentationDefinitionUri: presentationDefinitionUri, clientMetaDataUri: clientMetaDataUri, clientIDScheme: clientIDScheme, transactionData: [""], dcqlQuery: dcqlQueryModel, request: request, authSession: authSession
                    )
                    if presentationDefinition == "" && presentationDefinitionUri != "" {
                        let presentationDefinitionFromUri = await resolvePresentationDefinitionFromURI(url: presentationDefinitionUri)
                        presentationRequest.presentationDefinition = presentationDefinitionFromUri
                    }
                    if clientMetaData == "" && clientMetaDataUri != "" {
                        let clientMetaDataFromUri = await resolveClientMetaDataFromURI(url: clientMetaDataUri)
                        presentationRequest.clientMetaData = clientMetaDataFromUri
                    }
                    return (presentationRequest, nil)
                    
                } else if openid4vpRequest != "" {
                    var presentationRquestDataModel: PresentationRequest?
                    if request != "" {
                        let split = request.split(separator: ".")
                        var decodedRequest: [String: Any] = [:]
                        var decoded = ""
                        if split.count > 1 {
                            decoded =  "\(split[1])".decodeBase64() ?? ""
                        }
                        if !decoded.isEmpty {
                            if let data = decoded.data(using: .utf8) {
                                do {
                                    presentationRquestDataModel = try JSONDecoder().decode(PresentationRequest.self, from: data)
                                } catch {
                                }
                            }
                        }
                    } else {
                        if let data = openid4vpRequest.data(using: .utf8) {
                            do {
                                presentationRquestDataModel = try JSONDecoder().decode(PresentationRequest.self, from: data)
                            } catch {
                            }
                        }
                    }
                    let resolvedClientID = presentationRquestDataModel?.clientId?.replacingOccurrences(of: "redirect_uri:", with: "")
                    let split = resolvedClientID?.components(separatedBy: "/")
                    let splitValue = split?.dropLast()
                    let updatedClientID = "iar:\(splitValue?.joined(separator: "/") ?? "")/iar"
                    presentationRquestDataModel?.clientId = updatedClientID
                    presentationRquestDataModel?.authSession = authSession
                    presentationRquestDataModel?.type = URL(string: code)?.queryParameters?["type"] ?? ""
                    presentationRquestDataModel?.request = request
                    return (presentationRquestDataModel, nil)
                } else if requestUri != "" {
                    var request = URLRequest(url: URL(string: requestUri)!)
                    request.httpMethod = "GET"
                    
                    do {
                        let (data, response) = try await URLSession.shared.data(for: request)
                        if let res = response as? HTTPURLResponse, res.statusCode >= 400 {
                            let dataString = String(data: data, encoding: .utf8)
                            let errorMsg = ErrorHandler.processError(data: data, contentType: res.value(forHTTPHeaderField: "Content-Type"))
                            return(nil, errorMsg)
                        } else {
                        let jsonDecoder = JSONDecoder()
                        var model = try? jsonDecoder.decode(PresentationRequest.self, from: data)
                        if model == nil {
                            if let jwtString = String(data: data, encoding: .utf8) {
                                do {
                                    let segments = jwtString.split(separator: ".")
                                    if segments.count == 3 {
                                        guard let jsonPayload = try? jwtString.decodeJWT(jwtToken: jwtString) else { return (nil, nil) }
                                        guard let data = try? JSONSerialization.data(withJSONObject: jsonPayload, options: []) else { return (nil, nil) }
                                        var model = try jsonDecoder.decode(PresentationRequest.self, from: data)
                                        let requestData = model.request
                                        if model.request == nil {
                                            model.request = jwtString
                                        } else {
                                            model.request = requestData
                                        }
                                        do {
                                            let updatedModel = try await ClientIdSchemeRequestHandler().handle(jwtRequest: model.request, presentationRequest: model)
                                            return (updatedModel, nil)
                                        } catch  PresentationRequestError.requestValidationFailed {
                                            let error = EUDIError(from: ErrorResponse(message:"Request validation failed", code: nil))
                                            return (nil, error)
                                        }
                                       // model.request = model.request != nil ? model.request : jwtString
                                    }
                                } catch {
                                    debugPrint("Error:\(error)")
                                }
                            } else {
                                let error = EUDIError(from: ErrorResponse(message:"Invalid DID", code: nil))
                                debugPrint(error)
                                return (nil, error)
                            }
                        }
                        if model?.presentationDefinition == nil && model?.presentationDefinitionUri != "" {
                            let presentationDefinitionFromUri = await resolvePresentationDefinitionFromURI(url: model?.presentationDefinitionUri)
                            model?.presentationDefinition = presentationDefinitionFromUri
                        }
                        if model?.clientMetaData == nil && model?.clientMetaDataUri != "" {
                            let clientMetaDataFromUri = await resolveClientMetaDataFromURI(url: model?.clientMetaDataUri)
                            model?.clientMetaData = clientMetaDataFromUri
                        }
                        return (model, nil)
                    }
                    } catch {
                        let errorMsg = EUDIError(from: ErrorResponse(message: error.localizedDescription, code: nil))
                        debugPrint(error)
                        return (nil, errorMsg)
                        debugPrint("Error:\(error)")
                    }
                }
            }
            
            return (nil, nil)
        }
    
    func resolvePresentationDefinitionFromURI(url: String?) async -> String? {
        if let uri = URL(string: url ?? "") {
            var request = URLRequest(url: uri)
            request.httpMethod = "GET"
            do {
                let (data, _) = try await URLSession.shared.data(for: request)
                if let presentationDefinitionFromUri = String(data: data, encoding: .utf8) {
                    return presentationDefinitionFromUri
                } else {
                    debugPrint("Error: Could not resolve presentation_definition from URI")
                    return nil
                }
            } catch {
                debugPrint("Error while fetching presentation_definition from URI: \(error)")
                return nil
            }
        }
        return nil
    }
    
    func resolveClientMetaDataFromURI(url: String?) async -> String? {
        if let uri = URL(string: url ?? "") {
            var request = URLRequest(url: uri)
            request.httpMethod = "GET"
            do {
                let (data, _) = try await URLSession.shared.data(for: request)
                if let clientMetaDataFromUri = String(data: data, encoding: .utf8) {
                    return clientMetaDataFromUri
                } else {
                    debugPrint("Error: Could not resolve presentation_definition from URI")
                    return nil
                }
            } catch {
                debugPrint("Error while fetching presentation_definition from URI: \(error)")
                return nil
            }
        }
        return nil
    }
    
    private func sendVPRequest(params: [String: Any], redirectURI: String, wua: String, pop: String) async -> WrappedVerificationResponse? {
        let postString = UIApplicationUtils.shared.getPostString(params: params)
        let paramsData = postString.data(using: .utf8)
        
        var request = URLRequest(url: URL(string: redirectURI)!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue(wua, forHTTPHeaderField: "OAuth-Client-Attestation")
        request.setValue(pop, forHTTPHeaderField: "OAuth-Client-Attestation-PoP")
        request.httpBody = paramsData
        
        // Performing the token request
        var responseUrl = ""
        do {
            let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
            
            let (data, response) = try await session.data(for: request)
            
            
            let httpres = response as? HTTPURLResponse
            
            if httpres?.statusCode == 302 {
                if let location = httpres?.value(forHTTPHeaderField: "Location") {
                    responseUrl = location
                    let url = URL.init(string: location)
                    if let errorDescription = url?.queryParameters?["error_description"] as? String {
                        let error = errorDescription.replacingOccurrences(of: "+", with: " ").data(using: .utf8)
                        return WrappedVerificationResponse(data: nil, error: ErrorHandler.processError(data: error, contentType: httpres?.value(forHTTPHeaderField: "Content-Type")))
                    } else {
                        return WrappedVerificationResponse(data: responseUrl, error: nil)
                    }
                } else {
                    return WrappedVerificationResponse(data: "https://www.example.com?code=1", error: nil)
                }
            } else if httpres?.statusCode == 200 || httpres?.statusCode == 204 {
                if let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                   let redirectUri = jsonResponse["redirect_uri"] as? String {
                    return WrappedVerificationResponse(data: redirectUri, error: nil)
                } else if let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                          let code = jsonResponse["code"] as? String {
                    return WrappedVerificationResponse(data: "https://www.example.com?code=\(code)", error: nil)
                } else {
                    return WrappedVerificationResponse(data: "https://www.example.com?code=1", error: nil)
                }
            } else if httpres?.statusCode ?? 400 >= 400 {
                return WrappedVerificationResponse(data: nil, error: ErrorHandler.processError(data: data, contentType: httpres?.value(forHTTPHeaderField: "Content-Type")))
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
        
    func extractStatusListFromCBOR(cbor: CBOR) -> (Int?, String?) {
        guard case let CBOR.map(map) = cbor else {
            return (nil, nil)        }
        
        var StatusIndex: Int? = 0
        var StatusUri: String? = ""
        for (key, value) in map {
            if case let CBOR.utf8String(keyString) = key, keyString == "status" {
                if case let CBOR.map(map) = value {
                    for (key, value) in map {
                        if case let CBOR.map(map) = value  {
                            for (key, value) in map {
                                if case let CBOR.utf8String(keyString) = key, keyString == "idx" {
                                    if case let CBOR.unsignedInt(index) = value {
                                        StatusIndex = Int(index)
                                    } else {
                                        print("The value associated with 'docType' is not a string.")
                                    }
                                }
                                if case let CBOR.utf8String(keyString) = key, keyString == "uri" {
                                    if case let CBOR.utf8String(uri) = value {
                                        StatusUri = uri
                                    } else {
                                        print("The value associated with 'docType' is not a string.")
                                    }
                                }
                            }
                        } else {
                            print("The value associated with 'docType' is not a string.")
                        }
                    }
                } else {
                    print("The value associated with 'docType' is not a string.")
                }
            }
        }
        return (StatusIndex, StatusUri)
        
        print("docType not found in the CBOR map.")
    }
    
    func getStatusListItemsFromCbor(cborData: CBOR) -> (Int?, String?) {
        guard case let CBOR.array(elements) = cborData else {
            print("Expected CBOR array, but got something else.")
            return (nil, nil)
        }
        var index: Int? = 0
        var uri: String? = ""
        for element in elements {
            if case let CBOR.byteString(byteString) = element {
                if let nestedCBOR = try? CBOR.decode(byteString) {
                    if case let CBOR.tagged(tag, item) = nestedCBOR, tag.rawValue == 24 {
                        if case let CBOR.byteString(data) = item {
                            if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)) {
                                (index, uri) = extractStatusListFromCBOR(cbor: decodedInnerCBOR)
                            } else {
                                print("Failed to decode inner ByteString under Tag 24.")
                            }
                        }
                    }
                } else {
                    print("Could not decode ByteString as CBOR, inspecting data directly.")
                    print("ByteString data: \(byteString)")
                }
            } else {
                print("Element: \(element)")
            }
        }
        return (index, uri)
    }
        
    public func getFilteredCbor(credential: String, query: Any?) -> CBOR? {
        var requestedParams: [String] = []
        var limitDisclosure: Bool = false
        if let inputDescriptor =  query as? InputDescriptor {
            if let fields = inputDescriptor.constraints?.fields {
                print("printing inputDescriptor fields: \(fields)")
                for field in fields {
                    let components = field.path?.first?.components(separatedBy: ["[", "]", "'"])
                    let filteredComponents = components?.filter { !$0.isEmpty }
                    if let identifier = filteredComponents?.last {
                        requestedParams.append(String(identifier))
                    }
                }
            }
            print("printing requestedParams from cbor: \(requestedParams)")
            if inputDescriptor.constraints?.limitDisclosure == nil {
                limitDisclosure = false
            } else {
                limitDisclosure = true
            }
        } else if let dcql = query as? CredentialItems {
            guard let claims = dcql.claims else {
                var cborDataValue: CBOR? = nil
                if let data = Data(base64URLEncoded: credential) {
                    do {
                        let decodedCBOR = try CBOR.decode([UInt8](data))
                        if let dictionary = decodedCBOR {
                            cborDataValue = filterCBORWithRequestedParams(cborData: dictionary, requestedParams: [])
                        }
                    } catch {
                        
                    }
                }
                return cborDataValue
            }
            for (pathIndex, claim) in claims.enumerated() {
                guard case .pathClaim(let pathClaim) = claim else { continue }
                let nonNilPaths = pathClaim.path.compactMap { $0 }
                let paths = nonNilPaths.last
                requestedParams.append(String(paths ?? ""))
            }
            limitDisclosure = true
        }
        if let data = Data(base64URLEncoded: credential) {
            do {
                let decodedCBOR = try CBOR.decode([UInt8](data))
                if let dictionary = decodedCBOR {
                    if limitDisclosure {
                        return filterCBORWithRequestedParams(cborData: dictionary, requestedParams: requestedParams)
                    } else {
                        return dictionary
                    }
                }
            } catch {
                print("Error decoding CBOR: \(error)")
                return nil
            }
        } else {
            print("Invalid base64 URL encoded credential.")
            return nil
        }
        
        return nil
    }
    
    
    public func filterCBORWithRequestedParams(cborData: CBOR, requestedParams: [String]) -> CBOR? {
        guard case let CBOR.map(cborMap) = cborData else { return nil }
        var modifiedCBORMap = cborMap
        if let namespacesValue = modifiedCBORMap[CBOR.utf8String("nameSpaces")] {
            if let filteredNameSpaces = MDocVpTokenBuilder().filterNameSpaces(nameSpacesValue: namespacesValue, requestedParams: requestedParams) {
                modifiedCBORMap[CBOR.utf8String("nameSpaces")] = filteredNameSpaces
            }
        }
        return CBOR.map(modifiedCBORMap)
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
extension VerificationService: URLSessionDelegate, URLSessionTaskDelegate {
    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        // Stops the redirection, and returns (internally) the response body.
        completionHandler(nil)
    }
}


