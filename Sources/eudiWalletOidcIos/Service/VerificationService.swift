//
//  VerificationService.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//
import Foundation
import JOSESwift
import CryptoKit
import PresentationExchangeSdkiOS
import SwiftCBOR
import OrderedCollections
import Security
import ASN1Decoder


private extension String {
    /// nil when empty or only whitespace, so a `??` chain treats an absent
    /// parameter and one present-but-empty alike - query parsing delivers both.
    var nilIfBlank: String? {
        trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : self
    }
}

public class VerificationService: NSObject, VerificationServiceProtocol {
    
    var keyHandler: SecureKeyProtocol
    
    // MARK: - A custom initialiser with dependency injection for encryption key generation handler
    ///
    /// - Parameters:
    ///   - keyhandler: A handler to encryption key generation class
    /// - Returns: An `VerificationService` object
    /// Session used to fetch a request object by reference. Replaceable in tests.
    var requestObjectSession: URLSession = .shared

    public required init(keyhandler: SecureKeyProtocol) {
        keyHandler = keyhandler
    }
    
    
    public func processOrSendAuthorizationResponse(
        did: String,
        presentationRequest: PresentationRequest?,
        credentialsList: [[String]]?,
        wua: String,
        pop: String, isSca: Bool = false, keyIds: [[String]] = [], amrInherenceFactor: String?, amrKnowledgeFactor: String?) async -> WrappedVerificationResponse? {
            
            guard let params = await AuthorisationResponseHandler().prepareAuthorisationResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler, isSca: isSca, keyIds: keyIds, amrInherenceFactor: amrInherenceFactor, amrKnowledgeFactor: amrKnowledgeFactor),
                  !params.isEmpty else {
                // Building the response failed. Posting the empty set that used to
                // stand in for it is worse than not posting: the verifier answers a
                // bodyless response by redirecting to its login page, so the failure
                // surfaced as a browser opening rather than as an error.
                return WrappedVerificationResponse(error: EUDIError(from: ErrorResponse(
                    message: "Could not build the presentation response", code: nil)))
            }
            // OpenID4VP 1.0 8.2: for direct_post the Authorization Response is
            // POSTed to response_uri, and redirect_uri MUST NOT be present. Only
            // the by-value parser used to alias the two, so a signed request
            // object - which carries response_uri and nothing else - resolved to
            // nil here and the presentation was never sent. redirect_uri stays as
            // a fallback for the redirect-based response modes.
            guard let responseEndpoint = presentationRequest?.responseUri?.nilIfBlank
                    ?? presentationRequest?.redirectUri?.nilIfBlank else {
                return nil
            }
            return await sendVPRequest(params: params, redirectURI: responseEndpoint, wua: wua, pop: pop)
        }
    
    /// Resolves scanned data into a presentation request (OpenID4VP 1.0 section 5) and verifies the
    /// verifier's identity by its client identifier prefix (section 5.9). The outcome says who the
    /// verifier is in `ResolvedPresentationRequest.verifier`.
    public func resolveAuthorizationRequest(data: String?, policy: PresentationRequestPolicy = .default) async -> PresentationRequestOutcome {
        await PresentationRequestResolver(policy: policy, session: requestObjectSession).resolve(data)
    }

    /// Kept for integrators on the previous API. Blank or unrecognised input still answers
    /// `(nil, nil)` as before; every other outcome maps onto the tuple.
    @available(*, deprecated, renamed: "resolveAuthorizationRequest(data:policy:)",
               message: "Use resolveAuthorizationRequest, which returns a typed outcome instead of a tuple of optionals")
    public func processAuthorisationRequest(data: String?) async -> (PresentationRequest?, EUDIError?) {
        switch await PresentationRequestResolver(session: requestObjectSession).resolveTyped(data) {
        case .success(let resolved):
            return (resolved.request, nil)
        case .failure(.noRequest):
            return (nil, nil)
        case .failure(let error):
            return (nil, error.eudiError)
        }
    }

    private func sendVPRequest(params: [String: Any], redirectURI: String, wua: String, pop: String) async -> WrappedVerificationResponse? {
        // OpenID4VP 1.0 8.2 requires application/x-www-form-urlencoded. getPostString
        // joined key=value with no escaping at all, so any value carrying "+", "/"
        // or "=" reached the Verifier corrupted - base64 vp_tokens (mdoc) above all.
        let postString = UIApplicationUtils.shared.getFormEncodedString(params: params)
        // What the verifier actually receives. A verifier that cannot correlate
        // the response to its session tends to answer with a redirect to its
        // login page rather than an error, so the fields it correlates on -
        // state above all - are worth seeing without turning on body tracing.
        let paramsData = postString.data(using: .utf8)
        let sanitisedWUA = wua.hasSuffix("~") ? String(wua.dropLast()) : wua
        var request = URLRequest(url: URL(string: redirectURI)!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue(sanitisedWUA, forHTTPHeaderField: "OAuth-Client-Attestation")
        request.setValue(pop, forHTTPHeaderField: "OAuth-Client-Attestation-PoP")
        request.httpBody = paramsData
        
        // Performing the token request
        var responseUrl = ""
        do {
            let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
            
            let (data, response) = try await NetworkLogger.send(request, tag: "vp-token-response", session: session)
            
            
            let httpres = response as? HTTPURLResponse
            
            // The success case OpenID4VP 8.2 defines comes first: 200 with a body
            // that MAY carry redirect_uri. A 302 is not in the specification and is
            // only read afterwards, as a vendor accommodation.
            if httpres?.statusCode == 200 || httpres?.statusCode == 204 {
                let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
                if let redirectUri = json?["redirect_uri"] as? String {
                    return WrappedVerificationResponse(redirectUri: redirectUri)
                } else if let code = json?["code"] as? String {
                    return WrappedVerificationResponse(data: "https://www.example.com?code=\(code)")
                } else {
                    // Presentation accepted, nowhere to send the user.
                    return WrappedVerificationResponse(data: "https://www.example.com?code=1")
                }
            } else if httpres?.statusCode == 302 {
                if let location = httpres?.value(forHTTPHeaderField: "Location") {
                    responseUrl = location
                    let url = URL.init(string: location)
                    if let errorDescription = url?.queryParameters?["error_description"] as? String {
                        let error = errorDescription.replacingOccurrences(of: "+", with: " ").data(using: .utf8)
                        return WrappedVerificationResponse(data: nil, error: ErrorHandler.processError(data: error, contentType: httpres?.value(forHTTPHeaderField: "Content-Type")))
                    } else {
                        return WrappedVerificationResponse(location: responseUrl)
                    }
                } else {
                    return WrappedVerificationResponse(data: "https://www.example.com?code=1")
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


