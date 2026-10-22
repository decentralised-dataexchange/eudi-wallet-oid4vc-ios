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
    
    
    /// What the previous API answered when the verifier accepted without a redirect.
    static let acceptedPlaceholder = "https://www.example.com?code=1"

    /// Builds the presentations for the selected credentials, shapes the Authorization Response for
    /// the request's response mode (OpenID4VP 1.0 section 8), encrypts it when asked and posts it.
    /// Over the Digital Credentials API the parameters are handed back for the platform to deliver.
    ///
    /// - Parameters:
    ///   - selected: the credentials the user chose, each named by the query entry it answers.
    ///   - identity: the wallet's DID; the service's key handler is its key.
    ///   - attestation: the wallet unit attestation, sent as client attestation headers.
    ///   - authentication: how the user authenticated, for a strong customer authentication.
    public func submitPresentation(request: PresentationRequest, selected: [SelectedCredential], identity: WalletIdentity,
                                   attestation: WalletAttestation? = nil,
                                   authentication: AuthenticationMethods? = nil) async -> PresentationOutcome {
        await PresentationSubmitter().submit(request, selected: selected, identity: identity, holderKey: keyHandler,
                                             attestation: attestation, authentication: authentication)
    }

    /// Kept for integrators on the previous API. The credentials and key ids arrive as lists aligned
    /// by position with the query; the outcome is wrapped the way callers of this entry point
    /// expect, placeholder redirect included.
    @available(*, deprecated, message: "Use submitPresentation, which takes SelectedCredential values and returns a typed outcome")
    public func processOrSendAuthorizationResponse(
        did: String,
        presentationRequest: PresentationRequest?,
        credentialsList: [[String]]?,
        wua: String,
        pop: String, isSca: Bool = false, keyIds: [[String]] = [], amrInherenceFactor: String?, amrKnowledgeFactor: String?) async -> WrappedVerificationResponse? {
        guard let request = presentationRequest else {
            return WrappedVerificationResponse(error: EUDIError(message: "Could not build the presentation response", errorCode: "invalid_request"))
        }
        guard let selected = LegacySelection.from(request, groups: credentialsList, keyIds: keyIds) else {
            return WrappedVerificationResponse(error: EUDIError(message: "The selected credentials do not match the query", errorCode: "invalid_request"))
        }
        let outcome = await submitPresentation(
            request: request,
            selected: selected,
            identity: WalletIdentity(did: did),
            attestation: WalletAttestation(attestationJwt: wua, proofOfPossession: pop),
            authentication: isSca ? AuthenticationMethods(inherence: amrInherenceFactor, knowledge: amrKnowledgeFactor) : nil)
        switch outcome {
        case .accepted(let redirectUri, let location, let code):
            if let redirectUri { return WrappedVerificationResponse(redirectUri: redirectUri) }
            if let location { return WrappedVerificationResponse(location: location) }
            // Callers of this entry point read the code out of the placeholder to continue issuance.
            if let code { return WrappedVerificationResponse(data: "https://www.example.com?code=\(code)") }
            return WrappedVerificationResponse(data: Self.acceptedPlaceholder)
        case .delivered:
            return WrappedVerificationResponse(data: Self.acceptedPlaceholder)
        case .refused(let error):
            return WrappedVerificationResponse(error: error)
        }
    }

    /// Resolves scanned data into a presentation request (OpenID4VP 1.0 section 5) and verifies the
    /// verifier's identity by its client identifier prefix (section 5.9). The outcome says who the
    /// verifier is in `ResolvedPresentationRequest.verifier`.
    public func resolveAuthorizationRequest(data: String?, policy: PresentationRequestPolicy = .default) async -> PresentationRequestOutcome {
        await PresentationRequestResolver(policy: policy, session: requestObjectSession).resolve(data)
    }

    /// Matches the wallet's credentials against the request's query (OpenID4VP 1.0 section 6, or
    /// a draft presentation definition): one entry per credential query with its candidates, and
    /// whether the required entries and credential sets can be satisfied at all.
    ///
    /// - Parameter credentials: every stored credential: SD-JWTs and JWTs in compact form, mdocs
    ///   as base64url IssuerSigned.
    public func matchCredentials(request: PresentationRequest, credentials: [String?]) async -> CredentialMatches {
        await PresentationQueryMatcher().match(request, credentials)
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
