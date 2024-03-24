//
//  VerificationService.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//

import Foundation
import CryptoKit

public class VerificationService: VerificationServiceProtocol {
    
    static var shared = VerificationService()
    private init() {}
    
    // MARK: - Sends a Verifiable Presentation (VP) token asynchronously.
    public func sendVPToken(
        did: String,
        privateKey: P256.Signing.PrivateKey,
        presentationRequest: PresentationRequest?,
        credentialsList: [String]?) async -> Data? {
        
        // Generate JWK
        let jwk = generateJWKFromPrivateKey(privateKey: privateKey, did: did)
        
        // Generate JWT header
        let header = generateJWTHeader(jwk: jwk, did: did)
        
        // Generate JWT payload
        let payload = generateJWTPayload(did: did, nonce: presentationRequest?.nonce ?? "", credentialsList: credentialsList ?? [], state: presentationRequest?.state ?? "", clientID: presentationRequest?.clientId ?? "")
        debugPrint("### Payload:\(payload)")
        
        // Generate VPToken
        let vpToken =  generateVPToken(header: header, payload: payload, privateKey: privateKey)
        
        // Presentation Submission model
        guard let presentationSubmission = preparePresentationSubmission() else { return nil }
        
        return await sendVPRequest(vpToken: vpToken, presentationSubmission: presentationSubmission, redirectURI: presentationRequest?.redirectUri ?? "", state: presentationRequest?.state ?? "")
    }
    
    // Method to process an authorization request and extract a PresentationRequest object
    public func processAuthorisationRequest(data: String?) -> PresentationRequest? {
        // Check if data exists
        if let code = data {
            if code.contains("presentation_definition") {
                // Extract parameters from the code
                let state = URL(string: code)?.queryParameters?["state"] ?? ""
                let nonce = URL(string: code)?.queryParameters?["nonce"] ?? ""
                let redirectUri = URL(string: code)?.queryParameters?["redirect_uri"] ?? ""
                let clientID = URL(string: code)?.queryParameters?["client_id"] ?? ""
                let responseType = URL(string: code)?.queryParameters?["response_type"] ?? ""
                let scope = URL(string: code)?.queryParameters?["scope"] ?? ""
                let requestUri = URL(string: code)?.queryParameters?["request_uri"] ?? ""
                let responseMode = URL(string: code)?.queryParameters?["response_mode"] ?? ""
                let presentationDefinition = URL(string: code)?.queryParameters?["presentation_definition"] ?? ""

                // Create and return a PresentationRequest object
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
            } else {
                return nil
            }
        } else {
            return nil
        }
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
        let pathNested = DescriptorMap(id: "vp1", path: "$.verifiableCredential[0]", format: "jwt_vc", pathNested: nil)
        let descMap = [
            DescriptorMap(id: "vp1", path: "$", format: "jwt_vp", pathNested: pathNested)]
        return PresentationSubmissionModel(id: "essppda1", definitionID: "essppda1", descriptorMap: descMap)
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
}
