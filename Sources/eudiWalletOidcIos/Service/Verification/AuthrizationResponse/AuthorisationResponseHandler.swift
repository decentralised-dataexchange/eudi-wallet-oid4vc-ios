//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation

class AuthorisationResponseHandler {
    
    func prepareAuthorisationResponse(credentialsList: [[String]]?,
                                      presentationRequest: PresentationRequest?,
                                      did: String, keyHandler: SecureKeyProtocol, isSca: Bool, keyIds: [[String]]) async -> [String: Any]?{
        guard let responseMode = ResponseMode(from: presentationRequest?.responseMode ?? "") else { return nil}
        switch responseMode {
        case .directPost:
            var params = await AuthorisationResponseBuilder.buildResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler, isSca: isSca, keyIds: keyIds)
            if let presentationSubmission = params["presentation_submission"] as? [String: Any] {
                // Hand over the plain JSON. This used to be percent-encoded here
                // because the body was assembled without escaping; the body is now
                // form-encoded as OpenID4VP 8.2 requires, so encoding it here too
                // would send the Verifier a doubly-escaped value.
                params["presentation_submission"] = presentationSubmission.toString()
            }
            return params
        case .iarPost :
            var params = await AuthorisationResponseBuilder.buildResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler, isSca: isSca, keyIds: keyIds)
            if var presentationSubmission = params["presentation_submission"] as? [String: Any] {
                 // For encoding the format we have encoded the presentation submission
                let encodedPresentationSubmission = presentationSubmission.toString()?.addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed.union(CharacterSet(charactersIn: "+")).subtracting(CharacterSet(charactersIn: "+")))?.replacingOccurrences(of: "+", with: "%2B")
                params["presentation_submission"] = encodedPresentationSubmission
            }
            
            
            var iarPostParameters: [String: Any] = [:]
            
            iarPostParameters["auth_session"] = presentationRequest?.authSession
            iarPostParameters["openid4vp_presentation"] = params.toString()
            
            return iarPostParameters
        case .iarPostJWT:
            let params = await AuthorisationResponseBuilder.buildResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler, isSca: isSca, keyIds: keyIds, isEncrypted: true)
            do {
                let encrypted = try await JWEEncryptor().encrypt(payload: params, presentationRequest: presentationRequest)
                var encryptedResponseParams: [String: Any] = [:]
                encryptedResponseParams["response"] = encrypted
                
                var iarPostParameters: [String: Any] = [:]
                
                iarPostParameters["auth_session"] = presentationRequest?.authSession
                iarPostParameters["openid4vp_presentation"] = encryptedResponseParams
                
                return iarPostParameters
            } catch {
                return nil
                print("")
            }
        case .directPostJWT:
            let params = await AuthorisationResponseBuilder.buildResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler, isSca: isSca, keyIds: keyIds, isEncrypted: true)
            do {
                let encrypted = try await JWEEncryptor().encrypt(payload: params, presentationRequest: presentationRequest)
                var encryptedResponseParams: [String: Any] = [:]
                encryptedResponseParams["response"] = encrypted
                return encryptedResponseParams
            } catch {
                // Was swallowed - the caller turned nil into an empty parameter
                // set and POSTed a body with nothing in it, which a verifier
                // answers by bouncing to its login page rather than with an error.
                return nil
            }
        case .dcApi:
            print("Handling DC API response mode")
            return [:]
        case .dcApiJWT:
            print("Handling DC API JWT response mode")
            return [:]
        default:
            print("Handling default response mode")
            return [:]
        }
    }
}
