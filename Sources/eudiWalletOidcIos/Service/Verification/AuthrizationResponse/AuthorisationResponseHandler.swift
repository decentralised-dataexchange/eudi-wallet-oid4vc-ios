//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation

class AuthorisationResponseHandler {
    
    func prepareAuthorisationResponse(credentialsList: [String]?,
                                      presentationRequest: PresentationRequest?,
                                      did: String, keyHandler: SecureKeyProtocol) async -> [String: Any]?{
        guard let responseMode = ResponseMode(from: presentationRequest?.responseMode ?? "") else { return nil}
        switch responseMode {
        case .directPost:
            var params = await AuthorisationResponseBuilder.buildResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler)
            if var presentationSubmission = params["presentation_submission"] as? [String: Any]{
                 // For encoding the format we have encoded the presentation submission
                let encodedPresentationSubmission = presentationSubmission.toString()?.addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed.union(CharacterSet(charactersIn: "+")).subtracting(CharacterSet(charactersIn: "+")))?.replacingOccurrences(of: "+", with: "%2B")
                params["presentation_submission"] = encodedPresentationSubmission
            }
            return params
        case .iarPost :
            var params = await AuthorisationResponseBuilder.buildResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler)
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
            let params = await AuthorisationResponseBuilder.buildResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler)
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
            let params = await AuthorisationResponseBuilder.buildResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler)
            do {
                let encrypted = try await JWEEncryptor().encrypt(payload: params, presentationRequest: presentationRequest)
                var encryptedResponseParams: [String: Any] = [:]
                encryptedResponseParams["response"] = encrypted
                return encryptedResponseParams
            } catch {
                return nil
                print("")
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
