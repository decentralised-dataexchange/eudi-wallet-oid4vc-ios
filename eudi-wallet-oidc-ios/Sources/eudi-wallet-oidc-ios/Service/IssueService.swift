//
//  IssueService.swift
//
//
//  Created by Mumthasir mohammed on 07/03/24.
//

import Foundation
import CryptoKit
import KeychainSwift
import CryptoSwift

public class IssueService {
    
    static var shared = IssueService()
    private init() {}
    
    // MARK: - Retrieves credential issuer asynchronously based on the provided credential_offer / credential_offer_uri.
    ///
    /// - Parameters:
    ///   - credentialOffer: The string representation of the credential offer.
    /// - Returns: A `CredentialOffer` object if the resolution is successful; otherwise, `nil`.
    public func resolveCredentialOffer(credentialOfferString: String) async throws -> CredentialOffer? {
        let credentialOfferUrl = URL(string: credentialOfferString)
        guard let credentialOfferUri = credentialOfferUrl?.queryParameters?["credential_offer_uri"] else { return nil }
        let jsonDecoder = JSONDecoder()
        
        if credentialOfferUri != "" {
            var request = URLRequest(url: URL(string: credentialOfferUri)!)
            request.httpMethod = "GET"
            
            let (data, _) = try await URLSession.shared.data(for: request)
            
            do {
                let model = try? jsonDecoder.decode(CredentialOffer.self, from: data)
                if model?.credentialIssuer == nil {
                    let error = Error(message:"Invalid DID", code: nil)
                    return CredentialOffer(error: error)
                }
                return model
            }
        } else {
            guard let credentialOffer = credentialOfferUrl?.queryParameters?["credential_offer"] else { return nil }
            let jsonData = Data(credentialOffer.utf8)
            
            if credentialOffer != "" {
                do {
                    let model = try? jsonDecoder.decode(CredentialOffer.self, from: jsonData)
                    if model?.credentialIssuer == nil {
                        let error = Error(message:"Invalid DID", code: nil)
                        return CredentialOffer(error: error)
                    }
                    return model
                }
            } else {
                return nil
            }
        }
    }
    
    // MARK: - To process the authorisation request, The authorisation request is to grant access to the credential endpoint.
    /// - Parameters:
    ///   - did - DID created for the issuance
    ///   - credentialOffer: The credential offer containing the necessary details for authorization.
    ///   - authServer: The authorization server configuration.
    ///   - codeVerifier - to build the authorisation request
    /// - Returns: code if successful; otherwise, nil.
    public func processAuthorisationRequest(did: String,
                                            privateKey: P256.Signing.PrivateKey,
                                            credentialOffer: CredentialOffer,
                                            codeVerifier: String,
                                            authServer: AuthorisationServerWellKnownConfiguration) async -> String? {
        
        guard let authorizationEndpoint = authServer.authorizationEndpoint else { return nil }
        let redirectUri = "http://localhost:8080"
        
        // Gather query parameters
        let responseType = "code"
        let scope = "openid"
        let state = UUID().uuidString
        let authorizationDetails =
        "[" + (([
            "type": "openid_credential",
            "format": "jwt_vc",
            "types": credentialOffer.credentials?[0].types ?? [],
            "locations": [credentialOffer.credentialIssuer]
        ] as [String : Any]).toString() ?? "") + "]"
        
        let nonce = UUID().uuidString
        let codeChallenge = CodeVerifierService.shared.generateCodeChallenge(codeVerifier: codeVerifier)
        let codeChallengeMethod = "S256"
        let clientMetadata =
        ([
          "vp_formats_supported": [
            "jwt_vp": [ "alg": ["ES256"] ],
            "jwt_vc": [ "alg": ["ES256"] ]
          ],
          "response_types_supported": ["vp_token", "id_token"],
          "authorization_endpoint": "\(redirectUri)"
        ] as [String : Any]).toString()
        
        // Validate required parameters
        if responseType == "", did == "" {
            return nil
        }
        
        // Construct the authorization URL
        var authorizationURLComponents = URLComponents(string: authorizationEndpoint)
        authorizationURLComponents?.queryItems = [
            URLQueryItem(name: "response_type", value: responseType),
            URLQueryItem(name: "scope", value: scope),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "client_id", value: did),
            URLQueryItem(name: "authorization_details", value: authorizationDetails),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: codeChallengeMethod),
            URLQueryItem(name: "client_metadata", value: clientMetadata),
            URLQueryItem(name: "issuer_state", value: credentialOffer.grants?.authorizationCode?.issuerState)
        ]
        
        // Validate the constructed authorization URL
        guard let authorizationURL = authorizationURLComponents?.url else {
            debugPrint("Failed to construct the authorization URL.")
            return nil
        }
        debugPrint(authorizationURL)
        
        // Service call to get authorisation response
        var request = URLRequest(url: authorizationURL)
        request.httpMethod = "GET"
                
        var responseUrl = ""
        do {
            // Try to fetch data from the URL session
            let (data, _) = try await URLSession.shared.data(for: request)
            guard let authorization_response = String.init(data: data, encoding: .utf8) else { return nil }
            responseUrl = authorization_response
        } catch {
            // If an error occurs, attempt to extract the failing URL from the error
            let nsError = error as NSError
            let response = nsError.userInfo["NSErrorFailingURLKey"]
            responseUrl = String(describing: response ?? "")
        }
        
        if responseUrl.contains("code=") {
            let url = URL(string: responseUrl)
            let code =  url?.queryParameters?["code"]
            return code
        } else {
           // if 'code' is not present
            let url = URL(string: responseUrl)
            let state = url?.queryParameters?["state"]
            let nonce = url?.queryParameters?["nonce"]
            let redirectUri = url?.queryParameters?["redirect_uri"]
            
            let code =  await processAuthorisationRequestUsingIdToken(
                did: did,
                privateKey: privateKey,
                authServerWellKnownConfig: authServer,
                redirectURI: redirectUri ?? "",
                nonce: nonce ?? "",
                state: state ?? "")
            return code
        }
    }
    
    
    private func processAuthorisationRequestUsingIdToken(
        did: String,
        privateKey: P256.Signing.PrivateKey,
        authServerWellKnownConfig: AuthorisationServerWellKnownConfiguration,
        redirectURI: String,
        nonce: String,
        state: String) async -> String? {
            
            // Retrieve the authorization endpoint from the server configuration.
            guard let authorizationEndpoint = authServerWellKnownConfig.authorizationEndpoint else { return nil }
            
            let header =
            ([
              "typ": "JWT",
              "alg": "ES256",
              "kid": "\(did)#\(did.replacingOccurrences(of: "did:key:", with: ""))"
            ]).toString() ?? ""

            // Generate JWT payload
            let currentTime = Int(Date().timeIntervalSince1970)
            let payload =
            ([
              "iss": "\(did)",
              "sub": "\(did)",
              "aud": "\(authorizationEndpoint)",
              "exp": currentTime + 3600,
              "iat": currentTime,
              "nonce": "\(nonce)"
            ] as [String : Any]).toString() ?? ""
            
            // Create JWT token
            let headerData = Data(header.utf8)
            let payloadData = Data(payload.utf8)
            let unsignedToken = "\(headerData.base64URLEncodedString()).\(payloadData.base64URLEncodedString())"
            let signatureData = try! privateKey.signature(for: unsignedToken.data(using: .utf8)!)
            let signature = signatureData.rawRepresentation
            let idToken = "\(unsignedToken).\(signature.base64URLEncodedString())"
            
            guard let urlComponents = URLComponents(string: redirectURI) else { return nil }
    
            // Create the URL with the added query parameters
            guard let url = urlComponents.url else { return nil }
            
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            
            let params = [
                "id_token" : idToken,
                "state" : state
            ] as [String: Any]

            
            let postString = UIApplicationUtils.shared.getPostString(params: params)
            request.httpBody = postString.data(using: .utf8)
            
            var responseUrl = ""
            
            do {
                // Perform the request to the redirect URI
                let (data, _) = try await URLSession.shared.data(for: request)
                let authorization_response = String.init(data: data, encoding: .utf8) ?? ""
                guard let authorisation_url = URL(string: authorization_response) else { return nil }
                
                if let components = URLComponents(url: authorisation_url, resolvingAgainstBaseURL: false),
                   let auth_code = components.queryItems?.first(where: { $0.name == "code" })?.value {
                    return auth_code
                } else {
                    return nil
                }
            } catch {
                let nsError = error as NSError
                let response = nsError.userInfo["NSErrorFailingURLKey"]
                responseUrl = String(describing: response ?? "")
                return responseUrl
            }
        }
    
    // MARK: -  Processes the token request to obtain the access token.
    /** - Parameters
        - authServerWellKnownConfig: The well-known configuration of the authorization server.
        - code:  If the credential offer is pre authorised, then use the pre authorised code from the credential offer
          else use the code from the previous function - processAuthorisationRequest
        - did: The identifier for the DID key.
        - isPreAuthorisedCodeFlow: A boolean indicating if it's a pre-authorized code flow.
        - preAuthCode: The pre-authorization code for the token request.
        - userPin: The user's PIN, if required.
     
     - Returns: A `TokenResponse` object if the request is successful, otherwise `nil`.
     */
    public func processTokenRequest(authServerWellKnownConfig: AuthorisationServerWellKnownConfiguration,
                                    code: String,
                                    did: String,
                                    privateKey: P256.Signing.PrivateKey,
                                    codeVerifier: String,
                                    isPreAuthorisedCodeFlow: Bool = false,
                                    preAuthCode: String,
                                    userPin: String?) async -> TokenResponse? {
        
        let codeVal = code.removingPercentEncoding ?? ""
        // Service call for access token and details
        if userPin == nil || userPin == "" {
            let tokenResponse = await getAccessToken(didKeyIdentifier: did, codeVerifier: codeVerifier, authCode: codeVal, privateKey: privateKey, tokenEndpoint: authServerWellKnownConfig.tokenEndpoint ?? "")
            return tokenResponse
        } else {
            // Service call for access token and details
            let tokenResponse = await getAccessTokenForPreAuthCredential(preAuthCode: preAuthCode, otpVal: userPin ?? "", tokenEndpoint: authServerWellKnownConfig.tokenEndpoint ?? "")
            return tokenResponse
        }
    }
    
    // MARK:  Processes a credential request to the specified credential endpoint.
    
    /** - Parameters
        - did: The identifier for the DID key.
        - credentialOffer: The credential offer object containing offer details.
        - credentialEndpointUrlString: The URL string of the credential endpoint.
        - c_nonce: The nonce value for the credential request.
        - accessToken: The access token for authentication.

     - Returns: A `CredentialResponse` object if the request is successful, otherwise `nil`.
     */
    public func processCredentialRequest(
        did: String,
        privateKey: P256.Signing.PrivateKey,
        credentialOffer: CredentialOffer,
        credentialEndpointUrlString: String,
        c_nonce: String,
        accessToken: String) async -> CredentialResponse? {
        
        let jsonDecoder = JSONDecoder()
        let methodSpecificId = did.replacingOccurrences(of: "did:key:", with: "")
            
            
        // Generate JWT header
        let header = ([
                "typ": "openid4vci-proof+jwt",
                "alg": "ES256",
                "kid": "\(did)#\(methodSpecificId)"
        ]).toString() ?? ""
        
        // Generate JWT payload
        let currentTime = Int(Date().epochTime) ?? 0
        let payload = ([
                "iss": "\(did)",
                "iat": currentTime,
                "aud": "\(credentialOffer.credentialIssuer ?? "")",
                "exp": currentTime + 86400,
                "nonce": "\(c_nonce)"
        ] as [String : Any]).toString() ?? ""
        
        guard let url = URL(string: credentialOffer.credentialIssuer ?? "") else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue( "Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        
        // Create JWT token
        let headerData = Data(header.utf8)
        let payloadData = Data(payload.utf8)
        let unsignedToken = "\(headerData.base64URLEncodedString()).\(payloadData.base64URLEncodedString())"
        let signatureData = try! privateKey.signature(for: unsignedToken.data(using: .utf8)!)
        let signature = signatureData.rawRepresentation
        let idToken = "\(unsignedToken).\(signature.base64URLEncodedString())"
        let format = credentialOffer.credentials?[0].format ?? ""
        
        // Set up parameters for the request
        let params = [
            "types": credentialOffer.credentials?[0].types ?? [],
            "format": format,
            "proof": [
              "proof_type": "jwt",
              "jwt": idToken
            ]
        ] as [String: Any]
        
        // Create URL for the credential endpoint
        guard let url = URL(string: credentialEndpointUrlString) else { return nil }
        
        // Set up the request for the credential endpoint
        request = URLRequest(url: url)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue( "Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.httpMethod = "POST"

        // Convert the parameters to JSON data and set it as the request body
        let requestBodyData = try? JSONSerialization.data(withJSONObject: params)
        request.httpBody =  requestBodyData
        
        // Perform the request and handle the response
        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            let model = try jsonDecoder.decode(CredentialResponse.self, from: data)
            return model
        } catch {
            debugPrint("Process credential request failed: \(error)")
            let nsError = error as NSError
            let errorCode = nsError.code
            let error = Error(message:error.localizedDescription, code: errorCode)
            return CredentialResponse(error: error)
        }
    }
    
    
// MARK: - Processes a deferred credential request to obtain the credential response in deffered manner.

    /** - Parameters
        - acceptanceToken - token which we got from credential request
        - deferredCredentialEndPoint - end point to call the deferred credential
    **/
//    - Returns: A `CredentialResponse` object if the request is successful, otherwise `nil`.

    public func processDeferredCredentialRequest(
        acceptanceToken: String,
        deferredCredentialEndPoint: String) async -> CredentialResponse? {
            
            let jsonDecoder = JSONDecoder()
            guard let url = URL(string: deferredCredentialEndPoint) else { return nil }
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue( "Bearer \(acceptanceToken)", forHTTPHeaderField: "Authorization")
            let params = "{}"
            let data = params.data(using: .utf8)
            request.httpBody = data
            
        // Perform the request and handle the response
        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            let model = try jsonDecoder.decode(CredentialResponse.self, from: data)
            return model
        } catch {
            debugPrint("Process deferred credential request failed: \(error)")
            let nsError = error as NSError
            let errorCode = nsError.code
            let error = Error(message:error.localizedDescription, code: errorCode)
            return CredentialResponse(error: error)
        }
    }
    
    // MARK: - Private methods
    
    // Retrieves the access token for Pre-Authorised credential using the provided parameters.
    private func getAccessTokenForPreAuthCredential(
        preAuthCode: String,
        otpVal: String ,
        tokenEndpoint: String) async -> TokenResponse? {
            
        let jsonDecoder = JSONDecoder()
        let grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        
        // Constructing parameters for the token request
        let params = ["grant_type": grantType, "pre-authorized_code":preAuthCode, "user_pin": otpVal] as [String: Any]
            let postString = UIApplicationUtils.shared.getPostString(params: params)

        // Creating the request
        var request = URLRequest(url: URL(string: tokenEndpoint)!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = postString.data(using: .utf8)
        
        // Performing the token request
        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            let model = try jsonDecoder.decode(TokenResponse.self, from: data)
            return model
        } catch {
            debugPrint("Get access token for preauth credential failed: \(error)")
            let nsError = error as NSError
            let errorCode = nsError.code
            let error = Error(message:error.localizedDescription, code: errorCode)
            return TokenResponse(error: error)
        }
    }
    
    // Retrieves the access token using the provided parameters.
    private func getAccessToken(
        didKeyIdentifier: String,
        codeVerifier: String,
        authCode: String,
        privateKey: P256.Signing.PrivateKey,
        tokenEndpoint: String) async -> TokenResponse? {
            
        let jsonDecoder = JSONDecoder()
        let grantType = "authorization_code"
        
        // Constructing parameters for the token request
        let params = ["grant_type": grantType, "code":authCode, "client_id": didKeyIdentifier, "code_verifier": codeVerifier] as [String: Any]
            let postString = UIApplicationUtils.shared.getPostString(params: params)
            
        // Creating the request
        var request = URLRequest(url: URL(string: tokenEndpoint)!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = postString.data(using: .utf8)
        
        // Performing the token request
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            debugPrint(response)
            let model = try jsonDecoder.decode(TokenResponse.self, from: data)
            return model
        } catch {
            debugPrint("Get access token for preauth credential failed: \(error)")
            let nsError = error as NSError
            let errorCode = nsError.code
            let error = Error(message:error.localizedDescription, code: errorCode)
            return TokenResponse(error: error)
        }
    }
}
