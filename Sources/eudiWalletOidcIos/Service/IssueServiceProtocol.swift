//
//  IssueServiceProtocol.swift
//
//
//  Created by Mumthasir mohammed on 18/03/24.
//
import Foundation
import CryptoKit
import JOSESwift
protocol IssueServiceProtocol {
    // Retrieves credential issuer asynchronously based on the provided credential_offer / credential_offer_uri.
    ///
    /// - Parameters:
    ///   - credentialOffer: The string representation of the credential offer.
    /// - Returns: A `CredentialOffer` object if the resolution is successful; otherwise, `nil`.
    func resolveCredentialOffer(credentialOffer: String) async throws -> CredentialOffer?
    
    
    // To process the authorisation request, The authorisation request is to grant access to the credential endpoint.
    /// - Parameters:
    ///   - did - DID created for the issuance
    ///   - secureKey: A wrapper object containing the public and private encryption keys
    ///   - credentialOffer: The credential offer containing the necessary details for authorization.
    ///   - authServer: The authorization server configuration.
    ///   - codeVerifier - to build the authorisation request
    /// - Returns: code if successful; otherwise, nil.
    func processAuthorisationRequest(did: String, credentialOffer: CredentialOffer, codeVerifier: String, authServer: AuthorisationServerWellKnownConfiguration, credentialFormat: String, docType: String, issuerConfig: IssuerWellKnownConfiguration?, redirectURI: String?, isApiCallRequired: Bool?, wua: String, pop: String) async -> WrappedResponse?

    /// The authorization request.
    ///
    /// Replaces ``processAuthorisationRequest(did:credentialOffer:codeVerifier:authServer:credentialFormat:docType:issuerConfig:redirectURI:isApiCallRequired:wua:pop:)``,
    /// whose `data: String?` meant six different things and left the caller re-parsing query
    /// parameters off a URL to work out which. Switch on ``AuthorizationResponse/outcome``.
    func requestAuthorization(
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        codeVerifier: String,
        selection: CredentialSelection,
        redirectUri: String?,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy
    ) async -> AuthorizationResponse

    /// Answers an authorization server that asked for an ID token rather than authorizing directly.
    ///
    /// Reached when ``requestAuthorization(session:wallet:attestation:codeVerifier:selection:redirectUri:mode:policy:)``
    /// answers with ``AuthorizationOutcome/idTokenRequired``, whose `url` is the `location` to pass
    /// here. Declared on the Android interface all along; it was missing here.
    func processAuthorisationRequestUsingIdToken(
        did: String,
        authServerWellKnownConfig: AuthorisationServerWellKnownConfiguration,
        redirectURI: String,
        nonce: String,
        state: String,
        clientID: String
    ) async -> String?
    
    // Processes the token request to obtain the access token.
    /** - Parameters
     - authServerWellKnownConfig: The well-known configuration of the authorization server.
     - code:  If the credential offer is pre authorised, then use the pre authorised code from the credential offer
     else use the code from the previous function - processAuthorisationRequest
     - did: The identifier for the DID key.
     - codeverifier:
     - isPreAuthorisedCodeFlow: A boolean indicating if it's a pre-authorized code flow.
     - preAuthCode: The pre-authorization code for the token request.
     - userPin: The user's PIN, if required.
     
     - Returns: A `TokenResponse` object if the request is successful, otherwise `nil`.
     */
    func processTokenRequest(did: String, tokenEndPoint: String?, code: String, codeVerifier: String, isPreAuthorisedCodeFlow: Bool, userPin: String?, version: String?, wua: String, pop: String, redirectURI: String?, isDPOPSupported: Bool, dpopKey: P256.Signing.PrivateKey?, dpopKeyHandler: SecureKeyProtocol?, dpopKeyPublicJwk: [String: Any]?) async -> TokenResponse?
    
    
    // Processes a credential request to the specified credential endpoint.
    
    /** - Parameters
     - did: The identifier for the DID key.
     - secureKey: A wrapper object containing the public and private encryption keys
     - credentialOffer: The credential offer object containing offer details.
     - credentialEndpointUrlString: The URL string of the credential endpoint.
     - c_nonce: The nonce value for the credential request.
     - accessToken: The access token for authentication.
     - Returns: A `CredentialResponse` object if the request is successful, otherwise `nil`.
     */
    func processCredentialRequest(did: String, nonce: String, credentialOffer: CredentialOffer, issuerConfig: IssuerWellKnownConfiguration, accessToken: String, format: String, credentialTypes: [String], tokenResponse: TokenResponse?, authDetails: AuthorizationDetails?, privateKey: ECPrivateKey?, isDpopSUpported: Bool, dpopKey: P256.Signing.PrivateKey?, dpopKeyHandler: SecureKeyProtocol?, dpopKeyPublicJwk: [String: Any]?, attachKeyAttestation: Bool, keyAttestationJwt: String?) async -> CredentialResponse?
    
    // Processes a deferred credential request to obtain the credential response in deffered manner.
    /** - Parameters
     - acceptanceToken - token which we got from credential request
     - deferredCredentialEndPoint - end point to call the deferred credential
     **/
    //    - Returns: A `CredentialResponse` object if the request is successful, otherwise `nil`.
    func processDeferredCredentialRequest(acceptanceToken: String, deferredCredentialEndPoint: String, version: String?, accessToken: String?, privateKey: ECPrivateKey?, jwks: [String: Any]?, encryptionRequired: Bool?, encValuesSupported: [String]?, isDPOPSupported: Bool, dpopKeyHandler: SecureKeyProtocol?, dpopKeyPublicJwk: [String: Any]?) async -> CredentialResponse?
    
    func getFormatFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?) -> String?
    
    func isCredentialMetaDataAvailable(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> Bool?
    
    func getTypesFromCredentialOffer(credentialOffer: CredentialOffer?) -> [String]?
    func getTypesFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> Any?
    func getCredentialDisplayFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> Display?
    func getDocTypeFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> String?
    
}
