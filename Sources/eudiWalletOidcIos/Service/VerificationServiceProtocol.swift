//
//  VerificationServiceProtocol.swift
//
//
//  Created by Mumthasir mohammed on 18/03/24.
//
import Foundation
import CryptoKit
protocol VerificationServiceProtocol {
    /**
     Sends a verifiable presentation token (VP token) asynchronously.
     - Parameters:
       - did: The decentralized identifier (DID) of the entity issuing the token.
       - secureKey: A wrapper object containing the public and private encryption keys
       - privateKey: The private key used for signing the token.
       - presentationRequest: The presentation request containing the details of the requested presentation, or nil if not applicable.
       - credentialsList: The list of credentials to be included in the token, or nil if not applicable.
     - Returns: The serialized VP token data, or nil if the input parameters are invalid or if an error occurs during token creation.
     */
    @available(*, deprecated, message: "Use submitPresentation")
    func processOrSendAuthorizationResponse(
        did: String,
        presentationRequest: PresentationRequest?,
        credentialsList: [[String]]?,
        wua: String,
        pop: String, isSca: Bool, keyIds: [[String]], amrInherenceFactor: String?, amrKnowledgeFactor: String?) async -> WrappedVerificationResponse?
    /// Builds, encodes and sends the Authorization Response for the selected credentials
    /// (OpenID4VP 1.0 section 8), or hands it back for the Digital Credentials API to deliver.
    func submitPresentation(request: PresentationRequest, selected: [SelectedCredential], identity: WalletIdentity,
                            attestation: WalletAttestation?, authentication: AuthenticationMethods?) async -> PresentationOutcome

    /// Resolves scanned data into a presentation request (OpenID4VP 1.0 section 5): by value, by
    /// `request` object, behind a `request_uri`, or as an interactive authorization request.
    func resolveAuthorizationRequest(data: String?, policy: PresentationRequestPolicy) async -> PresentationRequestOutcome

    /// Matches the wallet's credentials against the request's query (OpenID4VP 1.0 section 6, or a
    /// draft presentation definition), one entry per credential query, never by position.
    func matchCredentials(request: PresentationRequest, credentials: [String?]) async -> CredentialMatches

    /**
     Processes an authorization request and extracts a PresentationRequest object asynchronously.
     - Parameter data: The authorization request data.
     - Returns: The extracted PresentationRequest object, or nil if the input data is invalid or cannot be processed.
     */
    @available(*, deprecated, renamed: "resolveAuthorizationRequest(data:policy:)")
    func processAuthorisationRequest(data: String?) async -> (PresentationRequest?, EUDIError?)
    /**
     Processes the provided presentation definition data and returns a PresentationDefinitionModel object.
     - Parameter presentationDefinition: The presentation definition data.
     - Throws: An error if the presentation definition data is invalid or cannot be processed.
     - Returns: The PresentationDefinitionModel object representing the presentation definition.
     */
    static func processPresentationDefinition(_ presentationDefinition: Any?) throws -> PresentationDefinitionModel
    /**
     Filters the provided list of credentials based on the given presentation definition.
     - Parameters:
       - credentialList: The list of credentials to filter.
       - presentationDefinition: The presentation definition model containing the criteria for filtering.
     - Returns: An array of arrays of filtered credentials, where each inner array represents a set of credentials that satisfy the presentation definition criteria.
     */
}
