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
       - privateKey: The private key used for signing the token.
       - presentationRequest: The presentation request containing the details of the requested presentation, or nil if not applicable.
       - credentialsList: The list of credentials to be included in the token, or nil if not applicable.
     - Returns: The serialized VP token data, or nil if the input parameters are invalid or if an error occurs during token creation.
     */
    func sendVPToken(
        did: String,
        secureKey: SecureKeyData,
        presentationRequest: PresentationRequest?,
        credentialsList: [String]?
    ) async -> Data?

    /**
     Processes an authorization request and extracts a PresentationRequest object asynchronously.
     - Parameter data: The authorization request data.
     - Returns: The extracted PresentationRequest object, or nil if the input data is invalid or cannot be processed.
     */
    func processAuthorisationRequest(data: String?) async -> PresentationRequest?

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
    func filterCredentials(credentialList: [String?], presentationDefinition: PresentationDefinitionModel) -> [[String]]
}
