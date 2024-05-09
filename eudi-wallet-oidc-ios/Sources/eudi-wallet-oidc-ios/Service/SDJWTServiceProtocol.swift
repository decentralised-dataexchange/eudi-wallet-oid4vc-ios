//
//  SDJWTServiceProtocol.swift
//
//
//  Created by Mumthasir mohammed on 26/04/24.
//

import Foundation
import CryptoKit

protocol SDJWTServiceProtocol {
    
    /**
     Calculates the SHA-256 hash of the input string.
     - Parameter inputString: The string to calculate the hash for.
     - Returns: The SHA-256 hash of the input string, or nil if the input is nil.
     */
    func calculateSHA256Hash(inputString: String?) -> String?

    /**
     Creates a signed SDJWTR (Self-Describing JSON Web Token Response) using the provided credential, presentation request, and private key.
     - Parameters:
       - credential: The credential to include in the SDJWTR.
       - presentationRequest: The presentation request containing the details of the presentation request.
       - privateKey: The private key used for signing the SDJWTR.
     - Returns: The signed SDJWTR string, or nil if any of the input parameters are nil.
     */
    func createSDJWTR(
        credential: String?,
        presentationRequest: PresentationRequest,
        privateKey: P256.Signing.PrivateKey
    ) -> String?

    /**
     Processes the disclosures with the given presentation definition.
     - Parameters:
       - credential: The credential to process disclosures for.
       - presentationDefinition: The presentation definition model containing the details of the presentation.
     - Returns: The processed disclosures string based on the presentation definition, or nil if any of the input parameters are nil.
     */
    func processDisclosuresWithPresentationDefinition(
        credential: String?,
        presentationDefinition: PresentationDefinitionModel
    ) -> String?

    /**
     Updates the issuer JWT (JSON Web Token) with disclosures based on the provided credential.
     - Parameter credential: The credential containing the disclosures to update the issuer JWT.
     - Returns: The updated issuer JWT string with disclosures, or nil if the input credential is nil.
     */
    func updateIssuerJwtWithDisclosures(credential: String?) -> String?
}
