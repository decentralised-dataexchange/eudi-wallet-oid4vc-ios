//
//  VerificationServiceProtocol.swift
//
//
//  Created by Mumthasir mohammed on 18/03/24.
//

import Foundation
import CryptoKit

protocol VerificationServiceProtocol {
    // Sends a Verifiable Presentation (VP) token asynchronously.
    func sendVPToken(
        did: String,
        privateKey: P256.Signing.PrivateKey,
        presentationRequest: PresentationRequest?,
        credentialsList: [String]?) async -> Data?
    
    // Method to process an authorization request and extract a PresentationRequest object
    func processAuthorisationRequest(data: String?) -> PresentationRequest?
}
