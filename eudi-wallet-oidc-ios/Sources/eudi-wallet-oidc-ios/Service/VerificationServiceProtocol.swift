//
//  VerificationServiceProtocol.swift
//
//
//  Created by Mumthasir mohammed on 18/03/24.
//

import Foundation
import CryptoKit

// Sends a Verifiable Presentation (VP) token asynchronously.
protocol VerificationServiceProtocol {
    func sendVPToken( did: String,
                      privateKey: P256.Signing.PrivateKey,
                      nonce: String,
                      presentationRequest: PresentationRequest?,
                      credentialsList: [String]?) async -> Data?
}
