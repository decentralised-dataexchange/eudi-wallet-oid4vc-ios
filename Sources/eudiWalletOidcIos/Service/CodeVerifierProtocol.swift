//
//  CodeVerifierProtocol.swift
//  
//
//  Created by Mumthasir mohammed on 18/03/24.
//

import Foundation

protocol CodeVerifierProtocol {
    // Generates a code challenge string for PKCE (Proof Key for Code Exchange) based on the provided code verifier.
    /// - Parameter codeVerifier: The code verifier string used to generate the code challenge.
    /// - Returns: A code challenge string if successful; otherwise, nil.
    func generateCodeChallenge(codeVerifier: String) -> String?
    
    // Generates a random code verifier string for PKCE (Proof Key for Code Exchange).
    /// - Returns: A randomly generated code verifier string.
    func generateCodeVerifier() -> String?
}
