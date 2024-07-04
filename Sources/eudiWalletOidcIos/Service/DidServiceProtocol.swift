//
//  DidServiceProtocol.swift
//  
//
//  Created by Mumthasir mohammed on 18/03/24.
//

import Foundation

protocol DidServiceProtocol {
    // Creates a Decentralized Identifier (DID) asynchronously based on the provided JWK (JSON Web Key).
    ///
    /// - Parameter jwk: The JSON Web Key (JWK) used to create the DID.
    /// - Returns: The created DID string, or nil if an error occurs.
    func createDID(jwk: [String: Any]) async -> String?
    
    // Exposed method to create a JSON Web Key (JWK) asynchronously.
    ///
    /// - Returns: A dictionary representing the JWK, or nil if an error occurs.
    func createJWK(keyHandler: SecureKeyProtocol) async -> ([String: Any], SecureKeyData)?
}
