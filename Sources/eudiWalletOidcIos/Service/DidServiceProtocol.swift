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
    /// - Parameter cryptographicAlgorithm: Alg for creating the DID.
    /// - Returns: The created DID string, or nil if an error occurs.
    func createDID(jwk: [String: Any], cryptographicAlgorithm: String?) async -> String?
    
    // Creates a Decentralized Identifier (DID) asynchronously based on the provided JWK (JSON Web Key) for ES256.
    ///
    /// - Parameter jwk: The JSON Web Key (JWK) used to create the DID.
    /// - Returns: The created DID string, or nil if an error occurs.
    func createES256DID(jwk: [String: Any]) async -> String?
    
    // Creates a Decentralized Identifier (DID) asynchronously based on the provided JWK (JSON Web Key) for EdDSA.
    ///
    /// - Parameter jwk: The JSON Web Key (JWK) used to create the DID.
    /// - Returns: The created DID string, or nil if an error occurs.
    func createEdDSADID(jwk: [String: Any]) async -> String?
    
    // Exposed method to create a JSON Web Key (JWK) asynchronously.
    ///
    /// - Returns: A dictionary representing the JWK, or nil if an error occurs.
    func createJWK(keyHandler: SecureKeyProtocol) async -> ([String: Any], SecureKeyData)?
    
    // Exposed method to create a JSON Web Key (JWK) asynchronously for ES256.
    ///
    /// - Returns: A dictionary representing the JWK, or nil if an error occurs.
    func createES256JWK(keyHandler: SecureKeyProtocol) async -> ([String: Any], SecureKeyData)?
    
    // Exposed method to create a JSON Web Key (JWK) asynchronously for EdDSA.
    ///
    /// - Returns: A dictionary representing the JWK, or nil if an error occurs.
    func createEdDSAJWK(keyHandler: SecureKeyProtocol) async -> ([String: Any], SecureKeyData)?
    
    // Exposed method to create a JSON Web Key (JWK) asynchronously for Secure enclave.
    ///
    /// - Returns: A dictionary representing the JWK, or nil if an error occurs.
    func createSecureEnclaveJWK(keyHandler: SecureKeyProtocol) async -> ([String: Any], SecureKeyData)?
}
