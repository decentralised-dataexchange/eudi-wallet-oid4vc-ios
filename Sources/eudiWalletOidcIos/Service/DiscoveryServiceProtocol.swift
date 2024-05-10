//
//  DiscoveryServiceProtocol.swift
//  
//
//  Created by Mumthasir mohammed on 18/03/24.
//

import Foundation

protocol DiscoveryServiceProtocol {
    // Retrieves the issuer configuration asynchronously based on the provided credential issuer well-known URI.
    ///
    /// - Parameters:
    ///   - credentialIssuerWellKnownURI: The URI for the credential issuer well-known configuration.
    ///   - Returns - IssuerWellKnownConfiguration
    func getIssuerConfig(credentialIssuerWellKnownURI: String?) async throws -> IssuerWellKnownConfiguration?
    
    
    // To fetch the authorisation server configuration
    /// - Parameters:
    ///   - authorisationServerWellKnownURI: The URI for the credential issuer well-known configuration.
    ///   - Returns - AuthorisationServerWellKnownConfiguration
    func getAuthConfig(authorisationServerWellKnownURI: String?) async throws -> AuthorisationServerWellKnownConfiguration?
}
