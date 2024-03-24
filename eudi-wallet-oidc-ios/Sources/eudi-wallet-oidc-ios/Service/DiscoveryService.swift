//
//  DiscoveryService.swift
//
//
//  Created by Mumthasir mohammed on 08/03/24.
//

import Foundation
import CryptoKit

public class DiscoveryService: DiscoveryServiceProtocol {
    
    static var shared = DiscoveryService()
    private init(){}
    
    // MARK: - Retrieves the issuer configuration asynchronously based on the provided credential issuer well-known URI.
    ///
    /// - Parameters:
    ///   - credentialIssuerWellKnownURI: The URI for the credential issuer well-known configuration.
    ///   - Returns - IssuerWellKnownConfiguration
    public func getIssuerConfig(credentialIssuerWellKnownURI: String?) async throws -> IssuerWellKnownConfiguration? {
        let jsonDecoder = JSONDecoder()
        
        guard let uri = credentialIssuerWellKnownURI else { return nil }
        let openIdIssuerUrl = uri + "/.well-known/openid-credential-issuer"
        
        guard let url = URL.init(string: openIdIssuerUrl) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let (data, _) = try await URLSession.shared.data(for: request)
        
        do {
            let model = try jsonDecoder.decode(IssuerWellKnownConfiguration.self, from: data)
            return model
        } catch {
            debugPrint("JSON Serialization Error: \(error)")
            return nil
        }
    }
    
    // MARK: - To fetch the authorisation server configuration
    /// - Parameters:
    ///   - authorisationServerWellKnownURI: The URI for the credential issuer well-known configuration.
    ///   - Returns - AuthorisationServerWellKnownConfiguration
    public func getAuthConfig(authorisationServerWellKnownURI: String?) async throws -> AuthorisationServerWellKnownConfiguration? {
        let jsonDecoder = JSONDecoder()
        
        guard let uri = authorisationServerWellKnownURI else { return nil }
        let authUrl = uri +  "/.well-known/openid-configuration"
        
        guard let url = URL.init(string: authUrl) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let (data, _) = try await URLSession.shared.data(for: request)
        
        do {
            let model = try jsonDecoder.decode(AuthorisationServerWellKnownConfiguration.self, from: data)
            return model
        } catch {
            debugPrint("JSON Serialization Error: \(error)")
            return nil
        }
    }
}
