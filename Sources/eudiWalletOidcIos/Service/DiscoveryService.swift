//
//  DiscoveryService.swift
//
//
//  Created by Mumthasir mohammed on 08/03/24.
//
import Foundation
import CryptoKit
public class DiscoveryService: DiscoveryServiceProtocol {
    
    public static var shared = DiscoveryService()
    private init(){}
    
    // MARK: - Retrieves the issuer configuration asynchronously based on the provided credential issuer well-known URI.
    ///
    /// - Parameters:
    ///   - credentialIssuerWellKnownURI: The URI for the credential issuer well-known configuration.
    ///   - completionHandler: A closure to be called when the retrieval process is completed.
    public func getIssuerConfig(credentialIssuerWellKnownURI: String?) async throws -> IssuerWellKnownConfiguration? {
        let jsonDecoder = JSONDecoder()
        
        guard let uri = credentialIssuerWellKnownURI else { return nil }
        let openIdIssuerUrl = uri + "/.well-known/openid-credential-issuer"
        debugPrint("###OpenIdIssuer url:\(openIdIssuerUrl)")
        
        guard let url = URL.init(string: openIdIssuerUrl) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let (data, _) = try await URLSession.shared.data(for: request)
        
        do {
            guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
                return nil
                
            }
            if jsonObject["credentials_supported"] != nil {
                let model = try jsonDecoder.decode(IssuerWellKnownConfigurationResponse.self, from: data)
                return IssuerWellKnownConfiguration(from: model)
            } else if jsonObject["credential_configurations_supported"] != nil {
                let model = try jsonDecoder.decode(IssuerWellKnownConfigurationResponseV2.self, from: data)
                return IssuerWellKnownConfiguration(from: model)
            } else {
                return nil
            }
        } catch {
            debugPrint("Get Issuer config failed: \(error)")
            let nsError = error as NSError
            let errorCode = nsError.code
            let error = EUDIError(from: ErrorResponse(message:error.localizedDescription, code: errorCode))
            return try IssuerWellKnownConfiguration(from: error)
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
        debugPrint("###authServerUrl url:\(authUrl)")
        
        guard let url = URL.init(string: authUrl) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let (data, _) = try await URLSession.shared.data(for: request)
        
        do {
            guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
                return nil
                
            }
            let model = try jsonDecoder.decode(AuthorisationServerWellKnownConfiguration.self, from: data)
            return model
        } catch {
            debugPrint("Get Auth config failed: \(error)")
            let nsError = error as NSError
            let errorCode = nsError.code
            let error = EUDIError(from: ErrorResponse(message:error.localizedDescription, code: errorCode))
            return AuthorisationServerWellKnownConfiguration(error: error)
        }
    }
}
