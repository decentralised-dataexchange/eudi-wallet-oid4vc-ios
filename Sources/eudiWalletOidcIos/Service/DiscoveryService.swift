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
        
        guard let uri = authorisationServerWellKnownURI else { return nil }
        let authURL = uri + "/.well-known/oauth-authorization-server"
        let authUrl = uri + "/.well-known/openid-configuration"
        
        debugPrint("### Attempting with authServerUrl url:\(authURL)")
        
        do {
            let (config, response) = try await fetchConfig2(from: authURL)
            if let config = config {
                return config
            } else if let response = response, response.statusCode >= 400 {
                do {
                    let (config, _) = try await fetchConfig2(from: authUrl)
                    if let config = config {
                        return config
                    }
                } catch {
                    debugPrint("### authUrl also failed: \(error.localizedDescription). Throwing final error.")
                    let nsError = error as NSError
                    let errorCode = nsError.code
                    let finalError = EUDIError(from: ErrorResponse(message: error.localizedDescription, code: errorCode))
                    return AuthorisationServerWellKnownConfiguration(error: finalError)
                }
            }
        } catch {
            debugPrint("### authURL failed: \(error.localizedDescription). Attempting with authUrl.")
        }
        
        return nil
    }
    
    func fetchConfig2(from urlString: String) async throws -> (AuthorisationServerWellKnownConfiguration?, HTTPURLResponse?) {
        let jsonDecoder = JSONDecoder()
        guard let url = URL(string: urlString) else { return (nil, nil) }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else { return (nil, nil) }
        
        if httpResponse.statusCode >= 400 {
            return (nil, httpResponse)
        }
        
        let model = try jsonDecoder.decode(AuthorisationServerWellKnownConfiguration.self, from: data)
        return (model, httpResponse)
    }
}
