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

    /// Helper to construct RFC 8414 Section 3 compatible URLs when paths are present.
    /// Inserts the wellKnownSuffix immediately after the host/port.
    private func buildRfc8414Url(inputUri: String, wellKnownSuffix: String) -> String? {
        guard var components = URLComponents(string: inputUri) else { return nil }

        let originalPath = components.path
        // If there's no path components to shift, appending standard suffix is equivalent
        if originalPath.isEmpty || originalPath == "/" {
            return nil
        }

        // Strip leading slash from original path
        let cleanedPath = originalPath.hasPrefix("/") ? String(originalPath.dropFirst()) : originalPath

        // RFC 8414: well-known prefix goes first, followed by the rest of the path
        components.path = "/\(wellKnownSuffix)/\(cleanedPath)"

        return components.url?.absoluteString
    }

    // MARK: - Retrieves the issuer configuration asynchronously based on the provided credential issuer well-known URI.
    public func getIssuerConfig(credentialIssuerWellKnownURI: String?) async throws -> IssuerWellKnownConfiguration? {
        guard let uri = credentialIssuerWellKnownURI else { return nil }

        // Strip existing suffix if present to find base
        let baseIssuer = uri.replacingOccurrences(of: "/.well-known/openid-credential-issuer", with: "")

        // 1. Primary traditional URL strategy
        let primaryUrl = baseIssuer + "/.well-known/openid-credential-issuer"
        if let config = try await executeIssuerFetch(from: primaryUrl) {
            return config
        }

        // 2. Fallback RFC 8414 URL strategy
        if let fallbackUrl = buildRfc8414Url(inputUri: baseIssuer, wellKnownSuffix: ".well-known/openid-credential-issuer") {
            debugPrint("### Falling back to RFC 8414 Issuer URL:\(fallbackUrl)")
            if let config = try await executeIssuerFetch(from: fallbackUrl) {
                return config
            }
        }

        return nil
    }

    private func executeIssuerFetch(from urlString: String) async throws -> IssuerWellKnownConfiguration? {
        let jsonDecoder = JSONDecoder()
        guard let url = URL(string: urlString) else { return nil }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode >= 400 {
                return nil
            }

            let rawString = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let jsonData: Data
            if rawString.components(separatedBy: ".").count == 3 {
                let parts = rawString.components(separatedBy: ".")
                let payloadBase64 = parts[1]

                guard let decodedString = payloadBase64.decodeBase64(),
                      let payloadData = decodedString.data(using: .utf8) else {
                    return nil
                }
                jsonData = payloadData
            } else {
                jsonData = data
            }

            guard let jsonObject = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] else {
                return nil
            }
            if jsonObject["credential_configurations_supported"] != nil {
                let model = try jsonDecoder.decode(IssuerWellKnownConfigurationResponseV2.self, from: jsonData)
                return IssuerWellKnownConfiguration(from: model)
            } else if jsonObject["credentials_supported"] != nil {
                let model = try jsonDecoder.decode(IssuerWellKnownConfigurationResponse.self, from: jsonData)
                return IssuerWellKnownConfiguration(from: model)
            } else {
                return nil
            }
        } catch {
            debugPrint("Fetch execution failed for \(urlString): \(error)")
            return nil
        }
    }

    // MARK: - To fetch the authorisation server configuration
    public func getAuthConfig(authorisationServerWellKnownURI: String?) async throws -> AuthorisationServerWellKnownConfiguration? {
        guard let uri = authorisationServerWellKnownURI else { return nil }

        // Clean base URI string
        let baseAuthServer = uri.replacingOccurrences(of: "/.well-known/oauth-authorization-server", with: "")
                                .replacingOccurrences(of: "/.well-known/openid-configuration", with: "")

        // Dynamic array to maintain resolution sequence safely
        var urlsToTry: [String] = []

        // 1. Traditional Suffix Locations
        urlsToTry.append(baseAuthServer + "/.well-known/oauth-authorization-server")
        urlsToTry.append(baseAuthServer + "/.well-known/openid-configuration")

        // 2. RFC 8414 Structured Locations
        if let rfcOauth = buildRfc8414Url(inputUri: baseAuthServer, wellKnownSuffix: ".well-known/oauth-authorization-server") {
            urlsToTry.append(rfcOauth)
        }
        if let rfcOpenId = buildRfc8414Url(inputUri: baseAuthServer, wellKnownSuffix: ".well-known/openid-configuration") {
            urlsToTry.append(rfcOpenId)
        }

        var finalNetworkError: Error?

        // Iterate through all candidate URLs sequentially
        for urlString in urlsToTry {
            debugPrint("### Attempting Auth Discovery URL: \(urlString)")
            do {
                let (config, response) = try await fetchConfig(from: urlString)
                if let config = config {
                    return config
                }
                // Record context if it's an HTTP failure descriptor
                if let response = response, response.statusCode >= 400 {
                    finalNetworkError = NSError(domain: "HTTPError", code: response.statusCode, userInfo: [NSLocalizedDescriptionKey: "Server returned status code \(response.statusCode)"])
                }
            } catch {
                debugPrint("### Failed for URL: \(urlString) Error: \(error.localizedDescription)")
                finalNetworkError = error
            }
        }

        // If all attempts failed, wrap up the final gathered error state if available
        if let error = finalNetworkError {
            let nsError = error as NSError
            let errorCode = nsError.code
            let finalError = EUDIError(from: ErrorResponse(message: error.localizedDescription, code: errorCode))
            return AuthorisationServerWellKnownConfiguration(error: finalError)
        }

        return nil
    }

    func fetchConfig(from urlString: String) async throws -> (AuthorisationServerWellKnownConfiguration?, HTTPURLResponse?) {
        let jsonDecoder = JSONDecoder()
        guard let url = URL(string: urlString) else { return (nil, nil) }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else { return (nil, nil) }

        if httpResponse.statusCode >= 400 {
            return (nil, httpResponse)
        }

        let rawString = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let jsonData: Data

        if rawString.components(separatedBy: ".").count == 3 {
            let parts = rawString.components(separatedBy: ".")
            let payloadBase64 = parts[1]

            guard let decodedString = payloadBase64.decodeBase64(),
                  let payloadData = decodedString.data(using: .utf8) else {
                return (nil, httpResponse)
            }
            jsonData = payloadData
        } else {
            jsonData = data
        }

        let model = try jsonDecoder.decode(AuthorisationServerWellKnownConfiguration.self, from: jsonData)
        return (model, httpResponse)
    }
}
